"""Facts from a Terraform plan (or a state re-shaped as one) for AWS-style
infrastructure: nodes, data-flow edges, trust boundaries, and the normalized
security-group / IAM data the AWS config rules (threats/config_rules_aws.py,
plus any a plugin adds) read.

What this does that the first-generation parser did not:

- **Redaction.** A plan or state file holds real secrets (an IAM console
  password, a database master password, user_data with credentials). Values
  Terraform marks sensitive (`after_sensitive`) and any credential-named key
  are replaced before anything is stored, and user_data is decoded and passed
  through the same redactor the Kubernetes path uses. Nothing here stores a
  secret; `user_data_has_secrets` records that one existed.
- **Only real components are diagram boxes.** Route tables, associations,
  instance profiles, key pairs, `random_*` and similar plumbing stay as facts
  (detectors and edge inference read them) but as `config_resource`, which is
  not diagram-worthy (engine/dfd/derive.py's allowlist).
- **Edges.** Internet -> a resource that is actually reachable (public IP or
  internet-facing load balancer, and a security group admitting 0.0.0.0/0);
  load balancer -> target group via listeners and rules; security-group-to-
  security-group ingress; instance -> S3 bucket where its IAM role grants S3.
  Never a generic "A references B" edge: a dependency is not a data flow.
- **Trust boundaries.** A resource's subnet (else its VPC) is its boundary,
  labelled with the Terraform address. These are machine-chosen labels, so
  `boundary_kind` marks them and exposure is judged from evidence, not from
  words like "public" in the label (see threats/service.py).

Two input shapes are supported. A `terraform show -json` *state* carries ids
and ARNs, so relationships are found by matching identifier values. A real
`terraform plan -json` leaves computed ids unknown (they are not in `after`),
so relationships come from the plan's `configuration` block, which lists the
resources each attribute references. Both feed one resolver.

Deliberately not done: it reads declared configuration only (no live account),
a security group's stated reachability is not proof a host is up, and routing
(whether a subnet really has an internet route) is recorded but not required
for the exposure edge.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from kresheen.engine.ingest.k8s_facts import (
    INTERNET_BOUNDARY,
    is_secret_key,
    port_is_plaintext,
    redact_value,
)
from kresheen.models.facts import FactEdge, FactNode, new_fact_edge_id, new_fact_node_id

BOUNDARY_KIND_NETWORK = "network"
"""`boundary_kind` for a boundary derived from a subnet or VPC (a machine label)."""

DATA_STORE_HINTS = (
    "db", "database", "bucket", "storage", "queue", "table", "cache", "efs", "file_system", "dynamodb", "rds",
    "elasticache", "redshift",
)
"""Which resource types read as a data store on the diagram. Display only: it
never decides which threats apply (that is the reasoning stage's job)."""

_PLUMBING_PREFIXES = ("random_", "null_", "time_", "terraform_data", "local_", "tls_")
_PLUMBING_TYPES = frozenset(
    {
        "aws_route_table", "aws_route", "aws_route_table_association", "aws_main_route_table_association",
        "aws_iam_instance_profile", "aws_key_pair", "aws_s3_bucket_versioning", "aws_lb_target_group_attachment",
        "aws_eip_association", "aws_network_acl_association", "aws_db_subnet_group", "aws_elasticache_subnet_group",
        "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule",
        "aws_iam_role_policy_attachment", "aws_lb_listener_certificate",
    }
)
"""Resource types kept as facts but not drawn. A security-group *rule* resource
is folded into its group; a policy attachment to a role is folded into the
role's grants. (A *user* policy attachment stays a component: it is the
evidence for an admin user.)"""

_SENSITIVE_MASK = "<redacted>"
_WORLD_CIDRS = ("0.0.0.0/0", "::/0")
_MAX_CONFIG_DEPTH = 6
# Redaction walks much deeper than the config the engine reads, so a value Terraform marks sensitive is never kept
# because it sits deep. Anything below this is replaced as a whole.
_MAX_REDACT_DEPTH = 64
_TOO_DEEP = "<omitted: nested too deep>"
_ADDRESS_INDEX = re.compile(r"\[[^\]]*\]$")


def base_address(address: str) -> str:
    return _ADDRESS_INDEX.sub("", address)


def _redact_tree(value: Any, mask: Any, key: str = "", depth: int = 0) -> Any:
    """Copy of `value` with sensitive material replaced. `mask` is Terraform's
    `after_sensitive` (same shape; True marks a sensitive leaf or subtree)."""
    if mask is True:
        return _SENSITIVE_MASK
    if depth > _MAX_REDACT_DEPTH:
        return _SENSITIVE_MASK if mask else _TOO_DEEP
    if isinstance(value, dict):
        sub = mask if isinstance(mask, dict) else {}
        return {k: _redact_tree(v, sub.get(k), k, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [
            _redact_tree(v, mask[i] if isinstance(mask, list) and i < len(mask) else None, key, depth + 1)
            for i, v in enumerate(value)
        ]
    if isinstance(value, str) and value:
        return redact_value(key, value)[0]
    return value


_URL_CREDENTIALS_RE = re.compile(r"(://[^/\s:@]+:)[^@\s]+@")
_USER_DATA_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<key>[A-Za-z0-9_.\-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_.\-]*)
    (?P<sep>\s*[=:]\s*)
    (?P<quote>['"]?)
    (?P<value>[^\s'"]+)
    """
)


def _redact_user_data(text: str) -> tuple[str, bool]:
    """Replace literal credential assignments in a boot script. A value that is a
    reference (`$(...)`, `${var}`, a template placeholder) is a secret being
    fetched, not embedded, so it is left alone and not counted."""
    found = False

    def replace(match: re.Match[str]) -> str:
        nonlocal found
        value = match.group("value")
        if value.startswith(("$", "{{", "<")) or value in ("true", "false"):
            return match.group(0)
        found = True
        return f"{match.group('key')}{match.group('sep')}{match.group('quote')}{_SENSITIVE_MASK}"

    safe = _USER_DATA_SECRET_RE.sub(replace, text)
    safe, url_hits = _URL_CREDENTIALS_RE.subn(r"\1<redacted>@", safe)
    return safe, found or url_hits > 0


def _decode_user_data(after: dict[str, Any]) -> tuple[str | None, bool]:
    """(redacted user_data text, whether it held credential material)."""
    text: str | None = after.get("user_data") if isinstance(after.get("user_data"), str) else None
    encoded = after.get("user_data_base64")
    if isinstance(encoded, str) and encoded:
        try:
            text = base64.b64decode(encoded, validate=False).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            text = None
    if not text:
        return None, False
    # A hash-only user_data (state stores the SHA-1) is not script text.
    if re.fullmatch(r"[0-9a-f]{40}", text.strip()):
        return None, False
    return _redact_user_data(text)


def _json_document(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def policy_statements(document: Any) -> list[dict[str, Any]]:
    """Normalized statements of an IAM or bucket policy document (JSON string
    or dict): effect, actions, resources, principals."""
    doc = _json_document(document)
    if not doc:
        return []
    out = []
    for raw in _as_list(doc.get("Statement")):
        if not isinstance(raw, dict):
            continue
        principal = raw.get("Principal")
        if isinstance(principal, dict):
            principals = [p for v in principal.values() for p in _as_list(v)]
        else:
            principals = _as_list(principal)
        out.append(
            {
                "effect": str(raw.get("Effect", "Allow")),
                "actions": [str(a) for a in _as_list(raw.get("Action"))],
                "resources": [str(r) for r in _as_list(raw.get("Resource"))],
                "principals": [str(p) for p in principals],
                "has_condition": bool(raw.get("Condition")),
            }
        )
    return out


def config_refs(plan: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    """address -> {attribute name -> referenced resource base addresses}, from the
    plan's `configuration` block (present in a real plan, absent in a state)."""

    def collect(expressions: Any, into: dict[str, list[str]]) -> None:
        if not isinstance(expressions, dict):
            return
        for attr, expr in expressions.items():
            for node in _as_list(expr):
                if not isinstance(node, dict):
                    continue
                refs = node.get("references")
                if isinstance(refs, list):
                    for ref in refs:
                        parts = str(ref).split(".")
                        if len(parts) >= 2 and parts[0] not in ("var", "local", "data", "module", "each", "count", "path"):
                            into.setdefault(attr, []).append(base_address(f"{parts[0]}.{parts[1]}"))
                else:  # a nested block: {attr: expression, ...}
                    collect(node, into)

    out: dict[str, dict[str, list[str]]] = {}
    root = (plan.get("configuration") or {}).get("root_module") or {}
    for resource in root.get("resources", []):
        refs: dict[str, list[str]] = {}
        collect(resource.get("expressions"), refs)
        if refs:
            out[base_address(str(resource.get("address", "")))] = refs
    return out


class _Resolver:
    """Finds which resource an attribute value or reference points at."""

    def __init__(self, resources: list[dict[str, Any]], config_refs: dict[str, dict[str, list[str]]]):
        self.config_refs = config_refs
        self.type_of = {r["address"]: r["type"] for r in resources}
        self.addresses_by_base: dict[str, list[str]] = {}
        self.by_identifier: dict[str, list[str]] = {}
        for r in resources:
            self.addresses_by_base.setdefault(base_address(r["address"]), []).append(r["address"])
            for key in ("id", "arn", "name", "bucket"):
                value = r["after"].get(key)
                if isinstance(value, str) and value:
                    self.by_identifier.setdefault(value, []).append(r["address"])

    def targets(self, resource: dict[str, Any], attrs: Iterable[str], types: tuple[str, ...] = ()) -> list[str]:
        found: list[str] = []
        address = resource["address"]
        for attr in attrs:
            for ref in self.config_refs.get(base_address(address), {}).get(attr, []):
                found.extend(self.addresses_by_base.get(ref, []))
            for value in self._flatten(self._find(resource["after"], attr)):
                found.extend(self.by_identifier.get(value, []))
        seen: set[str] = set()
        out = []
        for a in found:
            if a != address and a not in seen and (not types or self.type_of.get(a) in types):
                seen.add(a)
                out.append(a)
        return out

    @staticmethod
    def _find(value: Any, attr: str, depth: int = 0) -> list[Any]:
        """Every value stored under key `attr`, at any nesting depth (a target
        group ARN sits inside a listener's `default_action` block)."""
        if depth > _MAX_CONFIG_DEPTH:
            return []
        if isinstance(value, dict):
            found = [value[attr]] if attr in value else []
            for v in value.values():
                found.extend(_Resolver._find(v, attr, depth + 1))
            return found
        if isinstance(value, list):
            return [x for v in value for x in _Resolver._find(v, attr, depth + 1)]
        return []

    @staticmethod
    def _flatten(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value] if value else []
        if isinstance(value, list):
            return [s for v in value for s in _Resolver._flatten(v)]
        if isinstance(value, dict):
            return [s for v in value.values() for s in _Resolver._flatten(v)]
        return []


def _ports(rule: dict[str, Any]) -> tuple[int, int]:
    lo, hi = rule.get("from_port"), rule.get("to_port")
    if str(rule.get("protocol")) == "-1":
        return 0, 65535
    return (int(lo) if lo is not None else 0), (int(hi) if hi is not None else 65535)


def _normalize_rule(raw: dict[str, Any], groups: list[str]) -> dict[str, Any]:
    proto = str(raw.get("protocol", raw.get("ip_protocol", "tcp")))
    cidrs = [c for c in [*_as_list(raw.get("cidr_blocks")), *_as_list(raw.get("ipv6_cidr_blocks")),
                         *_as_list(raw.get("cidr_ipv4")), *_as_list(raw.get("cidr_ipv6"))] if c]
    lo, hi = _ports({**raw, "protocol": proto})
    return {"protocol": "all" if proto == "-1" else proto, "from_port": lo, "to_port": hi, "cidr_blocks": cidrs,
            "security_groups": groups, "description": str(raw.get("description") or "")}


def _fold_security_group_rules(
    resources: list[dict[str, Any]], resolver: _Resolver
) -> dict[str, list[dict[str, Any]]]:
    """SG address -> normalized ingress rules: the group's inline rules plus any
    standalone rule resources that point at it."""
    by_group: dict[str, list[dict[str, Any]]] = {}
    for r in resources:
        after = r["after"]
        if r["type"] == "aws_security_group":
            for raw in _as_list(after.get("ingress")):
                if isinstance(raw, dict):
                    groups = resolver.targets({"address": r["address"], "after": {"g": raw.get("security_groups")}},
                                              ["g"], ("aws_security_group",))
                    by_group.setdefault(r["address"], []).append(_normalize_rule(raw, groups))
        elif r["type"] in ("aws_security_group_rule", "aws_vpc_security_group_ingress_rule"):
            if r["type"] == "aws_security_group_rule" and after.get("type") != "ingress":
                continue
            owner = resolver.targets(r, ["security_group_id"], ("aws_security_group",))
            source = resolver.targets(r, ["source_security_group_id", "referenced_security_group_id"],
                                      ("aws_security_group",))
            for group in owner:
                by_group.setdefault(group, []).append(_normalize_rule(after, source))
    return by_group


def _is_world(rule: dict[str, Any]) -> bool:
    return any(c in _WORLD_CIDRS for c in rule["cidr_blocks"])


def _port_label(rules: list[dict[str, Any]]) -> tuple[str, bool | None]:
    parts, plaintext = [], []
    for rule in rules:
        lo, hi = rule["from_port"], rule["to_port"]
        parts.append("all" if (lo, hi) == (0, 65535) else str(lo) if lo == hi else f"{lo}-{hi}")
        if lo == hi:
            plaintext.append(port_is_plaintext(None, lo))
    label = f"{rules[0]['protocol']}/{','.join(dict.fromkeys(parts))}"
    if any(p is True for p in plaintext):
        return label, False
    if plaintext and all(p is False for p in plaintext):
        return label, True
    return label, None


def _node_type(resource_type: str) -> str:
    if resource_type in _PLUMBING_TYPES or resource_type.startswith(_PLUMBING_PREFIXES):
        return "config_resource"
    return "data_store" if any(h in resource_type.lower() for h in DATA_STORE_HINTS) else "process"


def _scalars(after: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in after.items() if isinstance(v, (str, int, float, bool)) and not is_secret_key(k)}


def build_terraform_facts(
    records: list[dict[str, Any]], *, run_id: str, application_id: str, source_ref: str = "manifest_upload:terraform"
) -> tuple[list[FactNode], list[FactEdge]]:
    now = datetime.now(UTC)
    resources: list[dict[str, Any]] = []
    for record in records:
        change = record.get("change") or {}
        resource_type = str(record.get("type", "unknown"))
        address = str(record.get("address") or f"{resource_type}.{record.get('name', 'unknown')}")
        after = _redact_tree(change.get("after") or {}, change.get("after_sensitive"))
        user_data, user_data_secret = _decode_user_data(change.get("after") or {})
        after.pop("user_data_base64", None)
        if user_data is not None:
            after["user_data"] = user_data
        resources.append(
            {"address": address, "type": resource_type, "provider": record.get("provider_name", ""),
             "after": after, "user_data_secret": user_data_secret}
        )

    resolver = _Resolver(resources, {k: v for record in records for k, v in (record.get("_config_refs") or {}).items()})
    rules_by_group = _fold_security_group_rules(resources, resolver)
    by_address = {r["address"]: r for r in resources}

    def targets(resource: dict[str, Any], attrs: Iterable[str], *types: str) -> list[str]:
        return resolver.targets(resource, attrs, tuple(types))

    subnet_public: dict[str, bool] = {}
    igw_routes = {r["address"] for r in resources if r["type"] == "aws_route_table" and any(
        str(route.get("gateway_id", "")).startswith("igw-") or str(route.get("gateway_id", "")).startswith("aws_internet_gateway")
        for route in _as_list(r["after"].get("route")) if isinstance(route, dict))}
    igw_routes |= {a for r in resources if r["type"] == "aws_route" and str(r["after"].get("gateway_id", "")).startswith("igw-")
                   for a in targets(r, ["route_table_id"], "aws_route_table")}
    for r in resources:
        if r["type"] == "aws_route_table_association":
            subnets = targets(r, ["subnet_id"], "aws_subnet")
            tables = targets(r, ["route_table_id"], "aws_route_table")
            for subnet in subnets:
                subnet_public[subnet] = subnet_public.get(subnet, False) or any(t in igw_routes for t in tables)

    def boundary_of(resource: dict[str, Any]) -> tuple[str | None, str | None]:
        subnets = targets(resource, ["subnet_id", "subnet_ids", "subnets"], "aws_subnet")
        vpcs = targets(resource, ["vpc_id"], "aws_vpc")
        if resource["type"] == "aws_subnet":
            return (vpcs[0], "vpc") if vpcs else (None, None)
        if len(subnets) == 1:
            return subnets[0], "subnet"
        if subnets:  # spans several subnets: the shared VPC is the honest boundary
            vpc = targets(by_address[subnets[0]], ["vpc_id"], "aws_vpc")
            return (vpc[0], "vpc") if vpc else (None, None)
        return (vpcs[0], "vpc") if vpcs else (None, None)

    # -- per-resource derived attributes ------------------------------------------
    derived: dict[str, dict[str, Any]] = {}
    exposure: dict[str, list[dict[str, Any]]] = {}
    for r in resources:
        extra: dict[str, Any] = {}
        groups = targets(r, ["vpc_security_group_ids", "security_groups", "security_group_ids", "security_group_id"],
                         "aws_security_group")
        if groups:
            extra["security_group_addresses"] = groups
        boundary, kind = boundary_of(r)
        if boundary:
            extra["trust_boundary"], extra["boundary_kind"] = boundary, BOUNDARY_KIND_NETWORK
            extra["boundary_scope"] = kind
        if r["type"] == "aws_security_group":
            extra["ingress_rules"] = rules_by_group.get(r["address"], [])
        if r["type"] == "aws_subnet":
            extra["is_public_subnet"] = subnet_public.get(r["address"])
        if r["user_data_secret"]:
            extra["user_data_has_secrets"] = True
        statements = []
        for attr in ("policy",):
            statements += policy_statements(r["after"].get(attr))
        for inline in _as_list(r["after"].get("inline_policy")):
            if isinstance(inline, dict):
                statements += policy_statements(inline.get("policy"))
        if statements:
            extra["policy_statements"] = statements
        if r["type"] in ("aws_iam_user_policy_attachment", "aws_iam_role_policy_attachment",
                         "aws_iam_group_policy_attachment") and r["after"].get("policy_arn"):
            extra["managed_policy_arn"] = r["after"]["policy_arn"]
        if r["type"] == "aws_iam_role_policy" and r["after"].get("role"):
            extra["policy_for_role"] = targets(r, ["role"], "aws_iam_role")
        if r["type"] == "aws_instance":
            roles = _instance_roles(r, resolver, by_address)
            if roles:
                extra["role_addresses"] = roles
        if r["type"] == "aws_iam_role":
            extra["grant_policy_addresses"] = [
                p["address"] for p in resources
                if p["type"] == "aws_iam_role_policy" and r["address"] in targets(p, ["role"], "aws_iam_role")
            ]
        if r["type"] == "aws_vpc":
            extra["has_flow_log"] = any(
                r["address"] in targets(f, ["vpc_id", "subnet_id"], "aws_vpc")
                or any(v == r["address"] for sub in targets(f, ["subnet_id"], "aws_subnet")
                       for v in targets(by_address[sub], ["vpc_id"], "aws_vpc"))
                for f in resources if f["type"] == "aws_flow_log"
            )
        # Which security groups admit the internet, and to a reachable resource?
        world = [rule for g in groups for rule in rules_by_group.get(g, []) if _is_world(rule)]
        reachable = False
        if r["type"] == "aws_instance":
            reachable = bool(r["after"].get("associate_public_ip_address") or r["after"].get("public_ip"))
        elif r["type"] in ("aws_lb", "aws_alb"):
            reachable = r["after"].get("internal") is False
        elif r["type"] in ("aws_db_instance", "aws_rds_cluster_instance"):
            reachable = bool(r["after"].get("publicly_accessible"))
        if reachable and world:
            exposure[r["address"]] = world
            extra["internet_exposed"] = True
            extra["internet_ports"] = sorted({f"{x['from_port']}-{x['to_port']}" if x["from_port"] != x["to_port"]
                                              else str(x["from_port"]) for x in world})
        derived[r["address"]] = extra

    # -- nodes ------------------------------------------------------------------------
    nodes: list[FactNode] = []
    node_of: dict[str, FactNode] = {}
    for r in resources:
        after = r["after"]
        node = FactNode(
            id=new_fact_node_id(), run_id=run_id, application_id=application_id,
            node_type=_node_type(r["type"]), name=r["address"],
            attributes={
                "resource_type": r["type"], "provider": r["provider"],
                **_scalars(after),
                "config": {k: v for k, v in after.items() if k != "tags_all"},
                **derived[r["address"]],
            },
            source_ref=source_ref, discovered_at=now,
        )
        nodes.append(node)
        node_of[r["address"]] = node

    edges: list[FactEdge] = []

    def edge(src: FactNode, dst: FactNode, label: str, **attributes: Any) -> None:
        edges.append(FactEdge(id=new_fact_edge_id(), run_id=run_id, application_id=application_id,
                              source_node_id=src.id, target_node_id=dst.id, edge_type="data_flow", label=label,
                              attributes=attributes))

    internet: FactNode | None = None
    for address, world in exposure.items():
        if internet is None:
            internet = FactNode(
                id=new_fact_node_id(), run_id=run_id, application_id=application_id, node_type="external_entity",
                name="Internet", attributes={"trust_boundary": INTERNET_BOUNDARY, "note": "Untrusted clients"},
                source_ref=source_ref, discovered_at=now,
            )
            nodes.append(internet)
        label, encrypted = _port_label(world)
        edge(internet, node_of[address], label, protocol=label.split("/", 1)[0], encrypted=encrypted,
             via="security group admitting 0.0.0.0/0")

    # Load balancer -> target group, through listeners and listener rules.
    listener_lb: dict[str, str] = {}
    for r in resources:
        if r["type"] in ("aws_lb_listener", "aws_alb_listener"):
            for balancer in targets(r, ["load_balancer_arn"], "aws_lb", "aws_alb"):
                listener_lb[r["address"]] = balancer
    for r in resources:
        if r["type"] in ("aws_lb_listener", "aws_alb_listener", "aws_lb_listener_rule", "aws_alb_listener_rule"):
            lb = listener_lb.get(r["address"]) or next(
                (listener_lb[x] for x in targets(r, ["listener_arn"], "aws_lb_listener", "aws_alb_listener")
                 if x in listener_lb), None)
            if lb is None:
                continue
            protocol = str(r["after"].get("protocol") or listener_protocol(r, listener_lb, by_address, targets)).upper()
            for group in targets(r, ["target_group_arn"], "aws_lb_target_group", "aws_alb_target_group"):
                edge(node_of[lb], node_of[group], protocol.lower() or "http", protocol=protocol.lower() or "http",
                     encrypted=protocol in ("HTTPS", "TLS", "SSL") or (None if not protocol else False),
                     via=f"listener {r['address']}")
    for r in resources:
        if r["type"] == "aws_lb_target_group_attachment":
            for group in targets(r, ["target_group_arn"], "aws_lb_target_group", "aws_alb_target_group"):
                for member in targets(r, ["target_id"], "aws_instance"):
                    edge(node_of[group], node_of[member], "forward", via="target group attachment")

    # Security group -> security group ingress: members of the source group reach members of this one.
    members: dict[str, list[str]] = {}
    for address, extra in derived.items():
        if by_address[address]["type"] in ("aws_instance", "aws_lb", "aws_alb", "aws_db_instance",
                                           "aws_elasticache_replication_group", "aws_elasticache_cluster",
                                           "aws_efs_mount_target", "aws_rds_cluster_instance"):
            for group in extra.get("security_group_addresses", []):
                members.setdefault(group, []).append(address)
    seen_pairs: set[tuple[str, str]] = set()
    for group, rules in rules_by_group.items():
        for rule in rules:
            for source_group in rule["security_groups"]:
                for src in members.get(source_group, []):
                    for dst in members.get(group, []):
                        if src != dst and (src, dst) not in seen_pairs:
                            seen_pairs.add((src, dst))
                            label, encrypted = _port_label([rule])
                            edge(node_of[src], node_of[dst], label, protocol=label.split("/", 1)[0],
                                 encrypted=encrypted, via=f"security group {group} ingress")

    # Instance -> S3 bucket where the instance's role can use S3.
    role_policies = _role_grants(resources, resolver, derived)
    for r in resources:
        if r["type"] != "aws_instance":
            continue
        for role in _instance_roles(r, resolver, by_address):
            for bucket in _reachable_buckets(role_policies.get(role, []), resources):
                edge(node_of[r["address"]], node_of[bucket], "s3 (IAM grant)", protocol="https", encrypted=True,
                     via=f"role {role}")
    return nodes, edges


def listener_protocol(resource: dict[str, Any], listener_lb: dict[str, str], by_address: dict[str, Any], targets: Any) -> str:
    """The protocol of the listener a rule belongs to (a rule has none of its own)."""
    for listener in targets(resource, ["listener_arn"], "aws_lb_listener", "aws_alb_listener"):
        return str(by_address[listener]["after"].get("protocol") or "")
    return ""


def _instance_roles(instance: dict[str, Any], resolver: _Resolver, by_address: dict[str, Any]) -> list[str]:
    roles: list[str] = []
    for profile in resolver.targets(instance, ["iam_instance_profile"], ("aws_iam_instance_profile",)):
        roles.extend(resolver.targets(by_address[profile], ["role", "roles"], ("aws_iam_role",)))
    return roles


def _role_grants(
    resources: list[dict[str, Any]], resolver: _Resolver, derived: dict[str, dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    grants: dict[str, list[dict[str, Any]]] = {}
    for r in resources:
        statements = derived[r["address"]].get("policy_statements", [])
        if r["type"] == "aws_iam_role" and statements:
            grants.setdefault(r["address"], []).extend(statements)
        elif r["type"] == "aws_iam_role_policy" and statements:
            for role in resolver.targets(r, ["role"], ("aws_iam_role",)):
                grants.setdefault(role, []).extend(statements)
    return grants


def _reachable_buckets(statements: list[dict[str, Any]], resources: list[dict[str, Any]]) -> list[str]:
    buckets = [r for r in resources if r["type"] == "aws_s3_bucket"]
    out = []
    for statement in statements:
        if statement["effect"] != "Allow" or not any(a == "*" or a.lower().startswith("s3:") for a in statement["actions"]):
            continue
        for bucket in buckets:
            name = str(bucket["after"].get("bucket") or bucket["after"].get("id") or "")
            if bucket["address"] not in out and any(
                res == "*" or (name and f"arn:aws:s3:::{name}" in res) for res in statement["resources"]
            ):
                out.append(bucket["address"])
    return out
