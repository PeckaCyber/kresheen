"""Builds facts (and the flows between them) from parsed Kubernetes manifests.

What becomes a diagram element and what stays metadata:

- **Workloads** (Deployment, StatefulSet, DaemonSet, Job, CronJob, Pod) are
  `process` facts. Their attributes carry what threat rules need: namespace
  (also the trust boundary), containers and whether each sets resource limits,
  service account, config/secret/PVC references, and exposed ports.
- **ConfigMaps, Secrets, PVCs** are `data_store` facts. Values are redacted
  here, before anything is stored: a credential-like key or a URL with embedded
  credentials is replaced with `<redacted>` and only its *key name* is kept in
  `secret_keys`, so rules can say "this ConfigMap holds credentials" without
  the database holding them.
- **Services, Namespaces, RBAC objects, NetworkPolicies, Ingresses** are
  metadata facts with their own node types. They are never diagram boxes
  (engine/dfd/derive.py only draws allow-listed types) but feed rules and
  flows: a Service decides which workloads are exposed, a Namespace is the
  trust boundary, a RoleBinding is a cross-boundary permission.

Flows come from evidence in the manifests only: an internet-facing Service
(LoadBalancer/NodePort) gives Internet -> workload; a hostname or URL in an
environment variable or a referenced ConfigMap that names another Service
gives workload -> workload. Nothing is guessed from names alone.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from kresheen.models.facts import FactEdge, FactNode, new_fact_edge_id, new_fact_node_id

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}
_STORE_KINDS = {"Secret", "ConfigMap", "PersistentVolumeClaim", "PersistentVolume"}
_METADATA_NODE_TYPES = {
    "Namespace": "namespace",
    "Service": "service",
    "ServiceAccount": "service_account",
    "Role": "rbac_role",
    "ClusterRole": "rbac_role",
    "RoleBinding": "rbac_binding",
    "ClusterRoleBinding": "rbac_binding",
    "NetworkPolicy": "network_policy",
    "Ingress": "ingress",
}

KNOWN_KINDS = frozenset(WORKLOAD_KINDS | _STORE_KINDS | set(_METADATA_NODE_TYPES))


def is_manifest_record(doc: object) -> bool:
    """True for a parsed YAML document that is a Kubernetes object this module
    models. Used where the input is not known to be a manifest (files walked in
    a repository), so a GitHub Actions workflow, a kustomization or an OpenAPI
    file is skipped instead of becoming a component."""
    if not isinstance(doc, dict):
        return False
    kind, meta = doc.get("kind"), doc.get("metadata")
    return (
        isinstance(doc.get("apiVersion"), str)
        and isinstance(kind, str)
        and kind in KNOWN_KINDS
        and isinstance(meta, dict)
        and isinstance(meta.get("name"), str)
    )


NON_NETWORK_EDGE_LABELS = frozenset({"mounts", "config"})
"""In-pod wiring (a volume mount, an env var from a ConfigMap), drawn on the
diagram for context but not a network flow, so flow threats skip them."""

INTERNET_BOUNDARY = "internet"

BOUNDARY_KIND_NAMESPACE = "namespace"
"""`boundary_kind` on a fact whose trust boundary was derived from its namespace
(a machine-chosen label, not a user-typed one), so threat generation judges
its exposure from evidence rather than from the label text."""

_SECRET_KEY_RE = re.compile(
    r"pass(?:word|wd)?|secret|token|api[-_]?key|credential|private[-_]?key|access[-_]?key", re.IGNORECASE
)
_URL_CREDENTIALS_RE = re.compile(r"(://[^/\s:@]+:)[^@\s]+@")
_TEXT_SECRET_LINE_RE = re.compile(
    r"(?im)^(\s*[\w.\-]*(?:pass(?:word|wd)?|secret|token|api[-_]?key)[\w.\-]*\s*[:=]\s*)(\S.*)$"
)
_INLINE_KV_SECRET_RE = re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[-_]?key)(\s*=\s*)([^\s\"']+)")
_MAX_VALUE_CHARS = 4000

_PLAINTEXT_SCHEMES = {"http", "postgresql", "postgres", "redis", "mysql", "amqp", "ldap", "ftp", "mongodb"}
_TLS_SCHEMES = {"https", "rediss", "amqps", "ldaps", "mongodb+srv", "tls", "ssl"}
_SVC_HOST_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)(?:\.([a-z0-9-]+))?\.svc(?:\.cluster\.local)?\b")
_URL_RE = re.compile(r"\b([a-z][a-z0-9+.-]*)://(?:[^/@\s]*@)?([A-Za-z0-9.-]+)(?::(\d+))?")


def is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY_RE.search(key))


def redact_value(key: str, value: str) -> tuple[str, bool]:
    """Returns (safe value, whether it held credential material)."""
    has_url_credentials = bool(_URL_CREDENTIALS_RE.search(value))
    text_hits = (bool(_TEXT_SECRET_LINE_RE.search(value)) and "\n" in value) or bool(
        _INLINE_KV_SECRET_RE.search(value)
    )
    credential = bool(value) and (is_secret_key(key) or has_url_credentials or text_hits)
    if is_secret_key(key) and value:
        return "<redacted>", True
    safe = _URL_CREDENTIALS_RE.sub(r"\1<redacted>@", value)
    safe = _TEXT_SECRET_LINE_RE.sub(r"\1<redacted>", safe)
    safe = _INLINE_KV_SECRET_RE.sub(r"\1\2<redacted>", safe)
    return safe[:_MAX_VALUE_CHARS], credential


def _meta(record: dict) -> dict:
    return record.get("metadata") or {}


def _name(record: dict) -> str:
    return str(_meta(record).get("name", "unknown"))


def _namespace(record: dict) -> str:
    if record["kind"] == "Namespace":
        return _name(record)
    return str(_meta(record).get("namespace") or "default")


def pod_spec_of(record: dict) -> dict:
    spec = record.get("spec") or {}
    if record["kind"] == "Pod":
        return spec
    if record["kind"] == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec")) or {}
    template = spec.get("template")
    return (template.get("spec") or {}) if isinstance(template, dict) else {}


def pod_labels_of(record: dict) -> dict[str, str]:
    """Labels a Service selector can match: the pod template's, plus the object's own."""
    spec = record.get("spec") or {}
    labels: dict[str, str] = dict(_meta(record).get("labels") or {})
    template = spec.get("template")
    if isinstance(template, dict):
        labels.update((template.get("metadata") or {}).get("labels") or {})
    return {str(k): str(v) for k, v in labels.items()}


def _container_facts(container: dict, *, init: bool) -> dict[str, Any]:
    env: list[dict[str, Any]] = []
    for entry in container.get("env") or []:
        if not isinstance(entry, dict):
            continue
        item: dict[str, Any] = {"name": entry.get("name", "")}
        ref = (entry.get("valueFrom") or {})
        if isinstance(ref.get("configMapKeyRef"), dict):
            item["config_ref"] = {"kind": "configmap", **_ref(ref["configMapKeyRef"])}
        elif isinstance(ref.get("secretKeyRef"), dict):
            item["config_ref"] = {"kind": "secret", **_ref(ref["secretKeyRef"])}
        elif "value" in entry:
            value, _ = redact_value(str(entry.get("name", "")), str(entry["value"]))
            item["value"] = value
        env.append(item)
    resources = container.get("resources") or {}
    security = container.get("securityContext") or {}
    return {
        "name": container.get("name", ""),
        "image": container.get("image", ""),
        "init": init,
        "ports": [
            {"name": p.get("name"), "port": p.get("containerPort"), "protocol": p.get("protocol", "TCP")}
            for p in container.get("ports") or []
            if isinstance(p, dict)
        ],
        "has_limits": bool(resources.get("limits")),
        "privileged": bool(security.get("privileged")),
        "command": [str(c) for c in (container.get("command") or [])][:20],
        "args": [str(a) for a in (container.get("args") or [])][:40],
        "env": env,
        "env_from_configmaps": [
            str((e.get("configMapRef") or {}).get("name"))
            for e in container.get("envFrom") or []
            if isinstance(e, dict) and (e.get("configMapRef") or {}).get("name")
        ],
    }


def _ref(ref: dict) -> dict[str, Any]:
    return {"name": ref.get("name"), "key": ref.get("key")}


def _workload_attributes(record: dict) -> dict[str, Any]:
    pod_spec = pod_spec_of(record)
    containers = [
        _container_facts(c, init=False) for c in pod_spec.get("containers") or [] if isinstance(c, dict)
    ] + [
        _container_facts(c, init=True) for c in pod_spec.get("initContainers") or [] if isinstance(c, dict)
    ]
    configmaps: set[str] = set()
    secrets: set[str] = set()
    pvcs: set[str] = set()
    for container in containers:
        configmaps.update(container["env_from_configmaps"])
        for env in container["env"]:
            ref = env.get("config_ref")
            if ref and ref.get("name"):
                (configmaps if ref["kind"] == "configmap" else secrets).add(ref["name"])
    for volume in pod_spec.get("volumes") or []:
        if not isinstance(volume, dict):
            continue
        if isinstance(volume.get("configMap"), dict) and volume["configMap"].get("name"):
            configmaps.add(volume["configMap"]["name"])
        if isinstance(volume.get("secret"), dict) and volume["secret"].get("secretName"):
            secrets.add(volume["secret"]["secretName"])
        if isinstance(volume.get("persistentVolumeClaim"), dict) and volume["persistentVolumeClaim"].get("claimName"):
            pvcs.add(volume["persistentVolumeClaim"]["claimName"])
    return {
        "kind": record["kind"],
        "namespace": _namespace(record),
        "trust_boundary": _namespace(record),
        "boundary_kind": BOUNDARY_KIND_NAMESPACE,
        "labels": _meta(record).get("labels", {}),
        "pod_labels": pod_labels_of(record),
        "selector": (record.get("spec") or {}).get("selector", {}),
        "container_images": [c["image"] for c in containers if c["image"] and not c["init"]],
        "host_network": bool(pod_spec.get("hostNetwork") or (record.get("spec") or {}).get("hostNetwork")),
        "service_account": pod_spec.get("serviceAccountName"),
        "containers": containers,
        "configmap_refs": sorted(configmaps),
        "secret_refs": sorted(secrets),
        "pvc_refs": sorted(pvcs),
    }


def _store_attributes(record: dict) -> dict[str, Any]:
    kind = record["kind"]
    attrs: dict[str, Any] = {
        "kind": kind,
        "namespace": _namespace(record),
        "trust_boundary": _namespace(record),
        "boundary_kind": BOUNDARY_KIND_NAMESPACE,
        "labels": _meta(record).get("labels", {}),
        "selector": {},
        "container_images": [],
        "host_network": False,
    }
    if kind == "ConfigMap":
        data: dict[str, str] = {}
        secret_keys: list[str] = []
        for key, value in (record.get("data") or {}).items():
            safe, credential = redact_value(str(key), str(value))
            data[str(key)] = safe
            if credential:
                secret_keys.append(str(key))
        attrs["data"] = data
        attrs["secret_keys"] = secret_keys
    elif kind == "Secret":
        attrs["keys"] = sorted(str(k) for k in {**(record.get("data") or {}), **(record.get("stringData") or {})})
    elif kind == "PersistentVolumeClaim":
        spec = record.get("spec") or {}
        attrs["access_modes"] = list(spec.get("accessModes") or [])
        attrs["storage_class"] = spec.get("storageClassName")
    return attrs


def _metadata_attributes(record: dict) -> dict[str, Any]:
    kind = record["kind"]
    spec = record.get("spec") or {}
    attrs: dict[str, Any] = {
        "kind": kind,
        "namespace": _namespace(record),
        "labels": _meta(record).get("labels", {}),
        "selector": spec.get("selector", {}) if kind == "Service" else {},
        "container_images": [],
        "host_network": False,
    }
    if kind == "Namespace":
        attrs["annotations"] = {str(k): str(v) for k, v in (_meta(record).get("annotations") or {}).items()}
    elif kind == "Service":
        attrs["service_type"] = spec.get("type", "ClusterIP")
        attrs["ports"] = [
            {"name": p.get("name"), "port": p.get("port"), "protocol": p.get("protocol", "TCP")}
            for p in spec.get("ports") or []
            if isinstance(p, dict)
        ]
    elif kind in ("RoleBinding", "ClusterRoleBinding"):
        attrs["role_ref"] = {
            "kind": (record.get("roleRef") or {}).get("kind"),
            "name": (record.get("roleRef") or {}).get("name"),
        }
        attrs["subjects"] = [
            {"kind": s.get("kind"), "name": s.get("name"), "namespace": s.get("namespace")}
            for s in record.get("subjects") or []
            if isinstance(s, dict)
        ]
        # A ClusterRoleBinding has no namespace: it grants cluster-wide.
        attrs["binding_namespace"] = _meta(record).get("namespace") if kind == "RoleBinding" else None
    elif kind == "NetworkPolicy":
        attrs["policy_types"] = list(spec.get("policyTypes") or [])
        attrs["pod_selector"] = spec.get("podSelector", {})
    elif kind == "Ingress":
        attrs["has_tls"] = bool(spec.get("tls"))
        attrs["annotations"] = {str(k): str(v) for k, v in (_meta(record).get("annotations") or {}).items()}
        attrs["backend_services"] = sorted(_ingress_backends(spec))
    return attrs


def _ingress_backends(spec: dict) -> set[str]:
    names: set[str] = set()
    default = ((spec.get("defaultBackend") or {}).get("service") or {}).get("name")
    if default:
        names.add(str(default))
    for rule in spec.get("rules") or []:
        for path in ((rule.get("http") or {}).get("paths") or []):
            name = ((path.get("backend") or {}).get("service") or {}).get("name")
            if name:
                names.add(str(name))
    return names


def _node_type(kind: str) -> str:
    if kind in WORKLOAD_KINDS:
        return "process"
    if kind in _STORE_KINDS:
        return "data_store"
    return _METADATA_NODE_TYPES.get(kind, "k8s_resource")


_PLAINTEXT_PORT_NAMES = {"http", "postgres", "postgresql", "redis", "mysql", "amqp", "ldap", "ftp", "mongodb"}
_TLS_PORT_NAMES = {"https", "tls", "ssl", "amqps", "ldaps", "rediss"}


def port_is_plaintext(name: str | None, number: int | None = None) -> bool | None:
    """Plaintext (True), TLS (False) or unknown (None), from a Service port's
    name or well-known number. Deliberately conservative: an unnamed,
    unrecognised port is unknown, not plaintext."""
    lowered = (name or "").lower()
    if lowered in _TLS_PORT_NAMES or number in (443, 8443, 6443):
        return False
    if lowered in _PLAINTEXT_PORT_NAMES or number in (80, 8080, 5432, 3306, 6379):
        return True
    return None


def _encryption(scheme: str | None, url_text: str) -> bool | None:
    """True/False only when the manifests actually say so; None = unknown."""
    if scheme in _TLS_SCHEMES or re.search(r"sslmode=(require|verify)", url_text):
        return True
    if scheme in _PLAINTEXT_SCHEMES:
        return False
    return None


def build_k8s_facts(
    records: list[dict], *, run_id: str, application_id: str, source_ref: str = "manifest_upload:k8s"
) -> tuple[list[FactNode], list[FactEdge]]:
    now = datetime.now(UTC)
    nodes: list[FactNode] = []
    record_by_node_id: dict[str, dict] = {}
    for record in records:
        kind = record["kind"]
        node_type = _node_type(kind)
        if node_type == "process":
            attrs = _workload_attributes(record)
        elif node_type == "data_store":
            attrs = _store_attributes(record)
        else:
            attrs = _metadata_attributes(record)
        node = FactNode(
            id=new_fact_node_id(), run_id=run_id, application_id=application_id, node_type=node_type,
            name=f"{kind}/{_name(record)}", attributes=attrs, source_ref=source_ref, discovered_at=now,
        )
        nodes.append(node)
        record_by_node_id[node.id] = record

    def edge(source: FactNode, target: FactNode, edge_type: str, label: str, **attributes: Any) -> FactEdge:
        return FactEdge(
            id=new_fact_edge_id(), run_id=run_id, application_id=application_id, source_node_id=source.id,
            target_node_id=target.id, edge_type=edge_type, label=label, attributes=attributes,
        )

    workloads = [n for n in nodes if n.node_type == "process"]
    services = [n for n in nodes if n.node_type == "service"]
    stores = {(n.attributes["kind"], n.attributes["namespace"], n.name.split("/", 1)[1]): n
              for n in nodes if n.node_type == "data_store"}
    edges: list[FactEdge] = []

    def selected_by(service: FactNode) -> list[FactNode]:
        selector: dict[str, str] = service.attributes.get("selector") or {}
        if not selector:
            return []
        return [
            w for w in workloads
            if w.attributes["namespace"] == service.attributes["namespace"]
            and selector.items() <= w.attributes["pod_labels"].items()
        ]

    exposed_by_service: dict[str, list[FactNode]] = {}
    for service in services:
        targets = selected_by(service)
        exposed_by_service[service.id] = targets
        for target in targets:
            edges.append(edge(service, target, "routes_to", f"selector match: {service.attributes['selector']}"))

    # Internet -> workload where a Service (or Ingress) exposes it.
    internet: FactNode | None = None
    for service in services:
        if service.attributes.get("service_type") not in ("LoadBalancer", "NodePort"):
            continue
        for target in exposed_by_service[service.id]:
            if internet is None:
                internet = FactNode(
                    id=new_fact_node_id(), run_id=run_id, application_id=application_id, node_type="external_entity",
                    name="Internet", attributes={"trust_boundary": INTERNET_BOUNDARY, "note": "Untrusted clients"},
                    source_ref=source_ref, discovered_at=now,
                )
                nodes.append(internet)
            ports = service.attributes.get("ports") or []
            proto = str((ports[0].get("name") or "tcp") if ports else "tcp").lower()
            plaintext = port_is_plaintext(ports[0].get("name"), ports[0].get("port")) if ports else None
            edges.append(edge(internet, target, "data_flow", proto, protocol=proto,
                              encrypted=None if plaintext is None else not plaintext,
                              via=f"{service.attributes['service_type']} Service {service.name.split('/', 1)[1]}"))

    # Internet -> workload where an Ingress publishes a Service.
    service_by_ns_name = {(sv.attributes["namespace"], sv.name.split("/", 1)[1]): sv for sv in services}
    for ingress in (n for n in nodes if n.node_type == "ingress"):
        for backend in ingress.attributes.get("backend_services", []):
            backend_svc = service_by_ns_name.get((ingress.attributes["namespace"], backend))
            if backend_svc is None:
                continue
            for target in exposed_by_service[backend_svc.id]:
                if internet is None:
                    internet = FactNode(
                        id=new_fact_node_id(), run_id=run_id, application_id=application_id,
                        node_type="external_entity", name="Internet",
                        attributes={"trust_boundary": INTERNET_BOUNDARY, "note": "Untrusted clients"},
                        source_ref=source_ref, discovered_at=now,
                    )
                    nodes.append(internet)
                tls = bool(ingress.attributes.get("has_tls"))
                edges.append(edge(internet, target, "data_flow", "https" if tls else "http",
                                  protocol="https" if tls else "http", encrypted=tls,
                                  via=f"Ingress {ingress.name.split('/', 1)[1]}"))

    # Workload -> workload from hostnames/URLs the workload is configured with.
    service_index = {(s.attributes["namespace"], s.name.split("/", 1)[1]): s for s in services}
    seen: set[tuple[str, str]] = set()
    for workload in workloads:
        for text in _configured_texts(workload, stores):
            for host, scheme, url_text in _referenced_hosts(text):
                svc = _resolve_service(host, workload.attributes["namespace"], service_index)
                if svc is None:
                    continue
                for target in exposed_by_service[svc.id]:
                    if target.id == workload.id or (workload.id, target.id) in seen:
                        continue
                    seen.add((workload.id, target.id))
                    edges.append(edge(workload, target, "data_flow", scheme or "tcp", protocol=scheme or "tcp",
                                      encrypted=_encryption(scheme, url_text),
                                      via=f"Service {svc.name.split('/', 1)[1]}"))

    # In-pod wiring, for the diagram only.
    for workload in workloads:
        namespace = workload.attributes["namespace"]
        for name in workload.attributes["pvc_refs"]:
            store = stores.get(("PersistentVolumeClaim", namespace, name))
            if store:
                edges.append(edge(workload, store, "mounts", "mounts"))
        for name in workload.attributes["configmap_refs"]:
            store = stores.get(("ConfigMap", namespace, name))
            if store:
                edges.append(edge(store, workload, "config", "config"))
        for name in workload.attributes["secret_refs"]:
            store = stores.get(("Secret", namespace, name))
            if store:
                edges.append(edge(store, workload, "config", "config"))
    return nodes, edges


def _configured_texts(workload: FactNode, stores: dict[tuple[str, str, str], FactNode]) -> list[str]:
    """Every string the workload is configured with that could name another service."""
    texts: list[str] = []
    namespace = workload.attributes["namespace"]
    for container in workload.attributes["containers"]:
        texts.append(container["image"])
        texts.extend(str(e["value"]) for e in container["env"] if "value" in e)
        for env in container["env"]:
            ref = env.get("config_ref")
            if ref and ref["kind"] == "configmap":
                store = stores.get(("ConfigMap", namespace, str(ref["name"])))
                if store and ref.get("key") in store.attributes.get("data", {}):
                    texts.append(str(store.attributes["data"][ref["key"]]))
    for name in workload.attributes["configmap_refs"]:
        store = stores.get(("ConfigMap", namespace, name))
        if store:
            texts.extend(store.attributes.get("data", {}).values())
    return texts


def _referenced_hosts(text: str) -> list[tuple[str, str | None, str]]:
    found: list[tuple[str, str | None, str]] = []
    for match in _URL_RE.finditer(text):
        scheme, host = match.group(1).lower(), match.group(2).lower()
        found.append((host, scheme, text[match.start() : match.end() + 200]))
    for match in _SVC_HOST_RE.finditer(text.lower()):
        found.append((match.group(0), None, ""))
    return found


def _resolve_service(
    host: str, source_namespace: str, index: dict[tuple[str, str], FactNode]
) -> FactNode | None:
    parts = host.split(".")
    name = parts[0]
    namespace = parts[1] if len(parts) > 1 and parts[1] != "svc" else source_namespace
    return index.get((namespace, name))
