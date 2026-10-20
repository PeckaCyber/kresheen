"""Configuration-aware threat rules: detectors over the facts an ingest
produced (engine/ingest/k8s_facts.py), not just an element's type.

The generic STRIDE catalog (catalog.py) says every data store can be read or
every flow tampered with. A config rule recognises a *specific* misconfiguration
in the manifests (credentials in a ConfigMap, a LoadBalancer with no declared
authentication) and cites the evidence. The core ships a small set of sample
rules; a plugin can add more through `Plugin.config_rules`, and
`all_config_rules()` returns both. Each rule carries the id of the taxonomy
threat it instantiates so a run can be scored against known, seeded threats.

Detectors work from *declared* configuration only. They cannot see what a
manifest doesn't say (a proxy in front, a runtime flag set elsewhere), so
every claim is worded as "no X is declared", and evidence names the exact
objects and keys. ML-component detection is keyword-based (image, name and
labels), and is isolated in `is_model_registry` / `is_ml_inference`.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from kresheen.engine.facts.naming import unqualified_name
from kresheen.models.facts import FactEdge, FactNode
from kresheen.models.threat import ThreatSeverity
from kresheen.plugins import get_registry

HitKind = Literal["component", "flow", "boundary"]
RuleTarget = Literal["process", "data_store", "data_flow", "trust_boundary"]


@dataclass(frozen=True)
class Hit:
    kind: HitKind
    # component: fact name ("Deployment/jenkins"); boundary: namespace name;
    # flow: "<source fact name>-><target fact name>".
    target: str
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ConfigRule:
    id: str
    taxonomy_id: str
    target: RuleTarget
    # Always the STRIDE category this instantiates -- every config-derived
    # rule is inherently STRIDE-shaped (evidence-specific instances of the
    # generic STRIDE catalog's gaps); these only ever run when STRIDE is
    # active (engine/threats/service.py::generate_run_threats).
    category: str
    title: str  # "{name}" is replaced with the element's display name
    description: str
    severity: ThreatSeverity
    mitigations: tuple[str, ...]
    cwe: tuple[str, ...]
    attack: tuple[str, ...]
    applies_when: str
    detect: Callable[[FactContext], list[Hit]]
    # Rule ids this one replaces on the same element: a more specific rule (say, public
    # model storage) suppresses the general one (public bucket) where both fire.
    supersedes: tuple[str, ...] = ()


class FactContext:
    """Indexes over one run's facts, shared by every detector."""

    def __init__(self, nodes: list[FactNode], edges: list[FactEdge]):
        self.nodes = nodes
        self.edges = edges
        self.by_id = {n.id: n for n in nodes}
        # Only Kubernetes-shaped facts: a Terraform resource or a
        # GitHub repo is also a `process`/`data_store` fact but carries none of
        # these attributes, and must simply be ignored by these rules.
        self.workloads = [n for n in nodes if n.node_type == "process" and "containers" in n.attributes]
        self.services = [n for n in nodes if n.node_type == "service"]
        self.stores = [
            n for n in nodes if n.node_type == "data_store" and "kind" in n.attributes and "namespace" in n.attributes
        ]
        self.namespaces = {n.name.split("/", 1)[1]: n for n in nodes if n.node_type == "namespace"}
        self.bindings = [n for n in nodes if n.node_type == "rbac_binding"]
        self.network_policies = [n for n in nodes if n.node_type == "network_policy"]
        # Terraform resources by type (engine/ingest/terraform_facts.py); the AWS
        # rules read these and nothing above.
        self.tf_by_type: dict[str, list[FactNode]] = {}
        for n in nodes:
            resource_type = n.attributes.get("resource_type")
            if isinstance(resource_type, str):
                self.tf_by_type.setdefault(resource_type, []).append(n)
        self.exposing_services: dict[str, list[FactNode]] = {}
        for edge in edges:
            if edge.edge_type != "routes_to":
                continue
            service = self.by_id.get(edge.source_node_id)
            if service is not None:
                self.exposing_services.setdefault(edge.target_node_id, []).append(service)

    def tf(self, *resource_types: str) -> list[FactNode]:
        return [n for t in resource_types for n in self.tf_by_type.get(t, [])]

    def services_for(self, workload: FactNode) -> list[FactNode]:
        return self.exposing_services.get(workload.id, [])

    def config_stores(self, workload: FactNode) -> list[FactNode]:
        refs = set(workload.attributes.get("configmap_refs", []))
        return [
            s for s in self.stores
            if s.attributes["kind"] == "ConfigMap"
            and s.attributes["namespace"] == workload.attributes["namespace"]
            and unqualified_name(s).split("/", 1)[1] in refs
        ]

    def config_settings(self, workload: FactNode) -> dict[str, str]:
        """Every setting the workload is configured with, upper-cased key -> value
        (plain env vars, plus every referenced ConfigMap's keys)."""
        settings: dict[str, str] = {}
        for container in workload.attributes.get("containers", []):
            for env in container["env"]:
                if "value" in env:
                    settings[str(env["name"]).upper()] = str(env["value"])
        for store in self.config_stores(workload):
            for key, value in store.attributes.get("data", {}).items():
                settings[str(key).upper()] = str(value)
        return settings

    def config_text(self, workload: FactNode) -> str:
        parts = list(self.config_settings(workload).values())
        for container in workload.attributes.get("containers", []):
            parts.extend(container["args"])
            parts.extend(container["command"])
        return "\n".join(parts)

    def zone_of(self, namespace: str) -> str:
        """Environment of a namespace (label `environment`, else its name), lower-cased."""
        node = self.namespaces.get(namespace)
        label = (node.attributes.get("labels", {}).get("environment") if node else None) or namespace
        return str(label).lower()


def blob(*parts: object) -> str:
    return " ".join(str(p) for p in parts).lower()


def is_model_registry(w: FactNode) -> bool:
    text = blob(unqualified_name(w), w.attributes.get("container_images"), w.attributes.get("pod_labels", {}).values())
    return any(k in text for k in ("mlflow", "model-registry", "kubeflow"))


def is_ml_inference(w: FactNode) -> bool:
    text = blob(unqualified_name(w), w.attributes.get("container_images"), w.attributes.get("pod_labels", {}).values())
    keywords = ("inference", "model-serving", "seldon", "kserve", "triton", "torchserve", "llm", "llama", "ollama")
    return any(k in text for k in keywords)



_AUTH_KEY_RE = re.compile(r"auth|oidc|ldap|oauth|saml|htpasswd", re.IGNORECASE)
_NEGATED_AUTH_KEY_RE = re.compile(r"DISABLE|SKIP|NO[_-]|WITHOUT|INSECURE|ANONYMOUS", re.IGNORECASE)
DISABLED_VALUES = {"none", "false", "disabled", "off", "no", "0", ""}


def auth_declared(ctx: FactContext, w: FactNode) -> bool:
    """True if the manifests declare some authentication for the workload."""
    for key, value in ctx.config_settings(w).items():
        if not _AUTH_KEY_RE.search(key):
            continue
        on = value.strip().lower() not in DISABLED_VALUES
        # DISABLE_AUTH=true / ANONYMOUS_AUTH=on say authentication is OFF.
        if _NEGATED_AUTH_KEY_RE.search(key):
            on = not on
        if on:
            return True
    args = " ".join(a for c in w.attributes.get("containers", []) for a in c["args"] + c["command"]).lower()
    if re.search(r"--(basic-)?auth|--oidc|--ldap", args):
        return True
    return any("oauth2-proxy" in str(c["image"]) for c in w.attributes.get("containers", []))


def is_exposed(ctx: FactContext, w: FactNode) -> list[FactNode]:
    """Services (LoadBalancer/NodePort) and Ingresses that publish the workload."""
    services = ctx.services_for(w)
    published = [s for s in services if s.attributes.get("service_type") in ("LoadBalancer", "NodePort")]
    names = {s.name.split("/", 1)[1] for s in services}
    published += [
        n for n in ctx.nodes
        if n.node_type == "ingress" and n.attributes["namespace"] == w.attributes["namespace"]
        and names & set(n.attributes.get("backend_services", []))
    ]
    return published


def exposure_text(node: FactNode) -> str:
    if node.node_type == "ingress":
        return f"{node.name} publishes it{'' if node.attributes.get('has_tls') else ' without TLS'}"
    return f"{node.name} is type {node.attributes['service_type']}"


def _ingress_auth_declared(ctx: FactContext, w: FactNode) -> bool:
    return any(
        n.node_type == "ingress" and any("auth" in k.lower() for k in n.attributes.get("annotations", {}))
        for n in is_exposed(ctx, w)
    )


def authenticating_workload_names(ctx: FactContext) -> set[str]:
    """Workload fact names (`w.name`, e.g. `Deployment/api`) whose manifests
    declare real authentication (app-level or at the ingress).
    Public entry point for engine/threats/service.py to derive a
    `authenticates_callers` control property from config, the same signal
    `_detect_t01` already uses to withhold SC-T01 -- so a workload that
    already declares auth stops being generic STRIDE noise instead of only
    avoiding the specific config-rule hit. Absence proves nothing (a
    workload not in this set is simply unknown, not "no auth"), matching
    the tri-state property model in engine/threats/properties.py."""
    return {w.name for w in ctx.workloads if auth_declared(ctx, w) or _ingress_auth_declared(ctx, w)}


def ai_ml_component_names(ctx: FactContext) -> set[str]:
    """Workload fact names recognised as a model registry or inference
    service by the existing keyword detectors. Public entry point for
    `engine/threats/service.py` to derive an `is_ai_ml_component` control
    property from config, the same pattern `authenticating_workload_names`
    uses -- so a K8s-sourced model doesn't need manual tagging for a plugin
    methodology's rules that read it. Absence proves nothing (matches
    the tri-state property model)."""
    return {w.name for w in ctx.workloads if is_model_registry(w) or is_ml_inference(w)}


# -- Detectors ---------------------------------------------------------------------------------


def _detect_t01(ctx: FactContext) -> list[Hit]:
    hits = []
    for w in ctx.workloads:
        exposed = is_exposed(ctx, w)
        if not exposed or auth_declared(ctx, w) or _ingress_auth_declared(ctx, w):
            continue
        evidence = [exposure_text(s) for s in exposed]
        evidence.append("no authentication is declared in its manifests")
        hits.append(Hit("component", w.name, evidence))
    return hits


def _grants_admin(binding: FactNode) -> bool:
    return str(binding.attributes["role_ref"].get("name")) == "cluster-admin"


def _detect_t02(ctx: FactContext) -> list[Hit]:
    hits = []
    for b in ctx.bindings:
        if not _grants_admin(b):
            continue
        for subject in b.attributes["subjects"]:
            if subject.get("kind") != "ServiceAccount":
                continue
            for w in ctx.workloads:
                if w.attributes.get("service_account") == subject["name"] and (
                    w.attributes["namespace"] == subject.get("namespace", w.attributes["namespace"])
                ):
                    hits.append(Hit("component", w.name, [f"{b.name} grants cluster-admin to ServiceAccount {subject['name']}"]))
    return hits


def _detect_t08(ctx: FactContext) -> list[Hit]:
    return [
        Hit("component", s.name, [f"credential-like keys held in a ConfigMap: {', '.join(sorted(s.attributes['secret_keys']))}"])
        for s in ctx.stores
        if s.attributes["kind"] == "ConfigMap" and s.attributes.get("secret_keys")
    ]



CONFIG_RULES: tuple[ConfigRule, ...] = (
    ConfigRule("SC-T01", "T01", "process", "Spoofing",
               "{name} is reachable from the internet with no declared authentication",
               "{name} is published outside the cluster (LoadBalancer/NodePort) and its manifests declare no authentication, so anyone who can reach it can use it.",
               "high",
               ("Put an authenticating proxy or ingress with SSO in front, or enable the application's own authentication.",
                "Restrict source addresses with a NetworkPolicy or load-balancer allow-list.",
                "Use an internal (ClusterIP) service and reach it through a VPN or bastion."),
               ("CWE-306",), ("T1190",),
               "A workload is exposed by a LoadBalancer or NodePort Service and no authentication setting is declared", _detect_t01),
    ConfigRule("SC-T02", "T02", "process", "ElevationOfPrivilege",
               "{name} runs with cluster-admin rights",
               "The ServiceAccount used by {name} is bound to cluster-admin, so a compromise of this workload is a compromise of the whole cluster.",
               "critical",
               ("Replace the binding with a namespaced Role that grants only the verbs and resources needed.",
                "Bind the ServiceAccount only in the namespaces it must manage.",
                "Audit ServiceAccount permissions regularly (kubectl auth can-i --list)."),
               ("CWE-250", "CWE-269"), ("T1078",),
               "A ServiceAccount used by a workload is bound to the cluster-admin ClusterRole", _detect_t02),
    ConfigRule("SC-T08", "T08", "data_store", "InformationDisclosure",
               "Credentials are stored in ConfigMap {name}",
               "{name} holds credential-like values. ConfigMaps are not encrypted at rest and are readable by anyone with read access to the namespace.",
               "high",
               ("Move the values into Kubernetes Secrets (with encryption at rest) or an external secret manager.",
                "Rotate every credential that has been stored in the ConfigMap.",
                "Restrict read access to Secrets with RBAC."),
               ("CWE-256", "CWE-798"), ("T1552",),
               "A ConfigMap key names a credential (password, token, secret, API key) or a value embeds credentials in a URL", _detect_t08),
)

# AWS/Terraform sample rules live in their own module. It imports ConfigRule/Hit/FactContext
# from here, so it can only be imported once they are defined -- hence the bottom of
# the file, not the top.
from kresheen.engine.threats import config_rules_aws

CONFIG_RULES = (*CONFIG_RULES, *config_rules_aws.AWS_CONFIG_RULES)
CONFIG_RULES_BY_ID: dict[str, ConfigRule] = {rule.id: rule for rule in CONFIG_RULES}


def all_config_rules() -> tuple[ConfigRule, ...]:
    """The core's sample rules followed by whatever the installed plugins add."""
    return (*CONFIG_RULES, *get_registry().config_rules())


__all__ = ["CONFIG_RULES", "CONFIG_RULES_BY_ID", "ConfigRule", "FactContext", "Hit", "all_config_rules"]
