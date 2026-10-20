"""Coverage invariant.

Diagram elements are covered by construction: every DFD element gets the
full STRIDE-per-element pass (catalog.py). Facts that are *not* diagram
boxes -- Ingress, RBAC bindings, NetworkPolicy -- are only ever looked at by
the config rules' detectors, and those detectors only walk facts that
resolve all the way to a workload on the diagram (FactContext.workloads).
An Ingress whose backend Service doesn't exist, or a RoleBinding whose
subject isn't a ServiceAccount any workload uses, is silently skipped by
every detector today -- not "no threat", just never evaluated by anything.

This module finds those unevaluated facts. It does not re-judge anything a
detector already considered and decided was fine (that decision -- a hit,
or a deliberate "no hit" -- is itself the explicit not-applicable the
feature asks for); it only flags facts nothing ever looked at.

NetworkPolicy is not checked here: every NetworkPolicy fact is inherently
consulted (a rule that wants to know which namespaces are covered builds its
set from all of them, regardless of whether any workload matches a
selector), so there is no analogous "never looked at" case to catch for that fact type.
"""

from __future__ import annotations

from dataclasses import dataclass

from kresheen.engine.threats.config_rules import FactContext
from kresheen.models.facts import FactEdge, FactNode

CoverageGapKind = str  # "ingress" | "rbac_binding"


@dataclass(frozen=True)
class CoverageGap:
    kind: CoverageGapKind
    name: str
    reason: str


def check_coverage(fact_nodes: list[FactNode], fact_edges: list[FactEdge]) -> list[CoverageGap]:
    """Entry-point facts no detector ever got a chance to evaluate."""
    if not fact_nodes:
        return []
    ctx = FactContext(fact_nodes, fact_edges)
    gaps: list[CoverageGap] = []

    gaps.extend(_ingress_gaps(fact_nodes, ctx, fact_edges))
    gaps.extend(_rbac_binding_gaps(ctx))
    return gaps


def _ingress_gaps(fact_nodes: list[FactNode], ctx: FactContext, fact_edges: list[FactEdge]) -> list[CoverageGap]:
    service_by_ns_name = {(s.attributes["namespace"], s.name.split("/", 1)[1]): s for s in ctx.services}
    services_with_targets = {e.source_node_id for e in fact_edges if e.edge_type == "routes_to"}

    gaps: list[CoverageGap] = []
    for ingress in (n for n in fact_nodes if n.node_type == "ingress"):
        backends = ingress.attributes.get("backend_services", [])
        if not backends:
            gaps.append(CoverageGap("ingress", ingress.name, "declares no backend service, so no rule evaluated it"))
            continue
        for backend in backends:
            svc = service_by_ns_name.get((ingress.attributes["namespace"], backend))
            if svc is None:
                gaps.append(CoverageGap(
                    "ingress", ingress.name,
                    f"names backend service '{backend}', not found in namespace {ingress.attributes['namespace']}",
                ))
            elif svc.id not in services_with_targets:
                gaps.append(CoverageGap(
                    "ingress", ingress.name,
                    f"routes to Service {backend}, but its selector matches no workload, so no rule evaluated it",
                ))
    return gaps


def _rbac_binding_gaps(ctx: FactContext) -> list[CoverageGap]:
    workload_sa_ns = {(w.attributes.get("service_account"), w.attributes["namespace"]) for w in ctx.workloads}

    gaps: list[CoverageGap] = []
    for binding in ctx.bindings:
        subjects = binding.attributes.get("subjects") or []
        if not subjects:
            gaps.append(CoverageGap("rbac_binding", binding.name, "declares no subjects, so no rule evaluated it"))
            continue
        for subject in subjects:
            kind = subject.get("kind")
            if kind != "ServiceAccount":
                gaps.append(CoverageGap(
                    "rbac_binding", binding.name,
                    f"grants a role to a {kind or 'unknown'} subject; config rules only evaluate ServiceAccount subjects",
                ))
                continue
            ns = subject.get("namespace") or binding.attributes.get("binding_namespace")
            if (subject.get("name"), ns) not in workload_sa_ns:
                gaps.append(CoverageGap(
                    "rbac_binding", binding.name,
                    f"grants a role to ServiceAccount {subject.get('name')} ({ns}), which no workload in the diagram uses",
                ))
    return gaps
