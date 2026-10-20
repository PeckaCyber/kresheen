"""Builds the design-level threat list for one run: the merged DFD, the
built-in rule catalogs (STRIDE plus any plugin methodology), user-authored KB rules, and hand-attached manual
threats. Shared by the threats API and the validation harness."""

from __future__ import annotations

from dataclasses import replace

from kresheen.engine.dfd.merge import merge_run_dfd
from kresheen.engine.ingest.k8s_facts import BOUNDARY_KIND_NAMESPACE, NON_NETWORK_EDGE_LABELS
from kresheen.engine.ingest.terraform_facts import BOUNDARY_KIND_NETWORK
from kresheen.engine.threats.cia import cia_impacts_for
from kresheen.engine.threats.config_rules import (
    FactContext,
    ai_ml_component_names,
    all_config_rules,
    authenticating_workload_names,
)
from kresheen.engine.threats.custom import rules_from_kb_entries
from kresheen.engine.threats.generate import (
    DEFAULT_METHODOLOGIES,
    DfdElement,
    DfdFlow,
    apply_manual_threats,
    component_element_key,
    generate_threats,
    sort_threats,
)
from kresheen.engine.threats.methodology import available_methodology_names
from kresheen.engine.threats.properties import is_out_of_scope
from kresheen.engine.threats.risk import assess_threats
from kresheen.models.threat import Methodology, Threat
from kresheen.plugins import get_registry
from kresheen.storage.repository import Repository

GROUPING_EDGE_LABEL = "discovered_in"
"""The GitHub ingestor's hub-and-spoke edges mean "found while scanning this
repo", not a data flow (see github_repository_ingestor.py) -- never a
threat target."""


NON_FLOW_LABELS = frozenset({GROUPING_EDGE_LABEL}) | NON_NETWORK_EDGE_LABELS
"""Edge labels that aren't network data flows and so attract no flow threats."""


class UnknownRunError(LookupError):
    pass


def load_dfd_model(application_id: str, run_id: str, repo: Repository) -> tuple[list[DfdElement], list[DfdFlow]]:
    run = repo.get_run(run_id)
    if run is None or run.application_id != application_id:
        raise UnknownRunError(run_id)

    merged = merge_run_dfd(application_id, run_id, repo)
    # Files and the repo hub are facts about what was scanned, not system
    # components a designer would threat-model (a `go.sum` is not a process).
    fact_nodes = repo.list_fact_nodes_for_run(run_id)
    excluded_ids = {
        node.id
        for node in fact_nodes
        if node.node_type == "code_artifact" or node.source_ref == "github_repository"
    }
    name_by_id = {asset.id: asset.name for asset in merged.assets}
    flows = [
        DfdFlow(
            id=e["id"],
            source_id=e["source"],
            target_id=e["target"],
            label=e["label"],
            properties=merged.properties_by_key.get(
                f"flow:{name_by_id.get(e['source'])}->{name_by_id.get(e['target'])}", {}
            ),
            is_manual=e["is_manual"],
        )
        for e in merged.edges
        if e["label"] not in NON_FLOW_LABELS
    ]

    # A namespace- or subnet/VPC-derived boundary label says nothing about
    # exposure, so for those (unless the user relabelled the component) exposure
    # is evidence: a flow arriving straight from an external entity.
    namespace_bounded = {
        node.id
        for node in fact_nodes
        if node.attributes.get("boundary_kind") in (BOUNDARY_KIND_NAMESPACE, BOUNDARY_KIND_NETWORK)
    }
    external_ids = {asset.id for asset in merged.assets if asset.type.value == "external_entity"}
    fed_by_external = {flow.target_id for flow in flows if flow.source_id in external_ids}

    elements = [
        DfdElement(
            id=asset.id,
            name=asset.name,
            type=asset.type.value,
            trust_boundary=merged.boundary_by_name.get(asset.name, asset.trust_boundary),
            untrusted_facing=(
                asset.id in fed_by_external
                if asset.id in namespace_bounded and asset.name not in merged.boundary_by_name
                else None
            ),
            properties=merged.properties_by_key.get(f"{asset.type.value}:{asset.name}", {}),
            is_manual=asset.id in merged.manual_asset_ids,
            # Same signal engine/dfd/view.py's `boundary_overridden` computes.
            boundary_asserted=asset.name in merged.boundary_by_name,
        )
        for asset in merged.assets
        if asset.id not in excluded_ids
    ]
    return elements, flows


def generate_config_threats(
    context: FactContext | None, elements: list[DfdElement], flows: list[DfdFlow]
) -> list[Threat]:
    """Runs the configuration-aware rules (config_rules.py) over the run's facts
    and attaches each hit to the matching diagram element, matched by name so a
    hit on something not on the diagram is dropped, never invented."""
    if context is None:
        return []
    element_by_name = {e.name: e for e in elements}
    element_by_id = {e.id: e for e in elements}
    flow_by_names: dict[tuple[str, str], DfdFlow] = {}
    for flow in flows:
        src, dst = element_by_id.get(flow.source_id), element_by_id.get(flow.target_id)
        if src and dst:
            flow_by_names.setdefault((src.name, dst.name), flow)

    threats: dict[str, Threat] = {}
    superseded: set[str] = set()
    for rule in all_config_rules():
        for hit in rule.detect(context):
            if hit.kind == "component":
                element = element_by_name.get(hit.target)
                if element is None:
                    continue
                key = f"{rule.id}|{component_element_key(element)}"
                kind, element_id, name, element_type = "component", element.id, element.name, element.type
            elif hit.kind == "flow":
                src_name, dst_name = hit.target.split("->", 1)
                found_flow = flow_by_names.get((src_name, dst_name))
                if found_flow is None:
                    continue
                key = f"{rule.id}|flow:{src_name}->{dst_name}"
                kind, element_id, name, element_type = "flow", found_flow.id, f"{src_name} -> {dst_name}", "data_flow"
            else:
                key = f"{rule.id}|boundary:{hit.target}"
                kind, element_id, name, element_type = "boundary", hit.target, hit.target, "trust_boundary"
            superseded.update(f"{other}|{key.split('|', 1)[1]}" for other in rule.supersedes)
            threats.setdefault(
                key,
                Threat(
                    key=key,
                    rule_id=rule.id,
                    element_kind=kind,  # type: ignore[arg-type]  # one of component/flow/boundary above
                    element_id=element_id,
                    element_name=name,
                    element_type=element_type,
                    methodology="STRIDE",
                    category=rule.category,
                    cia_impacts=cia_impacts_for("STRIDE", rule.category),
                    title=rule.title.replace("{name}", name),
                    description=rule.description.replace("{name}", name),
                    severity=rule.severity,
                    mitigations=list(rule.mitigations),
                    cwe_refs=list(rule.cwe),
                    attack_refs=list(rule.attack),
                    risk_factors=list(hit.evidence),
                    taxonomy_ids=[rule.taxonomy_id],
                ),
            )
    return [threat for key, threat in threats.items() if key not in superseded]


def _with_derived_controls(elements: list[DfdElement], context: FactContext | None) -> list[DfdElement]:
    """Layers config-derived control properties under the owner-stated ones:
    a manifest that already
    declares real authentication shouldn't also read as unauthenticated
    generic-rule noise. An explicit owner-set value always wins -- this only
    fills a property the owner left unset. Absence never sets a property:
    a workload not in `authenticating_workload_names` stays unknown, not
    "no auth", matching the tri-state model (properties.py). Also fills
    `is_ai_ml_component` from the existing K8s ML detectors the same way,
    so a K8s-sourced model doesn't need manual tagging for a plugin
    methodology's rules that read it. The property is inert unless one does."""
    if context is None:
        return elements
    authenticating = authenticating_workload_names(context)
    ai_ml = ai_ml_component_names(context)
    updated = []
    for element in elements:
        properties = dict(element.properties)
        if element.name in authenticating and "authenticates_callers" not in properties:
            properties["authenticates_callers"] = True
        if element.name in ai_ml and "is_ai_ml_component" not in properties:
            properties["is_ai_ml_component"] = True
        updated.append(replace(element, properties=properties) if properties != element.properties else element)
    return updated


def load_derived_dfd_model(
    application_id: str, run_id: str, repo: Repository
) -> tuple[list[DfdElement], list[DfdFlow]]:
    """The merged DFD with config-derived controls layered under the owner's stated properties,
    i.e. what the threat generator actually reasons over. Used by the completeness check so it
    does not ask about a fact the configuration already states."""
    elements, flows = load_dfd_model(application_id, run_id, repo)
    fact_nodes = repo.list_fact_nodes_for_run(run_id)
    context = FactContext(fact_nodes, repo.list_fact_edges_for_run(run_id)) if fact_nodes else None
    return _with_derived_controls(elements, context), flows


def generate_run_threats(
    application_id: str, run_id: str, repo: Repository
) -> list[Threat]:
    application = repo.get_application(application_id)
    # A selection this installation cannot generate for (a plugin methodology after its licence lapsed) is skipped,
    # not fatal; the UI says so (see `unavailable_methodologies`).
    methodologies: frozenset[Methodology] = (
        frozenset(application.methodologies) & available_methodology_names() if application else DEFAULT_METHODOLOGIES
    )
    elements, flows = load_dfd_model(application_id, run_id, repo)
    fact_nodes = repo.list_fact_nodes_for_run(run_id)
    context = FactContext(fact_nodes, repo.list_fact_edges_for_run(run_id)) if fact_nodes else None
    elements_for_threats = _with_derived_controls(elements, context)
    entries = repo.list_kb_entries()
    # The curated feed is not part of the open-source core; a plugin supplies it through `threat_sources`.
    entries = [e for e in entries if e.source != "kresheen_curated"]
    generated = generate_threats(
        elements_for_threats, flows, extra_rules=[*rules_from_kb_entries(entries), *get_registry().threat_rules(repo)], methodologies=methodologies
    )
    if "STRIDE" in methodologies:
        generated += generate_config_threats(context, elements, flows)
    # An element the owner marked out of scope has no generated threats (built-in,
    # custom or config rule). Manual threats are added after, so they stay.
    out_of_scope = {e.id for e in elements if is_out_of_scope(e.properties)} | {
        f.id for f in flows if is_out_of_scope(f.properties)
    }
    generated = [t for t in generated if t.element_kind == "boundary" or t.element_id not in out_of_scope]
    generated = assess_threats(
        generated,
        elements=elements_for_threats,
        flows=flows,
        findings=repo.list_findings(run_id=run_id, status="open"),
        fact_nodes=fact_nodes,
    )
    manual = apply_manual_threats(repo.list_manual_threats(application_id), elements, flows)
    return sort_threats([*generated, *manual])
