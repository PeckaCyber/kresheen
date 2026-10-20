"""Generates design-level threats for a DFD from the rule catalog.

A pure function of the diagram (`DfdElement`s and `DfdFlow`s): no I/O, no
storage, no dependence on which run produced the nodes. The route layer
feeds it the same merged DFD the user is looking at, so threats always
reflect manual components, boundary overrides, and manual flows too.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from kresheen.engine.threats.catalog import ThreatRule
from kresheen.engine.threats.cia import cia_impacts_for
from kresheen.engine.threats.methodology import methodology_rules
from kresheen.models.threat import ManualThreat, Methodology, Threat

DEFAULT_METHODOLOGIES: frozenset[Methodology] = frozenset({"STRIDE"})

_UNTRUSTED_BOUNDARY_HINTS = ("internet", "public", "dmz", "external", "untrusted", "third")
"""Substrings that make a free-text trust-boundary label read as
untrusted-facing. Matches the labels the UI suggests ("internet-facing",
"third-party") as well as common variants ("Public subnet", "DMZ")."""


@dataclass(frozen=True)
class DfdElement:
    id: str
    name: str
    type: str  # process | data_store | external_entity
    trust_boundary: str | None = None
    # None = judge exposure from the boundary label text (a boundary the user
    # typed). True/False = decided from evidence by the loader, used when the
    # label was derived by machine (e.g. a Kubernetes namespace named
    # "external-secrets", which says nothing about internet exposure).
    untrusted_facing: bool | None = None
    # Owner-stated properties (models/element_properties.py); absent = unknown.
    properties: dict = field(default_factory=dict, compare=False)
    # Drawn by hand (source="manual"), not derived from any ingested source --
    # see risk.py's asserted-vs-verified provenance tagging.
    is_manual: bool = False
    # True when `trust_boundary` above comes from a user's TrustBoundaryAssignment
    # override rather than being auto-derived -- same signal engine/dfd/view.py's
    # `boundary_overridden` computes for the UI, threaded here too so risk.py can
    # tell an owner-typed boundary label from an evidence-derived one.
    boundary_asserted: bool = False


@dataclass(frozen=True)
class DfdFlow:
    id: str
    source_id: str
    target_id: str
    label: str | None = None
    properties: dict = field(default_factory=dict, compare=False)
    # Drawn by hand (a ManualFlow), not derived from any ingested source.
    is_manual: bool = False


def is_untrusted_boundary(label: str | None) -> bool:
    if not label:
        return False
    lowered = label.lower()
    return any(hint in lowered for hint in _UNTRUSTED_BOUNDARY_HINTS)


def component_element_key(element: DfdElement) -> str:
    return f"{element.type}:{element.name}"


def flow_element_key(source: DfdElement, target: DfdElement) -> str:
    return f"flow:{source.name}->{target.name}"


def component_key(rule_id: str, element: DfdElement) -> str:
    return f"{rule_id}|{component_element_key(element)}"


def flow_key(rule_id: str, source: DfdElement, target: DfdElement) -> str:
    return f"{rule_id}|{flow_element_key(source, target)}"


def _boundary_matches(hint: str | None, *labels: str | None) -> bool:
    if hint is None:
        return True
    needle = hint.lower()
    return any(label is not None and needle in label.lower() for label in labels)


def crosses_boundary(source: DfdElement, target: DfdElement) -> bool:
    """Two labeled boundaries that differ, or an external entity talking to
    something that isn't one. A component with no boundary label is
    "unassigned", not "different", so an unlabeled model doesn't light up
    every flow. Public: also used by engine/attack_paths.py."""
    if source.trust_boundary and target.trust_boundary and source.trust_boundary != target.trust_boundary:
        return True
    return (source.type == "external_entity") != (target.type == "external_entity")


def _when_matches(rule: ThreatRule, properties: dict) -> bool:
    """True when every property the rule needs has exactly the stated value.
    An unset property never matches, so an element with no properties gets
    exactly the generic threats it always did."""
    return all(key in properties and type(properties[key]) is type(value) and properties[key] == value
               for key, value in rule.when)


def _asserted_factors(rule: ThreatRule, properties: dict) -> list[str]:
    if not rule.when:
        return []
    factors = [f"owner states: {rule.asserted}"]
    if properties.get("crosses_public_network") is True:
        factors.append("crosses a public network")
    return factors


def _fill(text: str, name: str) -> str:
    return text.replace("{name}", name)


def _build(
    rule: ThreatRule,
    *,
    key: str,
    kind: str,
    element_id: str,
    element_name: str,
    element_type: str,
    risk_factors: list[str],
) -> Threat:
    return Threat(
        key=key,
        rule_id=rule.id,
        element_kind="component" if kind == "component" else "flow",
        element_id=element_id,
        element_name=element_name,
        element_type=element_type,
        methodology=rule.methodology,
        category=rule.category,
        cia_impacts=cia_impacts_for(rule.methodology, rule.category),
        origin=rule.origin,
        title=_fill(rule.title, element_name),
        description=_fill(rule.description, element_name),
        severity=rule.severity,
        mitigations=[_fill(m, element_name) for m in rule.mitigations],
        cwe_refs=list(rule.cwe),
        attack_refs=list(rule.attack),
        risk_factors=risk_factors,
    )


def generate_threats(
    elements: list[DfdElement],
    flows: list[DfdFlow],
    *,
    extra_rules: tuple[ThreatRule, ...] | list[ThreatRule] = (),
    methodologies: frozenset[Methodology] | set[Methodology] = DEFAULT_METHODOLOGIES,
) -> list[Threat]:
    """Returns threats ordered by risk (impact x likelihood; every threat is
    `possible` until engine/threats/risk.py assesses it), then impact, then
    component before flow, then name, so the output is deterministic. Duplicate keys (two components
    sharing a name and type, or parallel flows between the same pair) collapse
    to one threat: the key is name-based on purpose, see models/threat.py.
    `extra_rules` (user-authored, see engine/threats/custom.py) run alongside
    the built-in catalogs (STRIDE and any plugin methodology, `methodology_rules()`). `methodologies` (default STRIDE-only, matching
    `Application.methodologies`'s default) filters both the built-in and
    extra rules -- a rule whose methodology isn't selected never fires,
    same as one whose element_type doesn't match."""
    rules = [
        rule
        for rule in (*methodology_rules(), *extra_rules)
        if rule.methodology in methodologies or rule.methodology == "Custom"
    ]
    by_id = {element.id: element for element in elements}
    threats: dict[str, Threat] = {}

    for element in elements:
        evidence_based = element.untrusted_facing is not None
        untrusted = element.untrusted_facing if evidence_based else is_untrusted_boundary(element.trust_boundary)
        for rule in rules:
            if rule.element_type != element.type:
                continue
            if rule.condition == "untrusted_facing" and not untrusted:
                continue
            if not _boundary_matches(rule.boundary_hint, element.trust_boundary):
                continue
            if not _when_matches(rule, element.properties):
                continue
            factors = _asserted_factors(rule, element.properties)
            if rule.condition == "untrusted_facing":
                factors += [
                    "directly reachable from an external entity"
                    if evidence_based
                    else f"in untrusted-facing boundary '{element.trust_boundary}'"
                ]
            key = component_key(rule.id, element)
            threats.setdefault(
                key,
                _build(
                    rule,
                    key=key,
                    kind="component",
                    element_id=element.id,
                    element_name=element.name,
                    element_type=element.type,
                    risk_factors=factors,
                ),
            )

    for flow in flows:
        source = by_id.get(flow.source_id)
        target = by_id.get(flow.target_id)
        if source is None or target is None:
            continue
        crosses = crosses_boundary(source, target)
        display = f"{source.name} -> {target.name}"
        for rule in rules:
            if rule.element_type != "data_flow":
                continue
            if rule.condition == "crosses_boundary" and not crosses:
                continue
            if not _boundary_matches(rule.boundary_hint, source.trust_boundary, target.trust_boundary):
                continue
            if not _when_matches(rule, flow.properties):
                continue
            key = flow_key(rule.id, source, target)
            threats.setdefault(
                key,
                _build(
                    rule,
                    key=key,
                    kind="flow",
                    element_id=flow.id,
                    element_name=display,
                    element_type="data_flow",
                    risk_factors=_asserted_factors(rule, flow.properties)
                    + (["crosses a trust boundary"] if rule.condition == "crosses_boundary" else []),
                ),
            )

    return _sorted(threats.values())


def apply_manual_threats(
    manual: list[ManualThreat], elements: list[DfdElement], flows: list[DfdFlow]
) -> list[Threat]:
    """Resolves each hand-attached threat against the current diagram by its
    name-based element key. One whose element is no longer present is left
    out (it stays stored and reappears if the element does)."""
    by_id = {element.id: element for element in elements}
    targets: dict[str, tuple[str, str, str, str]] = {}  # element_key -> (kind, id, display name, type)
    for element in elements:
        targets.setdefault(component_element_key(element), ("component", element.id, element.name, element.type))
    for flow in flows:
        source, target = by_id.get(flow.source_id), by_id.get(flow.target_id)
        if source is not None and target is not None:
            targets.setdefault(
                flow_element_key(source, target),
                ("flow", flow.id, f"{source.name} -> {target.name}", "data_flow"),
            )

    threats: list[Threat] = []
    for item in manual:
        resolved = targets.get(item.element_key)
        if resolved is None:
            continue
        kind, element_id, element_name, element_type = resolved
        threats.append(
            Threat(
                key=f"{item.id}|{item.element_key}",
                rule_id=item.id,
                element_kind="component" if kind == "component" else "flow",
                element_id=element_id,
                element_name=element_name,
                element_type=element_type,
                methodology=item.methodology,
                category=item.category,
                cia_impacts=cia_impacts_for(item.methodology, item.category),
                title=item.title,
                description=item.description,
                severity=item.severity,
                mitigations=list(item.mitigations),
                origin="manual",
                manual_threat_id=item.id,
            )
        )
    return threats


def sort_threats(threats: list[Threat]) -> list[Threat]:
    return _sorted(threats)


def _sorted(threats: Iterable[Threat]) -> list[Threat]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    # At equal risk, what was observed or is specific to this design outranks a generic
    # checklist item. Risk still decides first.
    basis_rank = {"observed": 0, "specific": 1, "generic": 2}
    return sorted(
        threats,
        key=lambda t: (
            -t.risk_score,
            basis_rank[t.basis],
            severity_rank[t.severity],
            t.element_kind,
            t.element_name.lower(),
            t.rule_id,
        ),
    )
