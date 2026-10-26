"""The risk model: how likely each generated threat is here, and what supports it.

Separates a *threat* (a class of problem a design can have) from *evidence* (a
finding that makes it more likely). A threat stands whether or not any bug has
been found (`PROC-T-01`: code or dependencies of this component can be tampered
with). A finding is one observed
instance. Findings never create threats here; they raise the likelihood of a
threat they support, and are listed on it. So a component with critical
findings outranks an identical one with none, and fixing every finding leaves
the threat (at a lower likelihood) rather than deleting it.

Likelihood starts at `possible` (`likely` when a config detector positively
found the misconfiguration in the ingested manifests). Each reason below is
recorded in `likelihood_factors`:

- **owner-stated weakness**: a rule that fires only on a property the owner set
  (`ThreatRule.when`, e.g. "not encrypted"). Lifts it to at least `likely`.
- **exposure**: the component (or an end of the flow) is directly reachable
  from an untrusted caller. Lifts it to at least `likely`.
- **component evidence**: an open finding on the same component and STRIDE
  category confirms the weakness (for a flow-kind threat, on either endpoint).
  Medium or worse lifts it to at least `likely`.
  High or critical evidence *on an exposed component* is one route to
  `almost_certain`; so is a supporting finding **known to be actively
  exploited** (Grype's native-json `knownExploited`, CISA's KEV catalog) or
  with a high **EPSS** score (`_EPSS_ALMOST_CERTAIN_THRESHOLD`), independent of
  severity -- both only ever apply to component evidence, never repository
  evidence, same reasoning as the severity route below.
- **repository evidence**: open high or critical dependency vulnerabilities in
  the source repository the component was defined in, on the dependency-
  tampering rule only. Lifts it to at least `likely` but can never reach
  `almost_certain`, since the CVE is not shown to be in this component's image
  -- an exploitation signal doesn't change that; it still isn't confirmed
  present here.

`almost_certain` is deliberately hard to reach: that level is reserved for
active exploitation, so evidence and exposure alone (no exploitation signal)
top out at `likely`.

**Asset sensitivity as an impact input**. A `data_classification` property (any non-empty text -- PII, PCI,
credentials, ...) on the threat's own element (component) or flow raises that
threat's impact (severity) by one level, capped at `critical`, via
`_bump_severity` below. This changes impact, not likelihood -- the
existing `risk_factors` list (already rendered by the UI) carries the reason,
since `Threat` has no separate "why this impact" field. Deliberately simple
(the threat's own element only, no borrowing a flow's severity from its
endpoints) to stay independent of the endpoint-evidence work above.

**Controls.** A handful of
generic rules pair with a specific property that, when it holds, is exactly
the weakness the rule describes (`CONTROL_MITIGATIONS` below). If the
property covers every way in -- the component itself asserts it, or every
incoming flow individually does -- the `exposed` bump above is withheld for
that threat, since exposure alone no longer says anything the control
doesn't already answer. If only some incoming flows are covered, the bump
still applies (a gap remains) but the threat is recorded as `partially
mitigated` in its factors so triage can see the difference from "nothing is
known." A control never *removes* a threat or lowers it below its exposure-
free baseline -- generic rules stay a permanent floor, and open evidence
(findings) always outranks an asserted control, since evidence is what was
actually observed, not what was configured.

Impact is the rule's severity. Risk = impact x likelihood (models/threat.py).
Manual threats are not assessed (the user has already judged them).
"""

from __future__ import annotations

from kresheen.engine.threats.catalog import ASSERTED_RULES
from kresheen.engine.threats.generate import DfdElement, DfdFlow, is_untrusted_boundary
from kresheen.models.facts import FactNode
from kresheen.models.finding import Domain, Finding
from kresheen.models.threat import (
    LIKELIHOOD_ORDER,
    Likelihood,
    Threat,
    ThreatEvidence,
    ThreatSeverity,
)

EVIDENCE_LIMIT = 10
"""Findings listed per threat. A repository can have hundreds of CVEs; the rest
are counted in `evidence_total`."""

REPOSITORY_EVIDENCE_RULES = frozenset({"PROC-T-01"})
"""Rules a repository's dependency vulnerabilities support: the one about the
component's code and dependencies being tampered with or exploited."""

CONTROL_MITIGATIONS: dict[str, tuple[str, bool]] = {
    # rule id -> (element/flow property, value that satisfies the control)
    "PROC-S-01": ("authenticates_callers", True),
    "PROC-S-02": ("authenticates_callers", True),
    "STORE-I-01": ("is_encrypted", True),
    "STORE-I-02": ("is_encrypted", True),
    "FLOW-I-01": ("is_encrypted", True),
    "FLOW-T-01": ("is_encrypted", True),
    "FLOW-I-02": ("is_encrypted", True),
}
"""Generic rule id -> the property that, when true, is exactly the weakness
the rule describes. Component-scoped for PROC-*/STORE-*, flow-scoped for
FLOW-*. Deliberately small: only rules with a single, unambiguous property
covering the whole rule are listed here, not every rule with some related
property (e.g. PROC-T-01 "code or input can be tampered with" has no one
property that closes it)."""

_ENTRY_PATH_RULES = frozenset({"PROC-S-01", "PROC-S-02"})
"""Component rules where, absent a component-level control statement,
coverage is judged per incoming flow instead (FLOW-P-02's `authenticated`),
since spoofing is about who is allowed to call in, not one internal setting."""

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_IMPACT_ORDER: tuple[ThreatSeverity, ...] = ("low", "medium", "high", "critical")
"""`Threat.severity`'s four values, low to high -- distinct from
`_SEVERITY_RANK` (which also has "info", for Finding.severity)."""

_EPSS_ALMOST_CERTAIN_THRESHOLD = 0.5
"""EPSS (Exploit Prediction Scoring System) probability of exploitation in
the next 30 days. 0.5 ("more likely than not") is a common analyst starting
threshold, not a validated cutoff -- revisit once real scan data is seen."""


def _bump_severity(severity: ThreatSeverity) -> ThreatSeverity:
    """One impact level up, capped at critical."""
    idx = _IMPACT_ORDER.index(severity)
    return _IMPACT_ORDER[min(idx + 1, len(_IMPACT_ORDER) - 1)]


def is_exposed(element: DfdElement) -> bool:
    """Directly reachable from an untrusted caller. Evidence when the loader
    set it, otherwise the boundary label the user typed."""
    if element.type == "external_entity":
        return False  # it is the untrusted caller, not something exposed to one
    if element.untrusted_facing is not None:
        return element.untrusted_facing
    return is_untrusted_boundary(element.trust_boundary)


def _exposure_is_asserted(element: DfdElement | None) -> bool:
    """True when `is_exposed(element)` is True only because of a trust-boundary
    label the user typed or overrode (`boundary_asserted`), not evidence the
    loader observed (`untrusted_facing`):
    an owner's assertion changes threat output exactly as evidence does today,
    with no way to tell the two apart in what the threat says. This doesn't
    change the likelihood bump `is_exposed` already grants; it only changes
    which sentence explains it."""
    return (
        element is not None
        and element.untrusted_facing is None
        and element.boundary_asserted
        and is_untrusted_boundary(element.trust_boundary)
    )


def _step(level: int, by: int = 1) -> int:
    return min(level + by, len(LIKELIHOOD_ORDER) - 1)


def _evidence(findings: list[Finding], scope: str) -> list[ThreatEvidence]:
    return [
        ThreatEvidence(
            finding_id=f.id,
            title=f.title,
            severity=f.severity.value,
            scope=scope,  # type: ignore[arg-type]
        )
        for f in findings
    ]


def _worst(evidence: list[Finding]) -> int:
    return max((_SEVERITY_RANK[f.severity.value] for f in evidence), default=0)


def _control_coverage(
    threat: Threat,
    element_by_id: dict[str, DfdElement],
    flow_by_id: dict[str, DfdFlow],
    incoming_by_target: dict[str, list[DfdFlow]],
) -> tuple[str | None, str | None]:
    """(full coverage note, partial coverage note) for `threat`, or (None,
    None) if CONTROL_MITIGATIONS has nothing to say about it. A component
    rule is fully covered if the component itself asserts the property,
    else -- for `_ENTRY_PATH_RULES` only -- if every incoming flow does. A
    flow rule is covered only by that flow's own property."""
    mitigation = CONTROL_MITIGATIONS.get(threat.rule_id)
    if mitigation is None:
        return None, None
    prop, expected = mitigation

    if threat.element_kind == "flow":
        flow = flow_by_id.get(threat.element_id)
        if flow is not None and flow.properties.get(prop) is expected:
            return f"owner states {prop.replace('_', ' ')}", None
        return None, None

    if threat.element_kind != "component":
        return None, None

    element = element_by_id.get(threat.element_id)
    if element is not None and element.properties.get(prop) is expected:
        return f"owner states {prop.replace('_', ' ')}", None
    if threat.rule_id not in _ENTRY_PATH_RULES:
        return None, None

    incoming = incoming_by_target.get(threat.element_id, [])
    if not incoming:
        return None, None
    authenticated = [f for f in incoming if f.properties.get("authenticated") is True]
    if len(authenticated) == len(incoming):
        return "every entry path requires authentication", None
    if authenticated:
        return None, f"{len(authenticated)} of {len(incoming)} entry paths require authentication"
    return None, None


def assess_threats(
    threats: list[Threat],
    *,
    elements: list[DfdElement],
    flows: list[DfdFlow],
    findings: list[Finding],
    fact_nodes: list[FactNode],
) -> list[Threat]:
    """Returns each generated threat with its likelihood, factors and evidence
    set. Only open findings count: a resolved, accepted or false-positive
    finding is no longer evidence."""
    open_findings = [f for f in findings if f.status == "open"]
    exposed_ids = {e.id for e in elements if is_exposed(e)}
    flow_ends = {f.id: (f.source_id, f.target_id) for f in flows}
    fact_by_id = {n.id: n for n in fact_nodes}
    element_by_id = {e.id: e for e in elements}
    flow_by_id = {f.id: f for f in flows}
    incoming_by_target: dict[str, list[DfdFlow]] = {}
    for f in flows:
        incoming_by_target.setdefault(f.target_id, []).append(f)

    on_component: dict[str, list[Finding]] = {}
    for finding in open_findings:
        if finding.evidence.stride_category:
            on_component.setdefault(finding.asset_id, []).append(finding)

    repo_vulns: dict[str, list[Finding]] = {}
    for finding in open_findings:
        if finding.domain != Domain.VULNERABILITY or not finding.evidence.attack_path:
            continue
        origin = fact_by_id.get(finding.evidence.attack_path[0])
        repo = origin.attributes.get("repo") if origin else None
        if repo:
            repo_vulns.setdefault(str(repo), []).append(finding)

    assessed: list[Threat] = []
    for threat in threats:
        if threat.origin == "manual":
            assessed.append(threat)
            continue

        factors: list[str] = []
        level = LIKELIHOOD_ORDER.index("likely" if threat.taxonomy_ids else "possible")
        if threat.taxonomy_ids:
            factors.append("the misconfiguration is declared in the ingested configuration")
        if threat.rule_id in ASSERTED_RULES:
            # The owner said the weakness is there, which is the same kind of
            # positive statement as a config detector finding it.
            level = max(level, LIKELIHOOD_ORDER.index("likely"))
            factors.append(f"owner states: {ASSERTED_RULES[threat.rule_id]}")

        # Provenance of the element/flow itself: a hand-drawn component or connection has no ingestion
        # evidence behind it at all -- it exists because the owner asserted
        # it, same as a stated property above. This never changes the
        # likelihood level (a manual element is otherwise scored exactly
        # like an ingested one, same as before this tagging existed); it
        # only makes the assertion visible in the "why" trail.
        if (
            threat.element_kind == "component"
            and (element := element_by_id.get(threat.element_id)) is not None
            and element.is_manual
        ):
            factors.append("owner states: this component was added by hand, not found in any ingested source")
        elif (
            threat.element_kind == "flow"
            and (flow_ := flow_by_id.get(threat.element_id)) is not None
            and flow_.is_manual
        ):
            factors.append("owner states: this connection was drawn by hand, not found in any ingested source")

        if threat.element_kind == "component":
            exposed = threat.element_id in exposed_ids
            exposure_asserted = _exposure_is_asserted(element_by_id.get(threat.element_id))
        elif threat.element_kind == "flow":
            ends = flow_ends.get(threat.element_id, ())
            exposed = any(end in exposed_ids for end in ends)
            exposure_asserted = any(_exposure_is_asserted(element_by_id.get(end)) for end in ends)
        else:
            exposed = False
            exposure_asserted = False

        full_control, partial_control = _control_coverage(threat, element_by_id, flow_by_id, incoming_by_target)

        likely = LIKELIHOOD_ORDER.index("likely")
        if exposed and not full_control:
            level = max(level, likely)
            if exposure_asserted:
                factors.append("owner states: exposed (trust boundary set by hand, not derived from evidence)")
            else:
                factors.append("exposed: directly reachable from an untrusted caller")
        elif exposed and full_control:
            factors.append("exposed, but a stated control covers every entry path (not counted toward likelihood)")
        if full_control:
            factors.append(f"control in place: {full_control}")
        elif partial_control:
            factors.append(f"partially mitigated: {partial_control}")

        evidence: list[ThreatEvidence] = []
        supporting: list[Finding] = []
        if threat.methodology == "STRIDE" and threat.category:
            if threat.element_kind == "component":
                candidate_ids = [threat.element_id]
            elif threat.element_kind == "flow":
                # Evidence on either endpoint supports the flow threat too --
                # a data store with a confirmed information-disclosure finding
                # is evidence for a flow into it, not just for the store's own
                # threat.
                candidate_ids = list(flow_ends.get(threat.element_id, ()))
            else:
                candidate_ids = []
            seen_ids: set[str] = set()
            for candidate_id in candidate_ids:
                for finding in on_component.get(candidate_id, []):
                    if finding.evidence.stride_category == threat.category and finding.id not in seen_ids:
                        supporting.append(finding)
                        seen_ids.add(finding.id)
        if supporting:
            worst = _worst(supporting)
            if worst >= _SEVERITY_RANK["medium"]:
                level = max(level, likely)
            if worst >= _SEVERITY_RANK["high"] and exposed:
                level = _step(level)
            exploited = [f for f in supporting if f.evidence.known_exploited]
            high_epss = [f for f in supporting if (f.evidence.epss_score or 0) >= _EPSS_ALMOST_CERTAIN_THRESHOLD]
            if exposed and (exploited or high_epss):
                level = _step(level)
                if exploited:
                    factors.append(
                        f"{len(exploited)} supporting finding(s) are known to be actively exploited (CISA KEV)"
                    )
                if high_epss:
                    top_epss = max(f.evidence.epss_score for f in high_epss if f.evidence.epss_score is not None)
                    factors.append(f"exploitation probability (EPSS) as high as {top_epss:.0%} on a supporting finding")
            scope_note = "on this component" if threat.element_kind == "component" else "on an endpoint of this flow"
            factors.append(f"{len(supporting)} open finding(s) {scope_note} confirm the weakness")
            evidence += _evidence(supporting, "component")

        repo_supporting: list[Finding] = []
        if threat.rule_id in REPOSITORY_EVIDENCE_RULES and threat.element_kind == "component":
            fact = fact_by_id.get(threat.element_id)
            repo = fact.attributes.get("source_repo") if fact else None
            repo_supporting = repo_vulns.get(str(repo), []) if repo else []
        if repo_supporting:
            if _worst(repo_supporting) >= _SEVERITY_RANK["high"]:
                level = max(level, likely)
            factors.append(
                f"{len(repo_supporting)} open dependency vulnerabilities in its source repository "
                "(not confirmed to be present in this component's image)"
            )
            evidence += _evidence(repo_supporting, "repository")

        # Asset sensitivity as an impact input: a `data_classification` tag on the threat's own
        # element (component) or flow raises impact, not likelihood, so this
        # goes on `risk_factors` (already rendered by the UI), not `factors`
        # (-> likelihood_factors) above.
        risk_factors = list(threat.risk_factors)
        severity = threat.severity
        if threat.element_kind == "component":
            sensitive_el = element_by_id.get(threat.element_id)
            sensitive = bool(sensitive_el and sensitive_el.properties.get("data_classification"))
        elif threat.element_kind == "flow":
            sensitive_fl = flow_by_id.get(threat.element_id)
            sensitive = bool(sensitive_fl and sensitive_fl.properties.get("data_classification"))
        else:
            sensitive = False
        if sensitive:
            bumped = _bump_severity(severity)
            if bumped != severity:
                risk_factors.append("owner states: this element's data classification raises its impact by one level")
                severity = bumped

        evidence.sort(key=lambda e: (-_SEVERITY_RANK.get(e.severity, 0), e.scope, e.title))
        likelihood: Likelihood = LIKELIHOOD_ORDER[level]
        assessed.append(
            threat.model_copy(
                update={
                    "likelihood": likelihood,
                    "likelihood_factors": factors,
                    "evidence": evidence[:EVIDENCE_LIMIT],
                    "evidence_total": len(evidence),
                    "severity": severity,
                    "risk_factors": risk_factors,
                }
            )
        )
    return assessed
