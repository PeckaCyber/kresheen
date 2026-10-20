"""Pivots the open threats into a deduplicated, ranked list of fixes.

Identity: a mitigation's text with the element name swapped back to a
placeholder, lower-cased. 21 of the built-in rules put the element name in the
text ("Restrict who can reach {name}"), and matching on the filled text would
split one fix into a row per element. The id is a hash of that normalised
text, so it is stable across runs and survives re-scans, like a threat key.
Pure: nothing here is persisted except the user's per-action status.
"""

from __future__ import annotations

import hashlib
from typing import Literal

from kresheen.models.action_plan import (
    ACTION_STATUSES,
    ActionOut,
    ActionPlanOut,
    ActionPlanSummary,
    ActionStatusRecord,
)
from kresheen.models.threat import ThreatOut
from kresheen.plugins import get_registry

_PLACEHOLDER = "{name}"
_TIER_WEIGHT = {"observed": 3, "specific": 2, "generic": 1}
_TIER_RANK = {"observed": 0, "specific": 1, "generic": 2}
_RISK_ORDER = ["critical", "high", "medium", "low"]  # also the impact order: same scale
_ELEMENT_CAP = 8
_VERIFY_CAP = 4
_FIX_CAP = 2
_CLOSED = ("done", "wont_do")


def _normalise(text: str, element_name: str) -> str:
    return " ".join(text.replace(element_name, _PLACEHOLDER).lower().split())


Tier = Literal["observed", "specific", "generic"]


def _tier(threat: ThreatOut) -> Tier:
    """How much this threat says its fix matters. Deliberately narrower than `Threat.basis`:
    only a config-derived (SC-*) rule is *observed*. A generic rule that merely has a scanner
    finding on the component is `specific`, because the finding raises that threat's likelihood
    but says nothing about whether this particular fix is the right response to it."""
    if threat.rule_id.startswith("SC-"):
        return "observed"
    return "specific" if threat.basis != "generic" else "generic"


def _fix_index(threat: ThreatOut) -> int | None:
    guidance = get_registry().guidance(threat.rule_id, threat.methodology, threat.category)
    return guidance.fix_example_mitigation_index if guidance is not None else None


def ordered_by_tier(threats: list[ThreatOut]) -> list[ThreatOut]:
    return sorted(threats, key=lambda t: _TIER_RANK[_tier(t)])


def action_id_for(normalised: str) -> str:
    return "ACT-" + hashlib.sha256(normalised.encode()).hexdigest()[:10]


def build_action_plan(threats: list[ThreatOut], statuses: dict[str, ActionStatusRecord]) -> ActionPlanOut:
    """`statuses` is keyed by action id. Only *open* threats feed the plan: one
    already mitigated, accepted or not applicable has been dealt with."""
    grouped: dict[str, list[tuple[ThreatOut, str, int]]] = {}
    for threat in threats:
        if threat.status != "open":
            continue
        for index, mitigation in enumerate(threat.mitigations):
            grouped.setdefault(_normalise(mitigation, threat.element_name), []).append((threat, mitigation, index))

    actions: list[ActionOut] = []
    # Not part of ActionOut: only used to order actions of equal risk, so a fix for a threat whose
    # impact was raised by stated sensitive data (critical impact, high risk) outranks a broader one.
    worst_impact: dict[str, int] = {}
    for normalised, members in grouped.items():
        # One threat can list the same fix twice; count it once.
        unique = {threat.key: (threat, text, index) for threat, text, index in members}
        member_threats = [t for t, _, _ in unique.values()]
        # An example fix only belongs beside the mitigation it implements, not every mitigation of the rule.
        matching_fixes = [t for t, _, index in unique.values() if _fix_index(t) == index]
        elements = sorted({t.element_name for t in member_threats}, key=str.lower)
        first_text = next(iter(unique.values()))[1]
        text = (
            first_text
            if len(elements) == 1
            else normalised_display(first_text, member_threats[0].element_name)
        )
        action_id = action_id_for(normalised)
        worst_impact[action_id] = min(_RISK_ORDER.index(t.severity) for t in member_threats)
        record = statuses.get(action_id)
        score = sum(t.risk_score * _TIER_WEIGHT[_tier(t)] for t in member_threats)
        top_risk = max(member_threats, key=lambda t: t.risk_score).risk
        actions.append(
            ActionOut(
                id=action_id,
                text=text,
                score=score,
                max_risk=top_risk,
                basis=min((_tier(t) for t in member_threats), key=lambda b: _TIER_RANK[b]),
                threat_count=len(member_threats),
                element_count=len(elements),
                elements=elements[:_ELEMENT_CAP],
                cwe_refs=sorted({cwe for t in member_threats for cwe in t.cwe_refs}),
                # Observed (config-derived) threats first, so their specific commands lead.
                verification=list(dict.fromkeys(v for t in ordered_by_tier(member_threats) for v in t.verification))[:_VERIFY_CAP],
                fix_examples=list(dict.fromkeys(t.fix_example for t in ordered_by_tier(matching_fixes) if t.fix_example))[:_FIX_CAP],
                threat_keys=sorted(t.key for t in member_threats),
                status=record.status if record else "todo",
                note=record.note if record else "",
                status_updated_at=record.updated_at if record else None,
            )
        )

    # Open before closed; then what was observed in the config, then what is specific to this design,
    # then generic hardening; within a tier, worst risk first, then worst impact, then breadth (score). Tier first on purpose: a broad generic fix
    # spanning many elements would otherwise outrank a single confirmed misconfiguration.
    actions.sort(
        key=lambda a: (
            a.status in _CLOSED,
            _TIER_RANK[a.basis],
            _RISK_ORDER.index(a.max_risk),
            worst_impact[a.id],
            -a.score,
            a.text.lower(),
        )
    )
    by_status: dict[str, int] = {status: 0 for status in ACTION_STATUSES}
    for action in actions:
        by_status[action.status] += 1
    covered = {key for action in actions if action.status not in _CLOSED for key in action.threat_keys}
    return ActionPlanOut(
        actions=actions,
        summary=ActionPlanSummary(total=len(actions), by_status=by_status, open_threats_covered=len(covered)),
    )


def normalised_display(text: str, element_name: str) -> str:
    """Wording for a fix that spans several elements: the element name becomes 'each affected element'."""
    return text.replace(element_name, "each affected element")
