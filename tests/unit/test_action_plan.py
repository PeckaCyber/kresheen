"""engine/action_plan.py."""

from datetime import UTC, datetime

from kresheen.engine.action_plan import action_id_for, build_action_plan
from kresheen.models.action_plan import ActionStatusRecord
from kresheen.models.threat import ThreatOut


def _threat(key, element, mitigations, *, severity="high", likelihood="likely", status="open", rule_id="PROC-S-01", **kw):
    return ThreatOut(
        key=key, rule_id=rule_id, element_kind="component", element_id=key, element_name=element,
        element_type="process", title="t", description="d", severity=severity, likelihood=likelihood,
        mitigations=mitigations, status=status, **kw,
    )


def test_the_same_fix_on_several_elements_is_one_action_with_name_swapped_out():
    threats = [
        _threat("a", "API", ["Restrict who can reach API to known callers."]),
        _threat("b", "Worker", ["Restrict who can reach Worker to known callers."]),
    ]
    plan = build_action_plan(threats, {})

    assert len(plan.actions) == 1
    action = plan.actions[0]
    assert action.threat_count == 2 and action.element_count == 2 and action.elements == ["API", "Worker"]
    assert action.text == "Restrict who can reach each affected element to known callers."


def test_a_single_element_action_keeps_the_specific_wording():
    plan = build_action_plan([_threat("a", "API", ["Restrict who can reach API."])], {})
    assert plan.actions[0].text == "Restrict who can reach API."


def test_only_open_threats_feed_the_plan():
    threats = [
        _threat("a", "API", ["Fix one."], status="mitigated"),
        _threat("b", "API", ["Fix two."], status="accepted"),
        _threat("c", "API", ["Fix three."]),
    ]
    plan = build_action_plan(threats, {})
    assert [a.text for a in plan.actions] == ["Fix three."]


def test_a_duplicate_mitigation_on_one_threat_counts_once():
    plan = build_action_plan([_threat("a", "API", ["Fix it.", "Fix it."])], {})
    assert plan.actions[0].threat_count == 1


def test_config_observed_fixes_rank_before_specific_before_generic():
    generic = _threat("g", "A", ["Generic advice."])
    specific = _threat("s", "B", ["Specific advice."], risk_factors=["crosses a trust boundary"])
    observed = _threat("o", "C", ["Config advice."], rule_id="SC-T01")
    plan = build_action_plan([generic, specific, observed], {})

    assert [(a.text, a.basis) for a in plan.actions] == [
        ("Config advice.", "observed"), ("Specific advice.", "specific"), ("Generic advice.", "generic"),
    ]


def test_a_broad_generic_fix_does_not_outrank_one_observed_misconfiguration():
    generics = [_threat(f"g{i}", f"E{i}", [f"Restrict who can reach E{i}."]) for i in range(8)]
    observed = _threat("o", "B", ["Fix the config."], rule_id="SC-T01", severity="low", likelihood="very_rare")
    plan = build_action_plan([*generics, observed], {})
    assert plan.actions[0].text == "Fix the config."


def test_a_scanner_finding_alone_does_not_make_generic_advice_observed():
    with_evidence = _threat("e", "A", ["Validate input."], evidence_total=2)
    action = build_action_plan([with_evidence], {}).actions[0]
    assert action.basis == "specific"  # backed by a finding, but not a config-derived rule


def test_status_overlay_and_closed_actions_sink_below_open_ones():
    threats = [_threat("a", "API", ["Big fix."], severity="critical"), _threat("b", "API", ["Small fix."], severity="low")]
    big_id = action_id_for("big fix.")
    record = ActionStatusRecord(
        id="AS-1", application_id="APP", action_id=big_id, status="done", note="shipped", updated_at=datetime.now(UTC),
    )
    plan = build_action_plan(threats, {big_id: record})

    assert [a.text for a in plan.actions] == ["Small fix.", "Big fix."]
    assert plan.actions[1].status == "done" and plan.actions[1].note == "shipped"
    assert plan.summary.by_status == {"todo": 1, "in_progress": 0, "done": 1, "wont_do": 0}
    assert plan.summary.open_threats_covered == 1


def test_action_ids_are_stable_and_text_specific():
    assert action_id_for("fix it.") == action_id_for("fix it.")
    assert action_id_for("fix it.") != action_id_for("fix that.")


def test_within_a_tier_the_worse_risk_comes_first_even_if_a_milder_fix_is_broader():
    broad_mild = [
        _threat(f"m{i}", f"E{i}", ["Mild broad fix."], rule_id="SC-T01", severity="medium", likelihood="possible")
        for i in range(6)
    ]
    narrow_severe = _threat("h", "X", ["Severe narrow fix."], rule_id="SC-T02", severity="high", likelihood="likely")
    plan = build_action_plan([*broad_mild, narrow_severe], {})
    assert [a.text for a in plan.actions][:2] == ["Severe narrow fix.", "Mild broad fix."]


def test_at_equal_risk_a_fix_for_a_critical_impact_threat_outranks_a_broader_one():
    """Stated sensitive data raises a threat's impact to critical without necessarily raising its risk
    above the rest; protecting that data should still come first."""
    broad = [_threat(f"b{i}", f"E{i}", ["Broad hygiene."], severity="high", likelihood="likely") for i in range(6)]
    sensitive = _threat("s", "DB", ["Protect the data."], severity="critical", likelihood="possible")
    assert sensitive.risk == broad[0].risk  # the case this guards: identical risk, different impact

    plan = build_action_plan([*broad, sensitive], {})
    assert [a.text for a in plan.actions][:2] == ["Protect the data.", "Broad hygiene."]


