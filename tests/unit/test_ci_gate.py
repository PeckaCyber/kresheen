from kresheen.engine.ci_gate import COMMENT_MARKER, GateOptions, evaluate_gate
from kresheen.models.run_diff import (
    BoundaryChangeOut,
    FindingDiffOut,
    FlowDiffOut,
    RunDiffOut,
    ThreatDiffOut,
)


def _diff(**kw) -> RunDiffOut:
    return RunDiffOut(current_run_id="R2", previous_run_id=kw.pop("previous_run_id", "R1"), **kw)


def test_no_baseline_passes_and_says_so():
    result = evaluate_gate(_diff(previous_run_id=None), GateOptions())
    assert result.passed
    assert "baseline" in result.markdown


def test_new_critical_finding_fails_default_gate():
    diff = _diff(new_findings=[FindingDiffOut(title="RCE in x", severity="critical", domain="vulnerability")])
    result = evaluate_gate(diff, GateOptions())
    assert not result.passed
    assert result.violations == ["New critical finding: RCE in x"]


def test_new_high_finding_passes_default_but_fails_at_high():
    diff = _diff(new_findings=[FindingDiffOut(title="t", severity="high", domain="vulnerability")])
    assert evaluate_gate(diff, GateOptions()).passed
    assert not evaluate_gate(diff, GateOptions(fail_on="high")).passed


def test_new_critical_threat_fails():
    diff = _diff(new_threats=[ThreatDiffOut(key="k", title="Spoofing", severity="critical")])
    assert not evaluate_gate(diff, GateOptions()).passed


def test_fail_on_none_disables_severity_gate():
    diff = _diff(new_findings=[FindingDiffOut(title="t", severity="critical", domain="d")])
    assert evaluate_gate(diff, GateOptions(fail_on=None)).passed


def test_new_boundary_crossing_flow_fails_and_can_be_disabled():
    diff = _diff(new_flows=[FlowDiffOut(key="k", source_name="Web", target_name="DB", crosses_boundary=True)])
    assert not evaluate_gate(diff, GateOptions()).passed
    relaxed = evaluate_gate(diff, GateOptions(fail_on_boundary_crossing=False))
    assert relaxed.passed
    assert "Web -> DB" in relaxed.markdown  # still reported


def test_non_crossing_new_flow_passes():
    diff = _diff(new_flows=[FlowDiffOut(key="k", source_name="A", target_name="B")])
    assert evaluate_gate(diff, GateOptions()).passed


def test_markdown_neutralises_mentions_and_markup_in_names():
    diff = _diff(new_findings=[FindingDiffOut(title="@octocat [x](http://e) <b>`z`", severity="critical", domain="d")])
    md = evaluate_gate(diff, GateOptions()).markdown
    assert "@octocat" not in md
    assert "<b>" not in md
    assert COMMENT_MARKER in md


def test_component_moving_trust_boundary_fails_and_can_be_disabled():
    diff = _diff(
        boundary_changes=[
            BoundaryChangeOut(name="Orders DB", type="data_store", from_boundary="internal", to_boundary=None)
        ]
    )
    result = evaluate_gate(diff, GateOptions())
    assert not result.passed
    assert result.violations == ["Component moved trust boundary: Orders DB (internal -> unassigned)"]
    assert evaluate_gate(diff, GateOptions(fail_on_boundary_crossing=False)).passed


def test_diff_boundaries_reports_only_components_present_in_both_runs(monkeypatch):
    from kresheen.engine.diff import diff_boundaries
    from kresheen.engine.threats.generate import DfdElement

    runs = {
        "R1": [
            DfdElement(id="1", name="API", type="process", trust_boundary="dmz"),
            DfdElement(id="2", name="DB", type="data_store", trust_boundary="internal"),
            DfdElement(id="3", name="Gone", type="process", trust_boundary="a"),
        ],
        "R2": [
            DfdElement(id="9", name="API", type="process", trust_boundary="dmz"),
            DfdElement(id="8", name="DB", type="data_store", trust_boundary="public"),
            DfdElement(id="7", name="New", type="process", trust_boundary="b"),
        ],
    }
    monkeypatch.setattr("kresheen.engine.threats.service.load_dfd_model", lambda app, run, repo: (runs[run], []))

    changes = diff_boundaries("APP", "R1", "R2", repo=None)  # type: ignore[arg-type]

    assert [(c.name, c.from_boundary, c.to_boundary) for c in changes] == [("DB", "internal", "public")]
