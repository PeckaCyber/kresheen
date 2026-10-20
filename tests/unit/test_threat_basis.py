"""Threat.basis and its tie-break in the ranking."""

from kresheen.engine.threats.generate import DfdElement, DfdFlow, generate_threats, sort_threats
from kresheen.models.threat import Threat


def _threat(**overrides) -> Threat:
    fields = {
        "key": "k", "rule_id": "PROC-S-01", "element_kind": "component", "element_id": "1", "element_name": "API",
        "element_type": "process", "title": "t", "description": "d", "severity": "high", "mitigations": ["m"],
    }
    fields.update(overrides)
    return Threat(**fields)


def test_config_derived_rules_are_observed():
    assert _threat(rule_id="SC-T08").basis == "observed"
    assert _threat(rule_id="SC-AWS-03").basis == "observed"


def test_a_supporting_finding_makes_any_threat_observed():
    assert _threat(evidence_total=2).basis == "observed"


def test_a_fact_that_triggered_the_rule_makes_it_specific():
    assert _threat(risk_factors=["crosses a trust boundary"]).basis == "specific"
    assert _threat(origin="manual").basis == "specific"


def test_a_plain_per_element_rule_is_generic():
    assert _threat().basis == "generic"


def test_at_equal_risk_observed_then_specific_then_generic_but_risk_still_wins():
    generic = _threat(key="g", rule_id="PROC-S-01", element_name="A")
    specific = _threat(key="s", rule_id="PROC-S-02", risk_factors=["x"], element_name="B")
    observed = _threat(key="o", rule_id="SC-T01", element_name="C")
    assert [t.key for t in sort_threats([generic, specific, observed])] == ["o", "s", "g"]

    lower_risk_observed = _threat(key="lo", rule_id="SC-T02", severity="low", element_name="D")
    assert sort_threats([lower_risk_observed, generic])[0].key == "g"


def test_generated_threats_carry_a_basis_and_flow_boundary_crossings_are_specific():
    elements = [
        DfdElement("e", "User", "external_entity", trust_boundary="internet"),
        DfdElement("p", "API", "process", trust_boundary="app"),
    ]
    threats = generate_threats(elements, [DfdFlow("f", "e", "p")])
    bases = {t.basis for t in threats}
    assert "generic" in bases and "specific" in bases
