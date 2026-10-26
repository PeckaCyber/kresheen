"""Owner-stated element properties: validation, the rules that read them, and
the promise that an element with no properties gets exactly today's threats."""

import pytest

from kresheen.engine.threats.catalog import ASSERTED_RULES, RULES
from kresheen.engine.threats.generate import DfdElement, DfdFlow, generate_threats
from kresheen.engine.threats.properties import (
    InvalidPropertiesError,
    is_out_of_scope,
    property_specs,
    validate_properties,
)
from kresheen.engine.threats.risk import assess_threats

_PROPERTY_RULE_IDS = {rule.id for rule in RULES if rule.when}


def _rule_ids(threats):
    return {t.rule_id for t in threats}


def _model(*, process=None, store=None, flow=None):
    elements = [
        DfdElement("p", "API", "process", properties=process or {}),
        DfdElement("d", "DB", "data_store", properties=store or {}),
    ]
    return elements, [DfdFlow("f", "p", "d", properties=flow or {})]


def test_property_rules_are_declared_and_map_to_an_asserted_fact():
    assert _PROPERTY_RULE_IDS == set(ASSERTED_RULES) and len(_PROPERTY_RULE_IDS) == 8
    assert all(ASSERTED_RULES[rule_id] for rule_id in _PROPERTY_RULE_IDS)


def test_no_properties_means_no_property_rule_fires():
    elements, flows = _model()

    assert not _rule_ids(generate_threats(elements, flows)) & _PROPERTY_RULE_IDS


@pytest.mark.parametrize(
    ("where", "properties", "rule_id"),
    [
        ("process", {"authenticates_callers": False}, "PROC-P-01"),
        ("process", {"runs_privileged": True}, "PROC-P-02"),
        ("process", {"is_web_application": True}, "PROC-P-03"),
        ("store", {"is_encrypted": False}, "STORE-P-01"),
        ("store", {"stores_credentials": True}, "STORE-P-02"),
        ("store", {"is_a_log": True, "is_signed": False}, "STORE-P-03"),
        ("flow", {"is_encrypted": False}, "FLOW-P-01"),
        ("flow", {"authenticated": False}, "FLOW-P-02"),
    ],
)
def test_each_rule_fires_only_on_its_explicit_value(where, properties, rule_id):
    elements, flows = _model(**{where: properties})
    assert rule_id in _rule_ids(generate_threats(elements, flows))

    # The opposite value, and the property being unknown, both leave it out.
    opposite = {key: (not value if isinstance(value, bool) else value) for key, value in properties.items()}
    for other in (opposite, {}):
        elements, flows = _model(**{where: other})
        assert rule_id not in _rule_ids(generate_threats(elements, flows))


def test_a_log_needs_both_properties_to_fire():
    elements, flows = _model(store={"is_a_log": True})
    assert "STORE-P-03" not in _rule_ids(generate_threats(elements, flows))
    elements, flows = _model(store={"is_signed": False})
    assert "STORE-P-03" not in _rule_ids(generate_threats(elements, flows))


def test_property_rules_are_additive_generic_threats_are_unchanged():
    plain = generate_threats(*_model())
    stated = generate_threats(*_model(store={"is_encrypted": False}, flow={"is_encrypted": False}))

    assert {t.key for t in plain} < {t.key for t in stated}
    assert {t.key for t in stated} - {t.key for t in plain} == {"STORE-P-01|data_store:DB", "FLOW-P-01|flow:API->DB"}


def test_owner_states_is_a_risk_factor_and_public_network_adds_another():
    elements, flows = _model(flow={"is_encrypted": False, "crosses_public_network": True})

    threat = next(t for t in generate_threats(elements, flows) if t.rule_id == "FLOW-P-01")

    assert threat.risk_factors == ["owner states: not encrypted in transit", "crosses a public network"]


def test_owner_stated_weakness_is_likely_never_almost_certain():
    elements, flows = _model(store={"is_encrypted": False})
    threats = generate_threats(elements, flows)

    assessed = {
        t.rule_id: t for t in assess_threats(threats, elements=elements, flows=flows, findings=[], fact_nodes=[])
    }

    stated = assessed["STORE-P-01"]
    assert stated.likelihood == "likely"
    assert "owner states: not encrypted at rest" in stated.likelihood_factors
    assert assessed["STORE-T-01"].likelihood == "possible"  # generic rules are untouched


def test_validate_properties_accepts_known_keys_and_cleans_text():
    cleaned = validate_properties(
        "data_flow", {"protocol": "  HTTPS ", "is_encrypted": True, "out_of_scope_reason": "  "}
    )

    assert cleaned == {"protocol": "HTTPS", "is_encrypted": True}


@pytest.mark.parametrize(
    ("element_type", "properties"),
    [
        ("process", {"is_encrypted": True}),  # a store property on a process
        ("data_store", {"is_encrypted": "yes"}),  # wrong type
        ("data_flow", {"protocol": True}),
        ("data_flow", {"protocol": "x" * 501}),
        ("trust_boundary", {}),
    ],
)
def test_validate_properties_rejects_unknown_keys_wrong_types_and_element_types(element_type, properties):
    with pytest.raises(InvalidPropertiesError):
        validate_properties(element_type, properties)


def test_every_element_type_can_be_marked_out_of_scope():
    for element_type in ("process", "data_store", "external_entity", "data_flow"):
        keys = {spec.key for spec in property_specs()[element_type]}
        assert {"out_of_scope", "out_of_scope_reason"} <= keys
    assert is_out_of_scope({"out_of_scope": True}) and not is_out_of_scope({"out_of_scope": False})
    assert not is_out_of_scope({})
