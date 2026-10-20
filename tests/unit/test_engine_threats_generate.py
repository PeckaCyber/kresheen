import pytest

from kresheen.engine.threats.catalog import RULES, RULES_BY_ID, ThreatRule
from kresheen.engine.threats.cia import cia_impacts_for
from kresheen.engine.threats.generate import (
    DfdElement,
    DfdFlow,
    generate_threats,
    is_untrusted_boundary,
)
from kresheen.engine.threats.methodology import (
    MethodologySpec,
    available_methodologies,
    methodology_rules,
)
from kresheen.plugins import Plugin, PluginRegistry, set_registry


def _by_rule(threats):
    return {t.rule_id: t for t in threats}


def test_every_rule_has_mitigations_and_a_valid_shape():
    assert len(RULES_BY_ID) == len(RULES)
    for rule in RULES:
        assert rule.mitigations, rule.id
        assert rule.cwe, rule.id
        assert rule.attack, rule.id


def test_stride_per_element_matrix():
    elements = [
        DfdElement("p", "API", "process"),
        DfdElement("d", "DB", "data_store"),
        DfdElement("e", "Vendor", "external_entity"),
    ]
    flows = [DfdFlow("f", "p", "d")]

    threats = generate_threats(elements, flows)

    def strides(kind_name):
        return {t.category for t in threats if t.element_name == kind_name}

    assert strides("API") == {
        "Spoofing", "Tampering", "Repudiation", "InformationDisclosure", "DenialOfService", "ElevationOfPrivilege",
    }
    assert strides("DB") == {"Tampering", "Repudiation", "InformationDisclosure", "DenialOfService"}
    assert {"Spoofing", "Repudiation"} <= strides("Vendor")
    assert strides("API -> DB") == {"Tampering", "InformationDisclosure", "DenialOfService"}


def test_untrusted_facing_rules_only_fire_for_untrusted_boundaries():
    plain = generate_threats([DfdElement("p", "API", "process", "internal")], [])
    exposed = generate_threats([DfdElement("p", "API", "process", "Internet-facing")], [])

    assert "PROC-E-02" not in _by_rule(plain)
    assert "PROC-E-02" in _by_rule(exposed)
    assert _by_rule(exposed)["PROC-E-02"].risk_factors == ["in untrusted-facing boundary 'Internet-facing'"]


def test_data_store_in_untrusted_boundary_is_critical():
    threats = generate_threats([DfdElement("d", "Users DB", "data_store", "public subnet")], [])

    assert _by_rule(threats)["STORE-I-02"].severity == "critical"
    assert threats[0].severity == "critical"  # sorted most severe first


def test_boundary_crossing_rules_need_two_different_labeled_boundaries():
    a = DfdElement("a", "Web", "process", "dmz")
    b = DfdElement("b", "DB", "process", "internal")
    same = DfdElement("c", "Cache", "process", "internal")
    unlabeled = DfdElement("d", "Worker", "process", None)

    crossing = generate_threats([a, b], [DfdFlow("f", "a", "b")])
    within = generate_threats([b, same], [DfdFlow("f", "b", "c")])
    unassigned = generate_threats([b, unlabeled], [DfdFlow("f", "b", "d")])

    assert {"FLOW-T-02", "FLOW-I-02"} <= set(_by_rule(crossing))
    assert "FLOW-T-02" not in _by_rule(within)
    assert "FLOW-T-02" not in _by_rule(unassigned)


def test_flow_between_external_entity_and_internal_component_crosses_boundary():
    threats = generate_threats(
        [DfdElement("e", "Customer", "external_entity"), DfdElement("p", "Web", "process")],
        [DfdFlow("f", "e", "p")],
    )

    assert "FLOW-T-02" in _by_rule(threats)


def test_flow_with_missing_endpoint_is_skipped():
    threats = generate_threats([DfdElement("p", "API", "process")], [DfdFlow("f", "p", "gone")])

    assert not [t for t in threats if t.element_kind == "flow"]


def test_keys_are_name_based_and_stable_across_ephemeral_ids():
    run_1 = generate_threats(
        [DfdElement("FACT-N-1", "API", "process"), DfdElement("FACT-N-2", "DB", "data_store")],
        [DfdFlow("FACT-E-1", "FACT-N-1", "FACT-N-2")],
    )
    run_2 = generate_threats(
        [DfdElement("FACT-N-9", "API", "process"), DfdElement("FACT-N-8", "DB", "data_store")],
        [DfdFlow("FACT-E-7", "FACT-N-9", "FACT-N-8")],
    )

    assert {t.key for t in run_1} == {t.key for t in run_2}
    assert "PROC-S-01|process:API" in {t.key for t in run_1}
    assert "FLOW-T-01|flow:API->DB" in {t.key for t in run_1}


def test_duplicate_names_collapse_to_one_threat_per_key():
    threats = generate_threats(
        [DfdElement("1", "API", "process"), DfdElement("2", "API", "process")], []
    )

    keys = [t.key for t in threats]
    assert len(keys) == len(set(keys))


def test_name_is_substituted_into_text_and_mitigations():
    threats = generate_threats([DfdElement("e", "Stripe", "external_entity")], [])
    spoof = _by_rule(threats)["EXT-S-01"]

    assert "Stripe" in spoof.title
    assert all("{name}" not in m for m in spoof.mitigations)
    assert any("Stripe" in m for m in spoof.mitigations)


def test_untrusted_boundary_label_matching():
    for label in ("internet-facing", "Public subnet", "DMZ", "third-party", "Untrusted"):
        assert is_untrusted_boundary(label), label
    for label in ("internal", "corporate lan", "", None):
        assert not is_untrusted_boundary(label), label


# -- User-authored rules and manual threats -------------------------------------


def _kb_entry(**overrides):
    from datetime import UTC, datetime

    from kresheen.models.threat_kb import ThreatKBEntry

    now = datetime.now(UTC)
    base = {
        "id": "KB-abc12345", "source": "custom", "name": "Badge cloning at {name}",
        "description": "Cloned badges.", "created_at": now, "updated_at": now,
    }
    return ThreatKBEntry(**{**base, **overrides})


def test_kb_entry_without_applies_to_is_not_a_rule():
    from kresheen.engine.threats.custom import rule_from_kb_entry

    assert rule_from_kb_entry(_kb_entry()) is None
    assert rule_from_kb_entry(_kb_entry(applies_to="process", is_active=False)) is None


def test_custom_rule_generates_on_matching_type_only_with_origin_and_no_stride_required():
    from kresheen.engine.threats.custom import rules_from_kb_entries

    rules = rules_from_kb_entries(
        [_kb_entry(applies_to="data_store", severity="high", mitigations=["Rotate badges."])]
    )
    elements = [DfdElement("p", "API", "process"), DfdElement("d", "Vault", "data_store")]

    threats = generate_threats(elements, [], extra_rules=rules)
    custom = [t for t in threats if t.origin == "custom_rule"]

    assert [t.element_name for t in custom] == ["Vault"]
    assert custom[0].key == "KB-abc12345|data_store:Vault"
    assert custom[0].title == "Badge cloning at Vault"
    assert custom[0].category is None
    assert custom[0].mitigations == ["Rotate badges."]
    assert all(t.origin == "predefined" for t in threats if t not in custom)


def test_custom_methodology_rule_is_always_on_and_keeps_its_free_text_category():
    from kresheen.engine.threats.custom import rules_from_kb_entries

    rules = rules_from_kb_entries(
        [_kb_entry(applies_to="data_store", methodology="Custom", category="Insider fraud")]
    )
    elements = [DfdElement("d", "Vault", "data_store")]

    # Default methodologies are STRIDE-only; a Custom rule still applies.
    threats = generate_threats(elements, [], extra_rules=rules)
    custom = [t for t in threats if t.origin == "custom_rule"]

    assert [(t.methodology, t.category) for t in custom] == [("Custom", "Insider fraud")]


def test_custom_rule_boundary_hint_filters_components_and_matches_either_flow_endpoint():
    from kresheen.engine.threats.custom import rules_from_kb_entries

    comp_rules = rules_from_kb_entries([_kb_entry(applies_to="process", boundary_hint="PCI")])
    flow_rules = rules_from_kb_entries([_kb_entry(id="KB-flow00001", applies_to="data_flow", boundary_hint="pci")])
    a = DfdElement("a", "Checkout", "process", "PCI zone")
    b = DfdElement("b", "Blog", "process", "corp")
    c = DfdElement("c", "Cache", "process", "corp")

    comp = [t for t in generate_threats([a, b], [], extra_rules=comp_rules) if t.origin == "custom_rule"]
    flows = [
        t.element_name
        for t in generate_threats([a, b, c], [DfdFlow("f1", "a", "b"), DfdFlow("f2", "b", "c")], extra_rules=flow_rules)
        if t.origin == "custom_rule"
    ]

    assert [t.element_name for t in comp] == ["Checkout"]
    assert flows == ["Checkout -> Blog"]  # f2 touches no PCI boundary


def _manual(element_key, **overrides):
    from datetime import UTC, datetime

    from kresheen.models.threat import ManualThreat

    base = {
        "id": "MT-11111111", "application_id": "APP-1", "element_kind": "component", "element_type": "process",
        "element_key": element_key, "element_name": "x", "title": "Insider export",
        "created_at": datetime.now(UTC),
    }
    return ManualThreat(**{**base, **overrides})


def test_manual_threat_resolves_by_name_and_is_skipped_when_element_is_gone():
    from kresheen.engine.threats.generate import apply_manual_threats

    manual = [
        _manual("process:API"),
        _manual("process:Gone", id="MT-22222222"),
        _manual("flow:API->DB", id="MT-33333333", element_kind="flow", element_type="data_flow"),
    ]
    run_1 = ([DfdElement("N1", "API", "process"), DfdElement("N2", "DB", "data_store")], [DfdFlow("E1", "N1", "N2")])
    run_2 = ([DfdElement("N9", "API", "process"), DfdElement("N8", "DB", "data_store")], [DfdFlow("E7", "N9", "N8")])

    first = apply_manual_threats(manual, *run_1)
    second = apply_manual_threats(manual, *run_2)

    assert {t.manual_threat_id for t in first} == {"MT-11111111", "MT-33333333"}
    assert {t.key for t in first} == {t.key for t in second}  # stable across ephemeral ids
    assert {t.element_id for t in second} == {"N9", "E7"}
    assert all(t.origin == "manual" for t in first)
    assert next(t for t in first if t.manual_threat_id == "MT-33333333").element_name == "API -> DB"


# -- Multi-methodology --------------


def test_methodologies_filter_is_a_no_op_at_the_default():
    elements = [DfdElement("p", "API", "process")]
    default = generate_threats(elements, [])
    explicit_stride = generate_threats(elements, [], methodologies={"STRIDE"})
    assert {t.key for t in default} == {t.key for t in explicit_stride}
    assert all(t.methodology == "STRIDE" for t in default)


def _demo_spec() -> MethodologySpec:
    """A stand-in for a plugin methodology; the core knows nothing about which ones exist."""
    gated = ThreatRule(
        id="DEMO-GATED-01", element_type="process", category="Gamma", title="Gated threat on {name}", description="d",
        severity="low", mitigations=("m",), methodology="Demo", when=(("demo_flag", True),), asserted="demo flag set",
    )
    always = ThreatRule(
        id="DEMO-ALWAYS-01", element_type="process", category="Alpha", title="Demo threat on {name}", description="d",
        severity="medium", mitigations=("m",), methodology="Demo",
    )
    from kresheen.engine.threats.properties import PropertySpec

    return MethodologySpec(
        name="Demo", description="A demo methodology.", categories=("Alpha", "Gamma"),
        category_descriptions={"Alpha": "First."}, cia={"Alpha": frozenset({"Availability", "Integrity"})},
        rules=(always, gated), properties=(PropertySpec("demo_flag", "Demo flag", "bool"),),
    )


class _DemoMethodologies(Plugin):
    name = "demo-methodologies"

    def methodologies(self):
        return [_demo_spec()]


@pytest.fixture
def demo_methodology():
    set_registry(PluginRegistry([_DemoMethodologies()]))
    yield
    set_registry(PluginRegistry())


def test_without_a_plugin_the_only_methodology_is_stride():
    set_registry(PluginRegistry())
    assert [m.name for m in available_methodologies()] == ["STRIDE"]
    assert methodology_rules() == RULES
    assert {r.methodology for r in methodology_rules()} == {"STRIDE"}
    # A methodology nobody offers generates nothing, even when asked for.
    assert generate_threats([DfdElement("p", "API", "process")], [], methodologies={"Demo"}) == []


def test_all_builtin_rules_have_a_methodology_and_a_valid_shape():
    for rule in methodology_rules():
        assert rule.mitigations, rule.id
        assert rule.methodology == "STRIDE", rule.id


def test_a_plugin_methodology_generates_only_when_selected(demo_methodology):
    elements = [DfdElement("p", "API", "process")]
    assert [m.name for m in available_methodologies()] == ["STRIDE", "Demo"]

    stride_only = generate_threats(elements, [], methodologies={"STRIDE"})
    assert not any(t.methodology == "Demo" for t in stride_only)

    demo_only = generate_threats(elements, [], methodologies={"Demo"})
    assert [t.rule_id for t in demo_only] == ["DEMO-ALWAYS-01"]  # the gated rule needs the owner's statement
    assert demo_only[0].cia_impacts == ["Integrity", "Availability"]

    both = generate_threats(elements, [], methodologies={"STRIDE", "Demo"})
    assert len(both) == len(stride_only) + 1


def test_a_plugin_methodology_rule_can_read_its_own_property(demo_methodology):
    tagged = DfdElement("p", "API", "process", properties={"demo_flag": True})
    ids = {t.rule_id for t in generate_threats([tagged], [], methodologies={"Demo"})}
    assert ids == {"DEMO-ALWAYS-01", "DEMO-GATED-01"}


def test_a_plugin_cannot_shadow_stride_or_custom():
    class Shadow(Plugin):
        name = "shadow"

        def methodologies(self):
            return [MethodologySpec("STRIDE", "x", ()), MethodologySpec("Custom", "x", ()), _demo_spec(), _demo_spec()]

    set_registry(PluginRegistry([Shadow()]))
    try:
        assert [m.name for m in available_methodologies()] == ["STRIDE", "Demo"]
    finally:
        set_registry(PluginRegistry())


def test_cia_impacts_are_derived_and_never_user_entered():
    elements = [DfdElement("p", "API", "process")]
    threats = generate_threats(elements, [], methodologies={"STRIDE"})
    spoofing = next(t for t in threats if t.category == "Spoofing")
    dos = next(t for t in threats if t.category == "DenialOfService")
    assert set(spoofing.cia_impacts) == {"Confidentiality", "Integrity"}
    assert set(dos.cia_impacts) == {"Availability"}
    # Unrecognized (methodology, category) -> no impacts, not an error.
    assert cia_impacts_for("STRIDE", None) == []
    assert cia_impacts_for("STRIDE", "not a real category") == []
    assert cia_impacts_for("Unoffered", "Alpha") == []
