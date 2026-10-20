from kresheen.engine.attack_paths import find_attack_paths
from kresheen.engine.threats.generate import DfdElement, DfdFlow


def _by_target(paths, name):
    return next(p for p in paths if p.target_name == name)


def test_finds_a_shortest_path_from_external_entity_to_a_data_store():
    entity = DfdElement("e", "Customer", "external_entity")
    web = DfdElement("w", "Web", "process")
    db = DfdElement("d", "Orders DB", "data_store")
    flows = [DfdFlow("f1", "e", "w", label="HTTPS"), DfdFlow("f2", "w", "d", label="SQL")]

    paths = find_attack_paths([entity, web, db], flows)

    assert len(paths) == 1
    path = paths[0]
    assert path.source_name == "Customer"
    assert path.target_name == "Orders DB"
    assert path.target_type == "data_store"
    assert path.is_crown_jewel is False
    assert [h.to_name for h in path.hops] == ["Web", "Orders DB"]
    assert path.hops[0].flow_label == "HTTPS"


def test_a_data_classification_tagged_process_is_a_crown_jewel_target():
    entity = DfdElement("e", "Customer", "external_entity")
    cache = DfdElement("c", "Session Cache", "process", properties={"data_classification": "PII"})

    paths = find_attack_paths([entity, cache], [DfdFlow("f1", "e", "c")])

    assert len(paths) == 1
    assert paths[0].target_type == "process"
    assert paths[0].is_crown_jewel is True
    assert "PII" in paths[0].risk_factors[0]


def test_an_authenticated_hop_downgrades_risk_from_critical_to_high():
    entity = DfdElement("e", "Customer", "external_entity")
    db = DfdElement("d", "PII DB", "data_store", properties={"data_classification": "PII"})
    unauth = find_attack_paths([entity, db], [DfdFlow("f", "e", "d")])
    auth = find_attack_paths([entity, db], [DfdFlow("f", "e", "d", properties={"authenticated": True})])

    assert unauth[0].risk == "critical"
    assert auth[0].risk == "high"


def test_plain_data_store_reached_with_no_authentication_is_high_not_critical():
    entity = DfdElement("e", "Customer", "external_entity")
    db = DfdElement("d", "Cache DB", "data_store")

    paths = find_attack_paths([entity, db], [DfdFlow("f", "e", "d")])

    assert paths[0].is_crown_jewel is False
    assert paths[0].risk == "high"


def test_plain_data_store_reached_with_authentication_is_medium():
    entity = DfdElement("e", "Customer", "external_entity")
    db = DfdElement("d", "Cache DB", "data_store")

    paths = find_attack_paths([entity, db], [DfdFlow("f", "e", "d", properties={"authenticated": True})])

    assert paths[0].risk == "medium"


def test_out_of_scope_element_is_excluded_from_traversal():
    entity = DfdElement("e", "Customer", "external_entity")
    gateway = DfdElement("g", "Gateway", "process", properties={"out_of_scope": True})
    db = DfdElement("d", "Orders DB", "data_store")
    flows = [DfdFlow("f1", "e", "g"), DfdFlow("f2", "g", "d")]

    paths = find_attack_paths([entity, gateway, db], flows)

    assert paths == []


def test_out_of_scope_flow_is_excluded_from_traversal():
    entity = DfdElement("e", "Customer", "external_entity")
    db = DfdElement("d", "Orders DB", "data_store")
    flows = [DfdFlow("f1", "e", "d", properties={"out_of_scope": True})]

    assert find_attack_paths([entity, db], flows) == []


def test_no_paths_when_nothing_connects_an_external_entity_to_a_target():
    entity = DfdElement("e", "Customer", "external_entity")
    isolated_db = DfdElement("d", "Backup DB", "data_store")

    assert find_attack_paths([entity, isolated_db], []) == []


def test_each_external_entity_gets_its_own_path_to_the_same_target():
    partner = DfdElement("e1", "Partner", "external_entity")
    customer = DfdElement("e2", "Customer", "external_entity")
    db = DfdElement("d", "Orders DB", "data_store")
    flows = [DfdFlow("f1", "e1", "d"), DfdFlow("f2", "e2", "d")]

    paths = find_attack_paths([partner, customer, db], flows)

    assert {p.source_name for p in paths} == {"Partner", "Customer"}
    assert all(p.target_name == "Orders DB" for p in paths)


def test_boundary_crossings_counted_via_the_shared_crosses_boundary_predicate():
    entity = DfdElement("e", "Customer", "external_entity")
    dmz = DfdElement("w", "Web", "process", trust_boundary="dmz")
    internal = DfdElement("d", "Orders DB", "data_store", trust_boundary="internal")
    flows = [DfdFlow("f1", "e", "w"), DfdFlow("f2", "w", "d")]

    path = find_attack_paths([entity, dmz, internal], flows)[0]

    assert path.boundary_crossings == 2  # entity->dmz (external talking to a boundary) and dmz->internal
    assert "crosses 2 trust boundaries" in path.risk_factors


def test_risk_factor_grammar_is_singular_for_exactly_one_crossing():
    entity = DfdElement("e", "Customer", "external_entity")
    db = DfdElement("d", "Orders DB", "data_store")  # no trust_boundary -> the only crossing is entity-vs-non-entity

    path = find_attack_paths([entity, db], [DfdFlow("f", "e", "d")])[0]

    assert path.boundary_crossings == 1
    assert "crosses 1 trust boundary" in path.risk_factors


def test_paths_sort_worst_first():
    entity = DfdElement("e", "Customer", "external_entity")
    crown_jewel = DfdElement("cj", "PII DB", "data_store", properties={"data_classification": "PII"})
    plain = DfdElement("p", "Cache DB", "data_store")
    flows = [
        DfdFlow("f1", "e", "p", properties={"authenticated": True}),  # medium
        DfdFlow("f2", "e", "cj"),  # critical
    ]

    paths = find_attack_paths([entity, crown_jewel, plain], flows)

    assert [p.risk for p in paths] == ["critical", "medium"]
