"""engine/completeness.py."""

from kresheen.engine.completeness import assess_completeness
from kresheen.engine.threats.generate import DfdElement, DfdFlow
from kresheen.models.threat_model_run import SourceResult


def _model(**props):
    web = DfdElement("w", "Web", "process", trust_boundary="dmz", properties=props.get("web", {}))
    db = DfdElement("d", "DB", "data_store", trust_boundary="data", properties=props.get("db", {}))
    user = DfdElement("u", "User", "external_entity", trust_boundary="internet")
    flows = [
        DfdFlow("f1", "u", "w", label=props.get("label", "HTTPS login"), properties=props.get("flow", {})),
        DfdFlow("f2", "w", "d", label="SQL"),
    ]
    return [web, db, user], flows


def _checks(out):
    return {(i.check, i.element_name) for i in out.items}


def test_unstated_facts_become_questions_with_a_score():
    out = assess_completeness(*_model(), [])

    assert _checks(out) >= {
        ("data_classification", "DB"),
        ("encrypted_at_rest", "DB"),
        ("authenticates_callers", "Web"),
        ("encrypted_in_transit", "User -> Web"),
        ("encrypted_in_transit", "Web -> DB"),
    }
    assert out.score == 0 and out.answered == 0 and out.total == 5


def test_answering_raises_the_score_and_removes_the_question():
    web = {"authenticates_callers": True}
    db = {"data_classification": "PHI", "is_encrypted": True}
    out = assess_completeness(*_model(web=web, db=db, flow={"is_encrypted": True}), [])

    assert out.answered == 4 and out.total == 5 and out.score == 80
    assert _checks(out) == {("encrypted_in_transit", "Web -> DB")}


def test_no_sensitive_data_settles_the_classification_question():
    out = assess_completeness(*_model(db={"no_sensitive_data": True}), [])
    assert ("data_classification", "DB") not in _checks(out)


def test_a_flow_label_only_ever_suggests_an_answer():
    out = assess_completeness(*_model(), [])
    https = next(i for i in out.items if i.element_name == "User -> Web")
    assert https.fix and https.fix.suggested_value is True and "HTTPS" in https.fix.suggestion_reason
    plain = next(i for i in out.items if i.element_name == "Web -> DB")
    assert plain.fix and plain.fix.suggested_value is None

    insecure = assess_completeness(*_model(label="plain HTTP"), [])
    assert next(i for i in insecure.items if i.element_name == "User -> Web").fix.suggested_value is False


def test_only_boundary_crossing_flows_and_reachable_processes_are_asked_about():
    a = DfdElement("a", "A", "process", trust_boundary="x")
    b = DfdElement("b", "B", "process", trust_boundary="x")
    out = assess_completeness([a, b], [DfdFlow("f", "a", "b")], [])
    assert not any(i.check == "encrypted_in_transit" for i in out.items)
    assert {(i.check, i.element_name) for i in out.items if i.check == "authenticates_callers"} == {
        ("authenticates_callers", "B")
    }


def test_out_of_scope_elements_are_not_asked_about():
    out = assess_completeness(*_model(db={"out_of_scope": True}), [])
    assert not any(i.element_name == "DB" and i.check != "encrypted_in_transit" for i in out.items)
    assert not any("DB" in i.element_name for i in out.items)


def test_structural_notes_have_no_inline_fix():
    lonely = DfdElement("l", "Lonely", "process")
    other = DfdElement("o", "Other", "process")
    out = assess_completeness([lonely, other], [], [])

    checks = {i.check for i in out.items}
    assert {"no_boundaries", "isolated_component", "no_external_actor"} <= checks
    assert all(i.fix is None for i in out.items)
    assert out.score is None  # nothing askable yet


def test_unanalysed_inputs_are_listed():
    result = SourceResult(data_source_id="DS", type="documentation", status="reference_only", message="Not read.")
    out = assess_completeness([], [], [result])
    assert [i.check for i in out.items] == ["unanalysed_input"] and out.items[0].why == "Not read."


def test_items_are_ordered_by_impact():
    out = assess_completeness(*_model(), [])
    order = {"high": 0, "medium": 1, "low": 2}
    assert [order[i.impact] for i in out.items] == sorted(order[i.impact] for i in out.items)
