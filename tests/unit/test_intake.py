"""engine/intake.py."""

import itertools
import typing

import pytest

from kresheen.engine.intake import (
    TEMPLATES,
    IntakeAnswers,
    SystemType,
    build_intake_model,
)
from kresheen.engine.threats.methodology import MethodologySpec
from kresheen.engine.threats.properties import PropertySpec, validate_properties
from kresheen.plugins import Plugin, PluginRegistry, set_registry


def _answers(**overrides) -> IntakeAnswers:
    fields = {
        "name": "Shop",
        "system_type": "web_app",
        "users": ["customers"],
        "authentication": "password",
        "data": ["personal"],
        "third_parties": [],
        "has_admin": False,
    }
    fields.update(overrides)
    return IntakeAnswers(**fields)


def _by_name(model):
    return {c.name: c for c in model.components}


def _flow(model, source, target):
    return next(f for f in model.flows if (f.source, f.target) == (source, target))


@pytest.mark.parametrize("system_type", typing.get_args(SystemType))
def test_every_system_type_builds_a_connected_model_with_unique_names(system_type):
    model = build_intake_model(_answers(system_type=system_type, third_parties=["payments", "email"], has_admin=True))

    names = [c.name for c in model.components]
    assert len(names) == len(set(names))
    assert {n for f in model.flows for n in (f.source, f.target)} == set(names)  # nothing orphaned
    assert any(c.type.value == "external_entity" for c in model.components)
    assert any(c.type.value == "data_store" for c in model.components)


def test_every_generated_fact_is_valid_for_its_element_type():
    """The persistence helper writes properties directly, bypassing the API's validation."""
    for system_type, auth, data, admin in itertools.product(
        typing.get_args(SystemType),
        ("none", "password", "sso", "api_keys"),
        ([], ["personal", "health", "payment", "credentials"]),
        (False, True),
    ):
        model = build_intake_model(
            _answers(
                system_type=system_type,
                authentication=auth,
                data=data,
                has_admin=admin,
                users=["public", "customers", "staff", "partners"],
                third_parties=["payments", "email", "identity_provider", "llm_api", "analytics"],
            )
        )
        for c in model.components:
            validate_properties(c.type.value, c.properties)
        for f in model.flows:
            validate_properties("data_flow", f.properties)


def test_authentication_answer_is_stated_on_the_entry_and_backend():
    yes = _by_name(build_intake_model(_answers(authentication="sso")))
    assert yes["Web frontend"].properties["authenticates_callers"] is True
    assert yes["Application server"].properties["authenticates_callers"] is True

    no = _by_name(build_intake_model(_answers(authentication="none")))
    assert no["Application server"].properties["authenticates_callers"] is False


def test_sensitive_data_is_classified_on_the_store_and_its_flows():
    model = build_intake_model(_answers(data=["personal", "payment", "credentials"]))
    db = _by_name(model)["Database"].properties
    assert db["data_classification"] == "PII, PCI, Credentials" and db["stores_credentials"] is True
    assert _flow(model, "Application server", "Database").properties["data_classification"] == "PII, PCI, Credentials"


def test_no_sensitive_data_is_stated_explicitly_rather_than_left_open():
    db = _by_name(build_intake_model(_answers(data=[])))["Database"].properties
    assert db == {"no_sensitive_data": True}


def test_third_parties_and_admin_are_drawn_and_connected():
    model = build_intake_model(_answers(third_parties=["payments"], has_admin=True))
    names = _by_name(model)

    assert names["Payment provider"].boundary == "Third party"
    assert _flow(model, "Application server", "Payment provider").properties == {"data_classification": "PCI"}
    assert {"Administrator", "Admin panel"} <= set(names)
    assert _flow(model, "Admin panel", "Database")
    assert "authenticates_callers" not in names["Admin panel"].properties  # left for completeness to ask


def test_sso_adds_an_identity_provider_even_if_not_listed():
    names = _by_name(build_intake_model(_answers(authentication="sso", third_parties=[])))
    assert "Identity provider" in names


def test_ai_app_marks_ml_components_and_uses_a_hosted_model_only_when_chosen():
    # The AI/ML marker is stated only when a plugin methodology offers that property.
    class AiMethodology(Plugin):
        name = "ai"

        def methodologies(self):
            return [MethodologySpec("Ai", "d", (), properties=(PropertySpec("is_ai_ml_component", "AI", "bool"),))]

    set_registry(PluginRegistry([AiMethodology()]))
    try:
        hosted = _by_name(build_intake_model(_answers(system_type="ai_rag_app", third_parties=["llm_api"])))
        assert hosted["Vector database"].properties["is_ai_ml_component"] is True
        assert "LLM provider API" in hosted and "Model server" not in hosted

        local = _by_name(build_intake_model(_answers(system_type="ai_rag_app", third_parties=[])))
        assert local["Model server"].properties["is_ai_ml_component"] is True and "LLM provider API" not in local
    finally:
        set_registry(PluginRegistry())


def test_ai_app_without_a_plugin_states_no_ml_marker_but_keeps_the_components():
    set_registry(PluginRegistry())
    local = _by_name(build_intake_model(_answers(system_type="ai_rag_app", third_parties=[])))
    assert "is_ai_ml_component" not in local["Model server"].properties
    assert "is_ai_ml_component" not in local["Vector database"].properties


def test_users_are_placed_outside_the_system_and_duplicates_are_ignored():
    answers = _answers(users=["public", "public", "staff"])
    assert answers.users == ["public", "staff"]
    names = _by_name(build_intake_model(answers))
    assert names["Anonymous visitor"].boundary == "Internet" and names["Staff member"].boundary == "Corporate network"


def test_needs_at_least_one_user_group_and_a_name():
    with pytest.raises(ValueError):
        _answers(users=[])
    with pytest.raises(ValueError):
        _answers(name="")


def test_every_template_is_valid_answers_and_builds_a_model():
    assert len(TEMPLATES) >= 5
    for template in TEMPLATES:
        model = build_intake_model(IntakeAnswers(name=template.title, **template.answers))
        assert model.components and model.flows, template.id
