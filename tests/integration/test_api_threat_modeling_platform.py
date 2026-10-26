from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

_OWNER_EMAIL = "owner@example.com"
_MEMBER_EMAIL = "member@example.com"
_PASSWORD = "correct-password"  # nosec: test fixture, not a real credential


def _client_and_repo(tmp_path) -> tuple[TestClient, SQLRepository, str]:
    db_url = f"sqlite:///{tmp_path}/test.db"
    repo = SQLRepository(db_url)
    return TestClient(create_app(db_url=db_url)), repo, db_url


def _login(client: TestClient, email: str) -> str:
    return client.post("/api/auth/login", json={"email": email, "password": _PASSWORD}).json()["csrf_token"]


def _owner_client(tmp_path) -> tuple[TestClient, str]:
    client, repo, _ = _client_and_repo(tmp_path)
    repo.save_user(
        User(
            id="USER-owner",
            email=_OWNER_EMAIL,
            password_hash=hash_password(_PASSWORD),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    return client, _login(client, _OWNER_EMAIL)


def _member_client(tmp_path) -> tuple[TestClient, str]:
    client, repo, _ = _client_and_repo(tmp_path)
    repo.save_user(
        User(
            id="USER-member",
            email=_MEMBER_EMAIL,
            password_hash=hash_password(_PASSWORD),
            role="member",
            created_at=datetime.now(UTC),
        )
    )
    return client, _login(client, _MEMBER_EMAIL)


# -- Threat Knowledge Base -----------------------------------------------------


def test_create_and_list_custom_kb_entry(tmp_path):
    client, csrf = _owner_client(tmp_path)

    created = client.post(
        "/api/threat-kb",
        json={"name": "Custom threat", "description": "d", "tags": ["custom-tag"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 200
    assert created.json()["source"] == "custom"

    listed = client.get("/api/threat-kb")
    assert listed.status_code == 200
    assert [e["name"] for e in listed.json()] == ["Custom threat"]


def test_predefined_rules_are_listed_generically_and_require_login(tmp_path):
    from kresheen.engine.threats.config_rules import all_config_rules
    from kresheen.engine.threats.methodology import methodology_rules

    client, _csrf = _owner_client(tmp_path)

    response = client.get("/api/threat-kb/rules")

    assert response.status_code == 200
    rules = response.json()
    assert [r["id"] for r in rules] == [rule.id for rule in methodology_rules()] + [
        rule.id for rule in all_config_rules()
    ]
    tagged = {r["id"]: r["taxonomy_id"] for r in rules if r["taxonomy_id"]}
    assert tagged["SC-T08"] == "T08" and all(r["taxonomy_id"] is None for r in rules[: len(methodology_rules())])
    assert all("{name}" not in r["title"] + r["description"] for r in rules)
    assert all(r["mitigations"] and r["applies_when"] for r in rules)
    assert any("<element>" in r["title"] for r in rules)

    anonymous = TestClient(client.app)
    assert anonymous.get("/api/threat-kb/rules").status_code == 401


def test_curated_feed_entries_are_hidden(tmp_path):
    client, repo, _ = _client_and_repo(tmp_path)
    repo.save_user(
        User(
            id="USER-1",
            email=_OWNER_EMAIL,
            password_hash=hash_password(_PASSWORD),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    _login(client, _OWNER_EMAIL)
    now = datetime.now(UTC)
    from kresheen.models.threat_kb import ThreatKBEntry

    repo.save_kb_entries(
        [
            ThreatKBEntry(
                id="KB-1", source="kresheen_curated", name="Curated", description="d", created_at=now, updated_at=now
            )
        ]
    )

    response = client.get("/api/threat-kb")

    assert response.json() == []


def test_cannot_delete_a_non_custom_entry(tmp_path):
    client, repo, _ = _client_and_repo(tmp_path)
    repo.save_user(
        User(
            id="USER-1",
            email=_OWNER_EMAIL,
            password_hash=hash_password(_PASSWORD),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    csrf = _login(client, _OWNER_EMAIL)
    now = datetime.now(UTC)
    from kresheen.models.threat_kb import ThreatKBEntry

    repo.save_kb_entries(
        [ThreatKBEntry(id="KB-1", source="mitre_attack", name="T1", description="d", created_at=now, updated_at=now)]
    )

    response = client.delete("/api/threat-kb/KB-1", headers={"X-CSRF-Token": csrf})

    assert response.status_code == 403


# -- Constructs -----------------------------------------------------------------


# -- Connectors ------------------------------------------------------------------


# -- Agent config -----------------------------------------------------------------
#
# `default_model` validation asks the provider for the key's live model list. Tests inject a `FakeProvider` through
# `create_app(llm_provider=...)` rather than let anything reach the real network. The routes answer 404 until the
# owner turns the instance switch on, so the helper does that first.


def _ai_owner_client(tmp_path, models: list[str] | None = None) -> tuple[TestClient, str]:
    from kresheen.engine.llm.provider import FakeProvider
    from kresheen.engine.llm.types import ModelInfo

    db_url = f"sqlite:///{tmp_path}/test.db"
    repo = SQLRepository(db_url)
    repo.save_user(
        User(
            id="USER-owner",
            email=_OWNER_EMAIL,
            password_hash=hash_password(_PASSWORD),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    provider = FakeProvider(models=[ModelInfo(m, m) for m in (models or [])])
    client = TestClient(create_app(db_url=db_url, llm_provider=provider))
    csrf = _login(client, _OWNER_EMAIL)
    assert client.put("/api/settings/ai", json={"enabled": True}, headers={"X-CSRF-Token": csrf}).status_code == 200
    return client, csrf


def test_get_agent_config_defaults_when_unset(tmp_path):
    client, _csrf = _ai_owner_client(tmp_path)

    response = client.get("/api/agent-config")

    assert response.status_code == 200
    body = response.json()
    assert body["has_api_key"] is False
    assert body["default_model"] is None


def test_save_agent_config_with_no_model_and_no_key_is_valid(tmp_path):
    """ "None" (rule-based only) is a permanent, valid choice -- no key required."""
    client, csrf = _ai_owner_client(tmp_path)

    response = client.put("/api/agent-config", json={"default_model": None}, headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200
    body = response.json()
    assert body["default_model"] is None
    assert body["has_api_key"] is False


def test_save_agent_config_requires_an_api_key_to_select_a_model(tmp_path):
    client, csrf = _ai_owner_client(tmp_path)

    response = client.put(
        "/api/agent-config", json={"default_model": "claude-haiku-4-5"}, headers={"X-CSRF-Token": csrf}
    )

    assert response.status_code == 422


def test_save_agent_config_roundtrips_and_hides_the_key(tmp_path):
    client, csrf = _ai_owner_client(tmp_path, ["claude-sonnet-4-5"])

    response = client.put(
        "/api/agent-config",
        json={"default_model": "claude-sonnet-4-5", "api_key": "sk-ant-secret"},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["default_model"] == "claude-sonnet-4-5"
    assert body["has_api_key"] is True
    assert "sk-ant-secret" not in response.text


def test_save_agent_config_rejects_unknown_model(tmp_path):
    client, csrf = _ai_owner_client(tmp_path, ["claude-haiku-4-5", "claude-sonnet-4-5"])

    response = client.put(
        "/api/agent-config", json={"default_model": "gpt-4", "api_key": "sk-ant-secret"}, headers={"X-CSRF-Token": csrf}
    )

    assert response.status_code == 422


def test_list_models_returns_empty_list_when_no_key_available(tmp_path):
    client, csrf = _ai_owner_client(tmp_path)

    response = client.post("/api/agent-config/models", json={}, headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200
    assert response.json() == []


def test_list_models_returns_live_list_for_a_freshly_supplied_key(tmp_path):
    client, csrf = _ai_owner_client(tmp_path, ["claude-haiku-4-5", "claude-opus-4-1"])

    response = client.post(
        "/api/agent-config/models", json={"api_key": "sk-ant-not-yet-saved"}, headers={"X-CSRF-Token": csrf}
    )

    assert response.status_code == 200
    assert [m["id"] for m in response.json()] == ["claude-haiku-4-5", "claude-opus-4-1"]


def test_list_models_uses_the_saved_key_when_none_supplied(tmp_path):
    client, csrf = _ai_owner_client(tmp_path, ["claude-sonnet-4-5"])
    client.put(
        "/api/agent-config",
        json={"default_model": "claude-sonnet-4-5", "api_key": "sk-ant-secret"},
        headers={"X-CSRF-Token": csrf},
    )

    response = client.post("/api/agent-config/models", json={}, headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200
    assert [m["id"] for m in response.json()] == ["claude-sonnet-4-5"]


# -- Users ------------------------------------------------------------------------


def test_list_users_requires_owner_role(tmp_path):
    client, csrf = _member_client(tmp_path)
    del csrf

    assert client.get("/api/users").status_code == 403


def test_owner_can_list_users_without_exposing_password_hash(tmp_path):
    client, _csrf = _owner_client(tmp_path)

    response = client.get("/api/users")

    assert response.status_code == 200
    assert response.json()[0]["email"] == _OWNER_EMAIL
    assert "password_hash" not in response.json()[0]
