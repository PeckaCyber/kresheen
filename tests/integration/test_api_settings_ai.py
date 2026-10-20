"""Instance AI switch: default off, owner-only, env override, capabilities, gated agent-config routes, audit."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.engine.llm.provider import FakeProvider
from kresheen.engine.llm.types import ModelInfo
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

_PASSWORD = "correct-password"  # nosec: test fixture, not a real credential


@pytest.fixture(autouse=True)
def _ai_not_forced_off(monkeypatch):
    monkeypatch.delenv("KRESHEEN_AI_DISABLED", raising=False)


def _app(tmp_path):
    db_url = f"sqlite:///{tmp_path}/test.db"
    repo = SQLRepository(db_url)
    for uid, role in (("USER-owner", "owner"), ("USER-member", "member")):
        repo.save_user(
            User(id=uid, email=f"{role}@example.com", password_hash=hash_password(_PASSWORD), role=role, created_at=datetime.now(UTC))
        )
    provider = FakeProvider(models=[ModelInfo("claude-x", "Claude X")])
    return TestClient(create_app(db_url=db_url, llm_provider=provider)), repo, provider


def _login(client: TestClient, role: str) -> dict[str, str]:
    csrf = client.post("/api/auth/login", json={"email": f"{role}@example.com", "password": _PASSWORD}).json()["csrf_token"]
    return {"X-CSRF-Token": csrf}


def _enable(client, headers):
    return client.put("/api/settings/ai", json={"enabled": True}, headers=headers)


def test_default_is_off(tmp_path):
    client, _, _ = _app(tmp_path)
    headers = _login(client, "owner")
    assert client.get("/api/settings/ai").json() == {"enabled": False, "forced_off": False}
    assert client.get("/api/capabilities").json()["ai"] == {"enabled": False, "experimental": True}
    assert headers


def test_owner_toggles_and_capabilities_follow(tmp_path):
    client, _, _ = _app(tmp_path)
    headers = _login(client, "owner")

    assert _enable(client, headers).json() == {"enabled": True, "forced_off": False}
    assert client.get("/api/settings/ai").json()["enabled"] is True
    assert client.get("/api/capabilities").json()["ai"] == {"enabled": True, "experimental": True}

    assert client.put("/api/settings/ai", json={"enabled": False}, headers=headers).json()["enabled"] is False
    assert client.get("/api/capabilities").json()["ai"]["enabled"] is False


def test_member_cannot_read_or_change(tmp_path):
    client, _, _ = _app(tmp_path)
    headers = _login(client, "member")
    assert client.get("/api/settings/ai").status_code == 403
    assert _enable(client, headers).status_code == 403


def test_put_needs_csrf_and_login(tmp_path):
    client, _, _ = _app(tmp_path)
    assert client.put("/api/settings/ai", json={"enabled": True}).status_code == 401
    _login(client, "owner")
    assert client.put("/api/settings/ai", json={"enabled": True}).status_code == 403


def test_forced_off_env_wins(tmp_path, monkeypatch):
    client, repo, _ = _app(tmp_path)
    headers = _login(client, "owner")
    assert _enable(client, headers).status_code == 200

    monkeypatch.setenv("KRESHEEN_AI_DISABLED", "1")
    assert client.get("/api/settings/ai").json() == {"enabled": False, "forced_off": True}
    assert client.get("/api/capabilities").json()["ai"]["enabled"] is False
    assert _enable(client, headers).status_code == 409
    assert client.get("/api/agent-config").status_code == 404
    assert repo.get_instance_setting("ai_enabled") is True  # the stored choice is kept


def test_agent_config_routes_are_404_when_off_and_work_when_on(tmp_path):
    client, _, _ = _app(tmp_path)
    headers = _login(client, "owner")
    assert client.get("/api/agent-config").status_code == 404
    assert client.post("/api/agent-config/models", json={}, headers=headers).status_code == 404
    assert client.put("/api/agent-config", json={}, headers=headers).status_code == 404
    assert client.delete("/api/agent-config/key", headers=headers).status_code == 404

    _enable(client, headers)
    assert client.get("/api/agent-config").status_code == 200


def test_saving_a_key_without_secret_key_env_is_a_clear_400(tmp_path, monkeypatch):
    client, _, provider = _app(tmp_path)
    headers = _login(client, "owner")
    _enable(client, headers)
    monkeypatch.delenv("KRESHEEN_SECRET_KEY", raising=False)

    response = client.put("/api/agent-config", json={"api_key": "sk-ant-x"}, headers=headers)

    assert response.status_code == 400
    assert "KRESHEEN_SECRET_KEY" in response.json()["detail"]
    assert provider.model_list_calls == []


def test_key_events_are_audited_without_the_key(tmp_path):
    client, repo, _ = _app(tmp_path)
    headers = _login(client, "owner")
    _enable(client, headers)

    saved = client.put("/api/agent-config", json={"api_key": "sk-ant-secret", "default_model": "claude-x"}, headers=headers)
    assert saved.json()["has_api_key"] is True
    removed = client.delete("/api/agent-config/key", headers=headers)
    assert removed.json() == {"default_model": None, "has_api_key": False, "workspace_id": None}

    events = repo.list_audit_events(limit=100)
    actions = [e.action for e in events]
    assert "ai.instance_toggled" in actions
    assert "ai.key_added" in actions
    assert "ai.key_removed" in actions
    assert "sk-ant-secret" not in "".join(e.model_dump_json() for e in events)
    toggled = next(e for e in events if e.action == "ai.instance_toggled")
    assert toggled.user_email == "owner@example.com" and toggled.subject == {"enabled": "true"}


def test_replacing_a_key_deletes_the_old_ciphertext(tmp_path):
    client, repo, _ = _app(tmp_path)
    headers = _login(client, "owner")
    _enable(client, headers)
    client.put("/api/agent-config", json={"api_key": "sk-ant-one"}, headers=headers)
    first = repo.get_agent_config("user", "USER-owner").api_key_ref
    client.put("/api/agent-config", json={"api_key": "sk-ant-two"}, headers=headers)
    assert repo.get_secret_blob(first) is None


def test_workspace_id_is_saved_returned_and_used_for_model_lists(tmp_path):
    client, repo, provider = _app(tmp_path)
    headers = _login(client, "owner")
    _enable(client, headers)
    tested = client.post("/api/agent-config/models", json={"api_key": "sk-ant-x", "workspace_id": "wrkspc_01ab"}, headers=headers)
    assert tested.status_code == 200 and provider.model_list_workspaces[-1] == "wrkspc_01ab"
    saved = client.put(
        "/api/agent-config",
        json={"api_key": "sk-ant-x", "default_model": "claude-x", "workspace_id": " wrkspc_01ab "},
        headers=headers,
    )
    assert saved.status_code == 200 and saved.json()["workspace_id"] == "wrkspc_01ab"
    assert provider.model_list_workspaces[-1] == "wrkspc_01ab"  # the model check on save uses it too
    assert client.get("/api/agent-config").json()["workspace_id"] == "wrkspc_01ab"
    assert repo.get_agent_config("user", "USER-owner").workspace_id == "wrkspc_01ab"
    cleared = client.put("/api/agent-config", json={"default_model": "claude-x", "workspace_id": ""}, headers=headers)
    assert cleared.json()["workspace_id"] is None


@pytest.mark.parametrize("bad", ["wrkspc 1", "wrkspc_1\r\nX-Evil: 1", "x" * 101])
def test_workspace_id_must_be_a_plain_id(tmp_path, bad):
    client, _, _ = _app(tmp_path)
    headers = _login(client, "owner")
    _enable(client, headers)
    response = client.put("/api/agent-config", json={"api_key": "sk-ant-x", "workspace_id": bad}, headers=headers)
    assert response.status_code == 422


def test_a_key_without_a_workspace_gets_a_422_that_says_what_to_do(tmp_path):
    client, _, provider = _app(tmp_path)
    headers = _login(client, "owner")
    _enable(client, headers)
    from kresheen.engine.llm.provider import provider_error

    provider.error = provider_error("workspace")
    response = client.post("/api/agent-config/models", json={"api_key": "sk-ant-x"}, headers=headers)
    assert response.status_code == 422 and "workspace ID" in response.json()["detail"]
