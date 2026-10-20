from __future__ import annotations

from fastapi.testclient import TestClient

from tests.integration.test_api_applications import _logged_in_client


def _events(client):
    return client.get("/api/audit-log").json()


def test_login_and_failed_login_are_audited(tmp_path):
    client, _ = _logged_in_client(tmp_path)
    fresh = TestClient(client.app)
    assert fresh.post("/api/auth/login", json={"email": "nobody@example.com", "password": "x"}).status_code == 401

    actions = [e["action"] for e in _events(client)]
    assert "auth.login" in actions
    failed = next(e for e in _events(client) if e["action"] == "auth.login_failed")
    assert failed["user_email"] == "nobody@example.com" and failed["status_code"] == 401


def test_mutations_are_audited_with_subject_and_reads_are_not(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    h = {"X-CSRF-Token": csrf}
    app = client.post("/api/applications", json={"name": "A"}, headers=h).json()
    client.get("/api/applications")
    client.post(f"/api/applications/{app['id']}/runs", json={}, headers=h)

    events = _events(client)
    run_event = next(e for e in events if e["action"] == "POST /api/applications/{application_id}/runs")
    assert run_event["subject"] == {"application_id": app["id"]}
    assert run_event["user_id"] == "USER-test" and run_event["status_code"] == 200 and run_event["via"] == "session"
    assert not any(e["action"].startswith("GET ") for e in events)


def test_rejected_mutation_is_recorded_with_its_status(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    client.delete("/api/applications/APP-missing", headers={"X-CSRF-Token": csrf})
    event = next(e for e in _events(client) if e["action"].startswith("DELETE "))
    assert event["status_code"] == 404


def test_api_token_actions_are_attributed_via_api_token(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    secret = client.post("/api/tokens", json={"name": "ci"}, headers={"X-CSRF-Token": csrf}).json()["secret"]
    bearer = TestClient(client.app)
    bearer.headers["Authorization"] = f"Bearer {secret}"
    app_id = client.post("/api/applications", json={"name": "ViaToken"}, headers={"X-CSRF-Token": csrf}).json()["id"]
    bearer.post(f"/api/applications/{app_id}/runs", json={})  # starting a run is one of the routes a CI token may call

    event = next(e for e in _events(client) if e["action"] == "POST /api/applications/{application_id}/runs")
    assert event["via"] == "api_token"


def test_request_bodies_and_secrets_are_never_recorded(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    secret = client.post("/api/tokens", json={"name": "topsecretname"}, headers={"X-CSRF-Token": csrf}).json()["secret"]
    dump = client.get("/api/audit-log").text
    assert secret not in dump and "topsecretname" not in dump


def test_audit_log_is_owner_only_and_needs_auth(tmp_path):
    client, _ = _logged_in_client(tmp_path)
    assert TestClient(client.app).get("/api/audit-log").status_code == 401

    from datetime import UTC, datetime

    from kresheen.dashboard.auth import hash_password
    from kresheen.models.user import User

    client.app.state.repo.save_user(
        User(id="U2", email="m@example.com", password_hash=hash_password("pw-member-1"), role="member", created_at=datetime.now(UTC))
    )
    member = TestClient(client.app)
    member.post("/api/auth/login", json={"email": "m@example.com", "password": "pw-member-1"})
    assert member.get("/api/audit-log").status_code == 403


def test_pagination_and_user_filter(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    for i in range(3):
        client.post("/api/applications", json={"name": f"A{i}"}, headers={"X-CSRF-Token": csrf})
    page = client.get("/api/audit-log", params={"limit": 2}).json()
    assert len(page) == 2
    older = client.get("/api/audit-log", params={"limit": 50, "before": page[-1]["at"]}).json()
    assert all(e["at"] < page[-1]["at"] for e in older)
    assert client.get("/api/audit-log", params={"user_id": "USER-nobody"}).json() == []
