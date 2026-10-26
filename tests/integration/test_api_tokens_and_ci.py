"""API tokens (bearer auth) and the `kresheen ci` client, end to end: the
CLI's HTTP calls are routed into an in-process TestClient, so the real
endpoints (token auth, run creation, diff) are exercised."""

from __future__ import annotations

import requests
from click.testing import CliRunner

from kresheen.cli.ci import ci
from tests.integration.test_api_applications import _logged_in_client


def _make_token(client, csrf, name="ci") -> dict:
    response = client.post("/api/tokens", json={"name": name}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    return response.json()


def _bearer_client(client, secret):
    from fastapi.testclient import TestClient

    fresh = TestClient(client.app)
    fresh.headers["Authorization"] = f"Bearer {secret}"
    return fresh


def test_token_secret_shown_once_and_never_listed(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    created = _make_token(client, csrf)
    assert created["secret"].startswith("pck_")
    listed = client.get("/api/tokens").json()
    assert len(listed) == 1
    assert "secret" not in listed[0] and "token_hash" not in listed[0]
    assert listed[0]["prefix"] == created["secret"][:8]


def test_bearer_token_authenticates_and_skips_csrf(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    secret = _make_token(client, csrf)["secret"]
    bearer = _bearer_client(client, secret)

    assert bearer.get("/api/applications").status_code == 200
    # No X-CSRF-Token: a bearer request isn't cookie-ridable, so it isn't needed.
    app_id = client.post("/api/applications", json={"name": "ViaToken"}, headers={"X-CSRF-Token": csrf}).json()["id"]
    assert bearer.post(f"/api/applications/{app_id}/runs", json={}).status_code == 200
    # A token is limited to the CI routes, so creating an application with one is refused.
    assert bearer.post("/api/applications", json={"name": "Nope"}).status_code == 403
    assert client.get("/api/tokens").json()[0]["last_used_at"] is not None


def test_bad_or_revoked_token_is_rejected(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    created = _make_token(client, csrf)
    assert _bearer_client(client, "pck_nope").get("/api/applications").status_code == 401

    client.delete(f"/api/tokens/{created['id']}", headers={"X-CSRF-Token": csrf})
    assert _bearer_client(client, created["secret"]).get("/api/applications").status_code == 401


def test_api_token_cannot_manage_tokens(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    bearer = _bearer_client(client, _make_token(client, csrf)["secret"])
    assert bearer.get("/api/tokens").status_code == 403
    assert bearer.post("/api/tokens", json={"name": "x"}).status_code == 403


def test_create_token_requires_csrf(tmp_path):
    client, _ = _logged_in_client(tmp_path)
    assert client.post("/api/tokens", json={"name": "x"}).status_code == 403


def test_source_ref_rejects_traversal(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    app = client.post("/api/applications", json={"name": "A"}, headers={"X-CSRF-Token": csrf}).json()
    bad = client.post(
        f"/api/applications/{app['id']}/runs", json={"source_ref": "../../x"}, headers={"X-CSRF-Token": csrf}
    )
    assert bad.status_code == 422


def _pretend_customer_to_api_flow_is_new(monkeypatch):
    """Manual components/flows are an Application-level overlay present in
    *every* run's merged DFD, so they never show up as "new" between two runs;
    only scan-derived flows do, and building one needs a full ingest fixture.
    Force the diff to report a new Customer -> API flow; whether it *crosses a
    boundary* is still computed for real from the run's merged elements."""
    from kresheen.engine.diff import FlowDiffEntry

    entry = FlowDiffEntry(key="flow:Customer->API", source_name="Customer", target_name="API")
    monkeypatch.setattr("kresheen.engine.diff.diff_flows", lambda previous, current: ([entry], []))


def test_diff_marks_new_boundary_crossing_flow(tmp_path, monkeypatch):
    client, csrf = _logged_in_client(tmp_path)
    h = {"X-CSRF-Token": csrf}
    app = client.post("/api/applications", json={"name": "A"}, headers=h).json()
    base = f"/api/applications/{app['id']}"
    first = client.post(f"{base}/runs", json={}, headers=h).json()
    user = client.post(f"{base}/manual-assets", json={"name": "Customer", "type": "external_entity"}, headers=h).json()
    api = client.post(f"{base}/manual-assets", json={"name": "API", "type": "process"}, headers=h).json()
    client.post(
        f"{base}/manual-flows",
        json={"source_ref": f"asset:{user['id']}", "target_ref": f"asset:{api['id']}", "label": "x"},
        headers=h,
    )
    second = client.post(f"{base}/runs", json={}, headers=h).json()
    _pretend_customer_to_api_flow_is_new(monkeypatch)

    diff = client.get(f"{base}/runs/{second['id']}/diff", params={"against": first["id"]}).json()
    assert [f["crosses_boundary"] for f in diff["new_flows"]] == [True]


def _route_requests_to(monkeypatch, client):
    def fake(method, url, headers=None, timeout=None, **kwargs):
        path = url.split("://", 1)[1].split("/", 1)[1]
        response = client.request(method, "/" + path, headers=headers, **kwargs)
        shim = requests.Response()
        shim.status_code = response.status_code
        shim._content = response.content
        return shim

    monkeypatch.setattr("kresheen.cli.ci.requests.request", fake)


def test_ci_command_fails_the_gate_on_new_boundary_crossing_then_passes_when_relaxed(tmp_path, monkeypatch):
    client, csrf = _logged_in_client(tmp_path)
    h = {"X-CSRF-Token": csrf}
    secret = _make_token(client, csrf)["secret"]
    app = client.post("/api/applications", json={"name": "Shop"}, headers=h).json()
    base = f"/api/applications/{app['id']}"
    client.post(f"{base}/runs", json={}, headers=h)  # baseline
    user = client.post(f"{base}/manual-assets", json={"name": "Customer", "type": "external_entity"}, headers=h).json()
    api = client.post(f"{base}/manual-assets", json={"name": "API", "type": "process"}, headers=h).json()
    client.post(
        f"{base}/manual-flows",
        json={"source_ref": f"asset:{user['id']}", "target_ref": f"asset:{api['id']}", "label": "x"},
        headers=h,
    )
    _route_requests_to(monkeypatch, _bearer_client(client, secret))
    _pretend_customer_to_api_flow_is_new(monkeypatch)

    args = ["--server", "http://pc.test", "--token", secret, "--application", "Shop"]
    failed = CliRunner().invoke(ci, args)
    assert failed.exit_code == 1, failed.output
    assert "Customer -> API" in failed.output
    assert f"/applications/{app['id']}/runs/" in failed.output  # a real SPA route

    passed = CliRunner().invoke(ci, [*args, "--no-fail-on-boundary-crossing"])
    assert passed.exit_code == 0, passed.output


def test_ci_command_reports_unknown_application_as_error(tmp_path, monkeypatch):
    client, csrf = _logged_in_client(tmp_path)
    secret = _make_token(client, csrf)["secret"]
    _route_requests_to(monkeypatch, _bearer_client(client, secret))
    result = CliRunner().invoke(ci, ["--server", "http://pc.test", "--token", secret, "--application", "Nope"])
    assert result.exit_code == 2


def test_expiry_defaults_to_90_days_and_never_needs_an_explicit_null(tmp_path):
    from datetime import UTC, datetime, timedelta

    client, csrf = _logged_in_client(tmp_path)
    headers = {"X-CSRF-Token": csrf}
    omitted = client.post("/api/tokens", json={"name": "a"}, headers=headers).json()
    expires = datetime.fromisoformat(omitted["expires_at"])
    assert timedelta(days=89, hours=23) < expires - datetime.now(UTC) <= timedelta(days=90)
    chosen = client.post("/api/tokens", json={"name": "b", "expires_in_days": 30}, headers=headers).json()
    assert (
        timedelta(days=29, hours=23)
        < datetime.fromisoformat(chosen["expires_at"]) - datetime.now(UTC)
        <= timedelta(days=30)
    )
    never = client.post("/api/tokens", json={"name": "c", "expires_in_days": None}, headers=headers).json()
    assert never["expires_at"] is None
    assert client.post("/api/tokens", json={"name": "d", "expires_in_days": 0}, headers=headers).status_code == 422
    assert client.post("/api/tokens", json={"name": "e", "expires_in_days": 731}, headers=headers).status_code == 422


def test_expired_token_is_refused(tmp_path):
    from datetime import UTC, datetime, timedelta

    client, csrf = _logged_in_client(tmp_path)
    created = _make_token(client, csrf)
    repo = client.app.state.repo
    stored = repo.list_api_tokens_for_user(repo.list_users()[0].id)[0]
    bearer = _bearer_client(client, created["secret"])
    assert bearer.get("/api/applications").status_code == 200
    repo.save_api_token(stored.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}))
    assert bearer.get("/api/applications").status_code == 401
