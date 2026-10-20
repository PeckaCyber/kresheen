"""A GitHub data source's token is encrypted at rest and never returned by any response."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import responses
from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.data_source import DataSourceConfig
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository
from tests.conftest import build_tarball_bytes

PW = "correct-password-1"  # nosec: test fixture
TOKEN = "ghp_SECRETTOKENVALUE1234"  # nosec: test fixture
TARBALL_URL = "https://api.github.com/repos/acme/widget/tarball"


def _setup(tmp_path):
    url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(url)
    repo.save_user(User(id="U1", email="o@x.test", password_hash=hash_password(PW), role="owner", created_at=datetime.now(UTC)))
    client = TestClient(create_app(db_url=url))
    client.headers["X-CSRF-Token"] = client.post("/api/auth/login", json={"email": "o@x.test", "password": PW}).json()["csrf_token"]
    app_id = client.post("/api/applications", json={"name": "A"}).json()["id"]
    return client, repo, app_id


def _add(client, app_id, **details):
    return client.post(
        f"/api/applications/{app_id}/data-sources",
        json={"type": "github_repository", "connection_details": {"repo_url": "acme/widget", **details}},
    )


def _db_text(repo) -> str:
    with repo.engine.connect() as conn:
        rows = []
        for table in ("data_source_configs", "encrypted_secrets", "threat_model_runs", "audit_events"):
            rows += [str(r) for r in conn.exec_driver_sql(f"select * from {table}").fetchall()]
    return "\n".join(rows)


def test_token_is_encrypted_at_rest_and_absent_from_every_response(tmp_path):
    client, repo, app_id = _setup(tmp_path)
    created = _add(client, app_id, github_token=TOKEN, ref="main")
    assert created.status_code in (200, 201)
    body = created.json()
    assert body["has_token"] is True and body["token_hint"] == TOKEN[-4:]
    assert body["connection_details"] == {"repo_url": "acme/widget", "ref": "main"}
    ds_id = body["id"]

    stored = repo.get_data_source(ds_id)
    assert "github_token" not in stored.connection_details
    assert TOKEN not in json.dumps(stored.model_dump(mode="json"))
    ref = stored.connection_details["github_token_ref"]
    assert repo.get_secret_blob(ref) is not None and TOKEN.encode() not in repo.get_secret_blob(ref)

    tar = build_tarball_bytes({"README.md": "x"})
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.GET, TARBALL_URL, body=tar, status=200)
        run = client.post(f"/api/applications/{app_id}/runs", json={}).json()
        assert rsps.calls[0].request.headers["Authorization"] == f"Bearer {TOKEN}"
    run_id = run["id"]

    base = f"/api/applications/{app_id}"
    responses_seen = [
        created,
        client.get(f"{base}/data-sources"),
        client.get(base),
        client.get("/api/applications"),
        client.get(f"{base}/staleness"),
        client.get(f"{base}/runs"),
        client.get(f"{base}/runs/{run_id}"),
        client.get(f"{base}/runs/{run_id}/report.html"),
        client.get(f"{base}/runs/{run_id}/threats.csv"),
        client.get(f"{base}/runs/{run_id}/findings.csv"),
        client.get("/api/audit"),
        client.get("/openapi.json"),
    ]
    for response in responses_seen:
        assert TOKEN not in response.text, response.request.url
        assert ref not in response.text, response.request.url
    docx = client.get(f"{base}/runs/{run_id}/report.docx")
    assert TOKEN.encode() not in docx.content
    assert TOKEN not in _db_text(repo)

    listed = client.get(f"{base}/data-sources").json()[0]
    assert listed["has_token"] is True and listed["token_hint"] == "1234"
    assert "github_token_ref" not in listed["connection_details"]


def test_token_needs_the_secret_key(tmp_path, monkeypatch):
    client, _repo, app_id = _setup(tmp_path)
    monkeypatch.delenv("KRESHEEN_SECRET_KEY")
    response = _add(client, app_id, github_token=TOKEN)
    assert response.status_code == 400 and "KRESHEEN_SECRET_KEY" in response.json()["detail"]
    assert TOKEN not in response.text
    assert client.get(f"/api/applications/{app_id}/data-sources").json() == []
    assert _add(client, app_id).status_code in (200, 201)  # a source without a token needs no key


def test_client_cannot_supply_a_secret_reference(tmp_path):
    client, repo, app_id = _setup(tmp_path)
    body = _add(client, app_id, github_token_ref="SECRET-abc", github_token_hint="zzzz").json()
    assert body["has_token"] is False
    assert not any(k.startswith("github_token") for k in repo.get_data_source(body["id"]).connection_details)


def test_replace_and_remove_token(tmp_path):
    client, repo, app_id = _setup(tmp_path)
    ds_id = _add(client, app_id, github_token=TOKEN).json()["id"]
    old_ref = repo.get_data_source(ds_id).connection_details["github_token_ref"]
    url = f"/api/applications/{app_id}/data-sources/{ds_id}/token"

    replaced = client.put(url, json={"token": "ghp_newvalue9999"})
    assert replaced.status_code == 200 and replaced.json()["token_hint"] == "9999"
    assert repo.get_secret_blob(old_ref) is None
    new_ref = repo.get_data_source(ds_id).connection_details["github_token_ref"]
    assert repo.get_secret_blob(new_ref) is not None

    removed = client.delete(url)
    assert removed.status_code == 200 and removed.json()["has_token"] is False
    assert repo.get_secret_blob(new_ref) is None
    assert not any(k.startswith("github_token") for k in repo.get_data_source(ds_id).connection_details)


def test_deleting_the_source_or_application_deletes_the_secret(tmp_path):
    client, repo, app_id = _setup(tmp_path)
    ds1 = _add(client, app_id, github_token=TOKEN).json()["id"]
    ds2 = _add(client, app_id, github_token="ghp_other5678").json()["id"]
    ref1 = repo.get_data_source(ds1).connection_details["github_token_ref"]
    ref2 = repo.get_data_source(ds2).connection_details["github_token_ref"]
    assert client.delete(f"/api/applications/{app_id}/data-sources/{ds1}").status_code == 204
    assert repo.get_secret_blob(ref1) is None and repo.get_secret_blob(ref2) is not None
    assert client.delete(f"/api/applications/{app_id}").status_code == 204
    assert repo.get_secret_blob(ref2) is None


def test_legacy_plaintext_row_is_never_returned_and_is_moved_when_the_key_is_available(tmp_path, monkeypatch):
    client, repo, app_id = _setup(tmp_path)
    legacy = DataSourceConfig(
        id="DS-legacy", application_id=app_id, type="github_repository",
        connection_details={"repo_url": "acme/widget", "github_token": TOKEN}, created_at=datetime.now(UTC),
    )
    from kresheen.engine.provenance import input_digest

    legacy.digest = input_digest(legacy)
    before = legacy.digest
    repo.save_data_source(legacy)

    with monkeypatch.context() as m:  # no key: still never returned, and not yet moved
        m.delenv("KRESHEEN_SECRET_KEY")
        out = client.get(f"/api/applications/{app_id}/data-sources")
        assert TOKEN not in out.text and out.json()[0]["has_token"] is True
        assert repo.get_data_source("DS-legacy").connection_details["github_token"] == TOKEN

    out = client.get(f"/api/applications/{app_id}/data-sources")  # key present: moved on first read
    assert TOKEN not in out.text and out.json()[0]["token_hint"] == "1234"
    moved = repo.get_data_source("DS-legacy")
    assert "github_token" not in moved.connection_details and moved.connection_details["github_token_ref"]
    assert TOKEN not in _db_text(repo)
    assert input_digest(moved) == before  # moving the token does not make the model look changed


def test_legacy_plaintext_row_still_runs_and_is_moved_by_the_run(tmp_path):
    client, repo, app_id = _setup(tmp_path)
    repo.save_data_source(DataSourceConfig(
        id="DS-legacy", application_id=app_id, type="github_repository",
        connection_details={"repo_url": "acme/widget", "github_token": TOKEN}, created_at=datetime.now(UTC),
    ))
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.GET, TARBALL_URL, body=build_tarball_bytes({"README.md": "x"}), status=200)
        run = client.post(f"/api/applications/{app_id}/runs", json={}).json()
        assert rsps.calls[0].request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert run["status"] == "completed"
    assert "github_token" not in repo.get_data_source("DS-legacy").connection_details
    assert client.get(f"/api/applications/{app_id}/staleness").json()["stale"] is False
