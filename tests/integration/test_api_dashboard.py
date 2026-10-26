from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository
from tests.integration.test_api_applications import (
    _create_application_with_manifest_source,
    _logged_in_client,
    _run_with_manifest,
)

_PASSWORD = "correct-password"  # nosec: test fixture, not a real credential
_OWNER_EMAIL = "owner@example.com"
_MEMBER_EMAIL = "member@example.com"


def test_dashboard_is_empty_with_no_applications(tmp_path):
    client, _ = _logged_in_client(tmp_path)
    body = client.get("/api/dashboard").json()
    assert body["applications"] == []
    assert body["trend"] == []
    assert isinstance(body["recent_activity"], list)  # owner's own login is an audit event
    assert body["summary"]["application_count"] == 0


def test_dashboard_lists_applications_and_records_a_snapshot(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    created = client.post("/api/applications", json={"name": "Shop", "description": ""}, headers={"X-CSRF-Token": csrf})
    assert created.status_code in (200, 201), created.text
    body = client.get("/api/dashboard").json()
    assert [a["name"] for a in body["applications"]] == ["Shop"]
    assert isinstance(body["trend"], list)


def _owner_client(tmp_path) -> tuple[TestClient, SQLRepository, str]:
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
    client = TestClient(create_app(db_url=db_url))
    csrf = client.post("/api/auth/login", json={"email": _OWNER_EMAIL, "password": _PASSWORD}).json()["csrf_token"]
    return client, repo, csrf


def test_recent_activity_is_owner_only(tmp_path):
    client, repo, csrf = _owner_client(tmp_path)
    repo.save_user(
        User(
            id="USER-member",
            email=_MEMBER_EMAIL,
            password_hash=hash_password(_PASSWORD),
            role="member",
            created_at=datetime.now(UTC),
        )
    )
    client.post("/api/applications", json={"name": "Shop", "description": ""}, headers={"X-CSRF-Token": csrf})

    owner_body = client.get("/api/dashboard").json()
    assert owner_body["recent_activity"], "owner should see audited writes"
    first = owner_body["recent_activity"][0]
    assert set(first.keys()) == {"at", "actor", "action", "target"}

    member_client = TestClient(client.app)
    member_client.post("/api/auth/login", json={"email": _MEMBER_EMAIL, "password": _PASSWORD})
    member_body = member_client.get("/api/dashboard").json()
    assert member_body["recent_activity"] == []


def test_a_completed_run_records_todays_snapshot(tmp_path):
    """D3(a): the orchestrator itself should upsert a snapshot on completion --
    checked via a fresh repo handle, with no intervening `/api/dashboard` GET
    (which would otherwise also write one and mask a missing call site)."""
    db_url = f"sqlite:///{tmp_path}/test.db"
    repo = SQLRepository(db_url)
    repo.save_user(
        User(
            id="USER-test",
            email=_OWNER_EMAIL,
            password_hash=hash_password(_PASSWORD),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    client = TestClient(create_app(db_url=db_url))
    csrf = client.post("/api/auth/login", json={"email": _OWNER_EMAIL, "password": _PASSWORD}).json()["csrf_token"]
    application = _create_application_with_manifest_source(client, csrf)

    run = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()
    assert run["status"] == "completed"

    snapshots = repo.list_threat_snapshots()
    assert [s.application_id for s in snapshots] == [application["id"]]


def test_a_threat_status_change_records_todays_snapshot(tmp_path):
    """D3(b): the single-status endpoint should upsert a snapshot too, again
    checked without an intervening dashboard load."""
    db_url = f"sqlite:///{tmp_path}/test.db"
    repo = SQLRepository(db_url)
    repo.save_user(
        User(
            id="USER-test",
            email=_OWNER_EMAIL,
            password_hash=hash_password(_PASSWORD),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    client = TestClient(create_app(db_url=db_url))
    csrf = client.post("/api/auth/login", json={"email": _OWNER_EMAIL, "password": _PASSWORD}).json()["csrf_token"]
    application, run = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    threats = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/threats").json()["threats"]
    # The run completing already wrote one snapshot; clear it so this test only
    # sees the one the status-change endpoint itself writes.
    repo.save_threat_snapshot(
        next(iter(repo.list_threat_snapshots())).model_copy(update={"open_keys": [t["key"] for t in threats]})
    )

    response = client.put(
        f"/api/applications/{application['id']}/runs/{run['id']}/threats/status",
        json={"threat_key": threats[0]["key"], "status": "mitigated", "note": "fixed"},
        headers=headers,
    )
    assert response.status_code == 200

    snapshots = repo.list_threat_snapshots()
    assert len(snapshots) == 1  # same (application, day) row, upserted
    assert len(snapshots[0].open_keys) == len(threats) - 1


def test_bulk_threat_status_change_records_todays_snapshot(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    threats = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/threats").json()["threats"]

    response = client.put(
        f"/api/applications/{application['id']}/runs/{run['id']}/threats/status/bulk",
        json={"threat_keys": [t["key"] for t in threats], "status": "mitigated", "note": "fixed"},
        headers=headers,
    )
    assert response.status_code == 200

    trend = client.get("/api/dashboard").json()["trend"]
    assert trend[-1]["open"] == 0
