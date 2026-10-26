from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.threat_model_run import ThreatModelRun, new_run_id
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository
from tests.integration.test_api_applications import _TEST_EMAIL, _TEST_PASSWORD, _logged_in_client


def _post(client, csrf, path, body):
    return client.post(path, json=body, headers={"X-CSRF-Token": csrf})


def _client_repo_csrf(tmp_path) -> tuple[TestClient, SQLRepository, str]:
    """Same as `_logged_in_client`, but also hands back a `Repository` bound
    to the same db so a test can seed a `ThreatModelRun` directly -- there is
    no API path to set `finding_counts_by_severity`/`input_digests` without
    running the real engine end to end."""
    db_url = f"sqlite:///{tmp_path}/test.db"
    repo = SQLRepository(db_url)
    repo.save_user(
        User(
            id="USER-test",
            email=_TEST_EMAIL,
            password_hash=hash_password(_TEST_PASSWORD),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    client = TestClient(create_app(db_url=db_url))
    login = client.post("/api/auth/login", json={"email": _TEST_EMAIL, "password": _TEST_PASSWORD})
    return client, repo, login.json()["csrf_token"]


def _seed_run(
    repo: SQLRepository,
    application_id: str,
    *,
    counts: dict[str, int],
    input_digests: dict[str, str] | None = None,
    stamped: bool | None = None,
) -> None:
    """Directly attaches a completed run with the given per-severity finding
    counts to an application, and points `latest_run_id` at it -- mirrors
    what `api_applications.py::create_run` does after a real engine run."""
    now = datetime.now(UTC)
    # A run is "stamped" (engine_version set) when it carries digests, unless
    # the caller says otherwise -- staleness keys off the stamp, not the map.
    if stamped is None:
        stamped = bool(input_digests)
    run = ThreatModelRun(
        id=new_run_id(),
        application_id=application_id,
        triggered_by_user_id="USER-test",
        status="completed",
        started_at=now,
        completed_at=now,
        finding_counts_by_severity=counts,
        input_digests=input_digests or {},
        engine_version="test" if stamped else None,
    )
    repo.save_run(run)
    application = repo.get_application(application_id)
    repo.save_application(application.model_copy(update={"latest_run_id": run.id}))


def test_groups_require_authentication_and_csrf(tmp_path):
    client, _csrf = _logged_in_client(tmp_path)

    assert client.post("/api/groups", json={"name": "Payments"}).status_code == 403
    client.cookies.clear()
    assert client.get("/api/groups").status_code == 401


def test_create_list_update_and_delete_group(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    headers = {"X-CSRF-Token": csrf}

    created = _post(client, csrf, "/api/groups", {"name": "Payments", "description": "Team A"})
    assert created.status_code == 200
    group = created.json()
    assert group["rollup"]["application_count"] == 0

    listed = client.get("/api/groups").json()
    assert [g["name"] for g in listed["groups"]] == ["Payments"]
    assert listed["ungrouped"]["application_count"] == 0

    renamed = client.put(f"/api/groups/{group['id']}", json={"name": "Payments Platform"}, headers=headers)
    assert renamed.json()["name"] == "Payments Platform"
    assert client.get(f"/api/groups/{group['id']}").json()["name"] == "Payments Platform"

    assert client.delete(f"/api/groups/{group['id']}", headers=headers).status_code == 204
    assert client.get(f"/api/groups/{group['id']}").status_code == 404


def test_group_names_must_be_non_blank_and_unique_ignoring_case(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    headers = {"X-CSRF-Token": csrf}
    _post(client, csrf, "/api/groups", {"name": "Payments"})

    assert _post(client, csrf, "/api/groups", {"name": "   "}).status_code == 422
    assert _post(client, csrf, "/api/groups", {"name": "payments"}).status_code == 409

    other = _post(client, csrf, "/api/groups", {"name": "Identity"}).json()
    clash = client.put(f"/api/groups/{other['id']}", json={"name": "PAYMENTS"}, headers=headers)
    assert clash.status_code == 409
    # Re-saving a group under its own name is not a clash with itself.
    same = client.put(f"/api/groups/{other['id']}", json={"name": "Identity", "description": "x"}, headers=headers)
    assert same.status_code == 200


def test_applications_are_filtered_by_group_and_counted(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    group = _post(client, csrf, "/api/groups", {"name": "Payments"}).json()

    in_group = _post(client, csrf, "/api/applications", {"name": "Checkout", "group_id": group["id"]}).json()
    loose = _post(client, csrf, "/api/applications", {"name": "Legacy"}).json()
    assert in_group["group_id"] == group["id"]
    assert loose["group_id"] is None

    by_group = client.get("/api/applications", params={"group_id": group["id"]}).json()
    assert [a["id"] for a in by_group] == [in_group["id"]]
    ungrouped = client.get("/api/applications", params={"group_id": "ungrouped"}).json()
    assert [a["id"] for a in ungrouped] == [loose["id"]]
    assert len(client.get("/api/applications").json()) == 2

    listed = client.get("/api/groups").json()
    assert listed["groups"][0]["rollup"]["application_count"] == 1
    assert listed["ungrouped"]["application_count"] == 1
    assert listed["overall"]["application_count"] == 2


def test_create_application_rejects_unknown_group(tmp_path):
    client, csrf = _logged_in_client(tmp_path)

    response = _post(client, csrf, "/api/applications", {"name": "X", "group_id": "GRP-nope"})

    assert response.status_code == 422


def test_move_application_between_groups_and_to_ungrouped(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    headers = {"X-CSRF-Token": csrf}
    a = _post(client, csrf, "/api/groups", {"name": "A"}).json()
    b = _post(client, csrf, "/api/groups", {"name": "B"}).json()
    app = _post(client, csrf, "/api/applications", {"name": "Svc", "group_id": a["id"]}).json()

    moved = client.patch(f"/api/applications/{app['id']}/group", json={"group_id": b["id"]}, headers=headers)
    assert moved.json()["group_id"] == b["id"]
    cleared = client.patch(f"/api/applications/{app['id']}/group", json={"group_id": None}, headers=headers)
    assert cleared.json()["group_id"] is None
    bad = client.patch(f"/api/applications/{app['id']}/group", json={"group_id": "GRP-nope"}, headers=headers)
    assert bad.status_code == 422


def test_deleting_a_group_keeps_its_applications_as_ungrouped(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    group = _post(client, csrf, "/api/groups", {"name": "Payments"}).json()
    app = _post(client, csrf, "/api/applications", {"name": "Checkout", "group_id": group["id"]}).json()

    client.delete(f"/api/groups/{group['id']}", headers={"X-CSRF-Token": csrf})

    survivor = client.get(f"/api/applications/{app['id']}").json()
    assert survivor["group_id"] is None
    assert client.get("/api/groups").json()["ungrouped"]["application_count"] == 1


# -- rollups (worst severity, finding count, staleness) -------------------------


def test_group_rollup_reports_worst_severity_and_finding_count(tmp_path):
    client, repo, csrf = _client_repo_csrf(tmp_path)
    group = _post(client, csrf, "/api/groups", {"name": "Payments"}).json()
    low = _post(client, csrf, "/api/applications", {"name": "Low sev", "group_id": group["id"]}).json()
    high = _post(client, csrf, "/api/applications", {"name": "High sev", "group_id": group["id"]}).json()
    _seed_run(repo, low["id"], counts={"low": 2}, input_digests={"x": "y"})
    _seed_run(repo, high["id"], counts={"high": 1, "medium": 3}, input_digests={"x": "y"})

    rollup = client.get("/api/groups").json()["groups"][0]["rollup"]

    assert rollup["application_count"] == 2
    assert rollup["worst_severity"] == "high"
    assert rollup["finding_count"] == 6  # 2 low + 1 high + 3 medium


def test_group_rollup_counts_stale_applications(tmp_path):
    client, repo, csrf = _client_repo_csrf(tmp_path)
    group = _post(client, csrf, "/api/groups", {"name": "Payments"}).json()
    never_run = _post(client, csrf, "/api/applications", {"name": "Never run", "group_id": group["id"]}).json()
    stale_stamp = _post(client, csrf, "/api/applications", {"name": "Stale stamp", "group_id": group["id"]}).json()
    _seed_run(repo, stale_stamp["id"], counts={})  # no input_digests -- unconditionally stale

    assert client.get(f"/api/applications/{never_run['id']}/staleness").json()["stale"] is True

    rollup = client.get("/api/groups").json()["groups"][0]["rollup"]
    assert rollup["stale_count"] == 2  # never run + stale stamp, both unconditionally stale


def test_ungrouped_and_overall_rollups_aggregate_across_groups(tmp_path):
    client, repo, csrf = _client_repo_csrf(tmp_path)
    group_a = _post(client, csrf, "/api/groups", {"name": "A"}).json()
    group_b = _post(client, csrf, "/api/groups", {"name": "B"}).json()
    in_a = _post(client, csrf, "/api/applications", {"name": "In A", "group_id": group_a["id"]}).json()
    in_b = _post(client, csrf, "/api/applications", {"name": "In B", "group_id": group_b["id"]}).json()
    loose = _post(client, csrf, "/api/applications", {"name": "Loose"}).json()
    _seed_run(repo, in_a["id"], counts={"low": 1}, input_digests={"x": "y"})
    _seed_run(repo, in_b["id"], counts={"critical": 1}, input_digests={"x": "y"})
    _seed_run(repo, loose["id"], counts={"medium": 1}, input_digests={"x": "y"})

    listed = client.get("/api/groups").json()

    assert listed["ungrouped"]["application_count"] == 1
    assert listed["ungrouped"]["worst_severity"] == "medium"
    assert listed["overall"]["application_count"] == 3
    assert listed["overall"]["worst_severity"] == "critical"  # worst across every group + ungrouped
    assert listed["overall"]["finding_count"] == 3


def test_group_rollup_counts_open_threats_and_unanalysed_inputs(tmp_path):
    """A hand-drawn model's design threats and a
    stored-but-unread input both show on the rollup, not just scanner findings."""
    client, _repo, csrf = _client_repo_csrf(tmp_path)
    headers = {"X-CSRF-Token": csrf}
    application = client.post("/api/applications", json={"name": "Drawn"}, headers=headers).json()
    client.post(
        f"/api/applications/{application['id']}/data-sources",
        json={"type": "documentation", "connection_details": {"filename": "d.md", "content": "x"}},
        headers=headers,
    )
    client.post(
        f"/api/applications/{application['id']}/manual-assets",
        json={"name": "API", "type": "process"},
        headers=headers,
    )
    client.post(f"/api/applications/{application['id']}/runs", headers=headers)

    overall = client.get("/api/groups").json()["overall"]

    assert overall["finding_count"] == 0
    assert overall["open_threat_count"] > 0
    assert overall["worst_threat_risk"] in {"critical", "high", "medium", "low"}
    assert overall["not_analysed_count"] == 1
