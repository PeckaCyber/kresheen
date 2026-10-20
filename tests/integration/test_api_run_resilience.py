import threading
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.threat_model_run import ThreatModelRun
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

PW = "correct-password-1"  # nosec: test fixture
K8S = "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: prod}\nspec: {template: {spec: {containers: [{name: c, image: nginx}]}}}\n"


def _setup(tmp_path):
    url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(url)
    repo.save_user(User(id="U1", email="o@x.test", password_hash=hash_password(PW), role="owner", created_at=datetime.now(UTC)))
    return url, repo


def _client(url):
    c = TestClient(create_app(db_url=url))
    c.headers["X-CSRF-Token"] = c.post("/api/auth/login", json={"email": "o@x.test", "password": PW}).json()["csrf_token"]
    return c


def test_run_left_non_terminal_by_a_crash_is_failed_at_startup(tmp_path):
    url, repo = _setup(tmp_path)
    c = _client(url)
    aid = c.post("/api/applications", json={"name": "a"}).json()["id"]
    stale = ThreatModelRun(id="RUN-stuck", application_id=aid, triggered_by_user_id="U1", data_source_config_ids=[],
                           status="ingesting", started_at=datetime.now(UTC) - timedelta(hours=2))
    repo.save_run(stale)
    c2 = _client(url)  # a new app on the same database = the server restarting
    run = c2.get(f"/api/applications/{aid}/runs/RUN-stuck").json()
    assert run["status"] == "failed" and "interrupted" in run["error_message"]


def test_stuck_run_is_also_fixed_when_read_without_a_restart(tmp_path):
    url, repo = _setup(tmp_path)
    c = _client(url)
    aid = c.post("/api/applications", json={"name": "a"}).json()["id"]
    repo.save_run(ThreatModelRun(id="RUN-stuck", application_id=aid, triggered_by_user_id="U1", data_source_config_ids=[],
                                 status="reasoning", started_at=datetime.now(UTC) - timedelta(hours=2)))
    assert [r["status"] for r in c.get(f"/api/applications/{aid}/runs").json()] == ["failed"]
    assert repo.get_run("RUN-stuck").status == "failed"  # persisted, not just displayed


def test_database_failure_during_a_run_is_recorded_without_leaking_sql(tmp_path, monkeypatch):
    url, _repo = _setup(tmp_path)
    c = _client(url)
    aid = c.post("/api/applications", json={"name": "a"}).json()["id"]
    c.post(f"/api/applications/{aid}/data-sources", json={"type": "manifest_upload", "connection_details": {"content": K8S, "filename": "m.yaml"}})
    app_repo = c.app.state.repo
    boom = OperationalError("INSERT INTO fact_nodes (id, run_id, data) VALUES (?, ?, ?)", ("FACT-N-secret",), Exception("database is locked"))
    monkeypatch.setattr(app_repo, "save_fact_nodes", lambda _n: (_ for _ in ()).throw(boom))
    run = c.post(f"/api/applications/{aid}/runs", json={}).json()
    assert run["status"] == "failed"
    assert "INSERT" not in run["error_message"] and "FACT-N-secret" not in run["error_message"]


def test_too_many_queued_runs_get_429(tmp_path, monkeypatch):
    monkeypatch.setenv("KRESHEEN_MAX_CONCURRENT_RUNS", "1")
    monkeypatch.setenv("KRESHEEN_MAX_QUEUED_RUNS", "1")
    url, _repo = _setup(tmp_path)
    c = _client(url)
    ids = []
    for i in range(4):
        aid = c.post("/api/applications", json={"name": f"a{i}"}).json()["id"]
        c.post(f"/api/applications/{aid}/data-sources", json={"type": "manifest_upload", "connection_details": {"content": K8S, "filename": "m.yaml"}})
        ids.append(aid)
    gate = threading.Event()
    app_repo = c.app.state.repo
    real = app_repo.save_fact_nodes
    app_repo.save_fact_nodes = lambda nodes: (gate.wait(5), real(nodes))[1]
    codes = []

    def go(aid):
        codes.append(c.post(f"/api/applications/{aid}/runs", json={}).status_code)

    threads = [threading.Thread(target=go, args=(a,)) for a in ids]
    for t in threads:
        t.start()
    import time
    time.sleep(1.5)
    gate.set()
    for t in threads:
        t.join()
    assert sorted(codes) == [200, 200, 429, 429]


def test_concurrent_sqlite_writers_do_not_hit_database_is_locked(tmp_path):
    _url, repo = _setup(tmp_path)
    errors = []

    def writer(n):
        try:
            for i in range(40):
                repo.save_run(ThreatModelRun(id=f"RUN-{n}-{i}", application_id="A", triggered_by_user_id="U", data_source_config_ids=[],
                                             started_at=datetime.now(UTC)))
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []
    with repo.engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
