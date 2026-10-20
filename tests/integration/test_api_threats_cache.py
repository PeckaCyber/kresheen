from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.engine.threats import view as view_mod
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

PW = "correct-password-1"  # nosec: test fixture


def _setup(tmp_path):
    url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(url)
    repo.save_user(User(id="U1", email="o@x.test", password_hash=hash_password(PW), role="owner", created_at=datetime.now(UTC)))
    c = TestClient(create_app(db_url=url))
    c.headers["X-CSRF-Token"] = c.post("/api/auth/login", json={"email": "o@x.test", "password": PW}).json()["csrf_token"]
    s = c.post("/api/applications/sample").json()
    return c, s["application_id"], s["run_id"]


def _count_generations(monkeypatch):
    calls = []
    real = view_mod._build_threats_out

    def counting(*a, **k):
        calls.append(1)
        return real(*a, **k)

    monkeypatch.setattr(view_mod, "_build_threats_out", counting)
    return calls


def test_list_pages_do_not_regenerate_threats_on_repeat_requests(tmp_path, monkeypatch):
    c, aid, rid = _setup(tmp_path)
    calls = _count_generations(monkeypatch)
    c.get("/api/groups"); first = len(calls)
    assert first >= 1
    c.get("/api/groups"); c.get("/api/dashboard"); c.get(f"/api/applications/{aid}/runs/{rid}/threats")
    assert len(calls) == first, "cached summary should serve repeat reads"


def test_a_status_change_is_visible_immediately(tmp_path, monkeypatch):
    c, aid, rid = _setup(tmp_path)
    before = c.get(f"/api/applications/{aid}/runs/{rid}/threats").json()
    open_before = before["summary"]["by_status"]["open"]
    key = before["threats"][0]["key"]
    def dashboard_open():
        return next(x for x in c.get("/api/dashboard").json()["applications"] if x["id"] == aid)["open_threat_count"]

    assert dashboard_open() == open_before  # warms the list-page cache
    r = c.put(f"/api/applications/{aid}/runs/{rid}/threats/status", json={"threat_key": key, "status": "mitigated", "note": "done"})
    assert r.status_code == 200
    after = c.get(f"/api/applications/{aid}/runs/{rid}/threats").json()
    assert after["summary"]["by_status"]["open"] == open_before - 1
    assert dashboard_open() == open_before - 1, "the list page served a stale cached count"


def test_adding_a_component_invalidates_that_application(tmp_path, monkeypatch):
    c, aid, rid = _setup(tmp_path)
    n0 = c.get(f"/api/applications/{aid}/runs/{rid}/threats").json()["summary"]["total"]
    assert c.post(f"/api/applications/{aid}/manual-assets", json={"name": "brand-new", "type": "process"}).status_code == 200
    n1 = c.get(f"/api/applications/{aid}/runs/{rid}/threats").json()["summary"]["total"]
    assert n1 > n0


def test_a_write_to_one_application_leaves_another_cached(tmp_path, monkeypatch):
    c, a1, r1 = _setup(tmp_path)
    s2 = c.post("/api/applications/sample").json()
    c.get(f"/api/applications/{a1}/runs/{r1}/threats"); c.get(f"/api/applications/{s2['application_id']}/runs/{s2['run_id']}/threats")
    calls = _count_generations(monkeypatch)
    c.post(f"/api/applications/{a1}/manual-assets", json={"name": "x", "type": "process"})
    c.get(f"/api/applications/{s2['application_id']}/runs/{s2['run_id']}/threats")
    assert not calls
    c.get(f"/api/applications/{a1}/runs/{r1}/threats")
    assert len(calls) == 1


def test_a_custom_kb_rule_invalidates_every_application(tmp_path, monkeypatch):
    c, aid, rid = _setup(tmp_path)
    c.get(f"/api/applications/{aid}/runs/{rid}/threats")
    calls = _count_generations(monkeypatch)
    r = c.post("/api/threat-kb", json={"name": "Custom", "description": "d", "applies_to": "process", "severity": "high"})
    assert r.status_code == 200
    c.get(f"/api/applications/{aid}/runs/{rid}/threats")
    assert len(calls) == 1, "a new rule changes every model's threats, so the cache must be dropped"


def test_writes_that_cannot_change_threats_keep_the_cache(tmp_path, monkeypatch):
    c, aid, rid = _setup(tmp_path)
    c.get(f"/api/applications/{aid}/runs/{rid}/threats")
    calls = _count_generations(monkeypatch)
    assert c.post("/api/groups", json={"name": "g"}).status_code == 200
    assert c.post("/api/tokens", json={"name": "t"}).status_code == 200
    c.get(f"/api/applications/{aid}/runs/{rid}/threats")
    c.get("/api/dashboard")
    assert not calls, "creating a group or a token must not force every model to be regenerated"


def test_concurrent_cold_requests_share_one_computation(tmp_path, monkeypatch):
    import threading
    import time

    c, aid, rid = _setup(tmp_path)
    c.post(f"/api/applications/{aid}/manual-assets", json={"name": "x", "type": "process"})  # invalidates: cache is cold
    calls = []
    real = view_mod._build_threats_out

    def slow(*a, **k):
        calls.append(1)
        time.sleep(0.4)
        return real(*a, **k)

    monkeypatch.setattr(view_mod, "_build_threats_out", slow)
    codes = []
    threads = [threading.Thread(target=lambda: codes.append(c.get(f"/api/applications/{aid}/runs/{rid}/threats").status_code)) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert codes == [200] * 6 and len(calls) == 1


def test_warmup_fills_the_cache_so_the_first_list_view_is_free(tmp_path, monkeypatch):
    from kresheen.engine.threats.warmup import warm_threats_cache

    c, aid, _rid = _setup(tmp_path)
    c.post(f"/api/applications/{aid}/manual-assets", json={"name": "y", "type": "process"})  # cold again
    assert warm_threats_cache(c.app.state.repo, pause=0) == 1
    calls = _count_generations(monkeypatch)
    c.get("/api/groups")
    c.get("/api/dashboard")
    assert not calls


def test_repeat_dashboard_loads_do_not_rebuild_the_action_plan(tmp_path, monkeypatch):
    from kresheen.dashboard.routes import api_dashboard

    c, aid, rid = _setup(tmp_path)
    first = c.get("/api/dashboard").json()
    calls = []
    real = api_dashboard.build_action_plan
    monkeypatch.setattr(api_dashboard, "build_action_plan", lambda *a, **k: calls.append(1) or real(*a, **k))
    second = c.get("/api/dashboard").json()
    assert not calls, "the per-model completeness score and action plan should come from the cache"
    row = lambda body: next(x for x in body["applications"] if x["id"] == aid)
    assert row(first)["open_action_count"] == row(second)["open_action_count"]
    assert row(first)["completeness_score"] == row(second)["completeness_score"]
    # an action status change is a write under the application: the plan is rebuilt and reflects it
    plan = c.get(f"/api/applications/{aid}/runs/{rid}/action-plan").json()
    action_id = plan["actions"][0]["id"]
    assert c.put(f"/api/applications/{aid}/runs/{rid}/action-plan/{action_id}/status", json={"status": "done"}).status_code in (200, 204)
    third = c.get("/api/dashboard").json()
    assert calls, "a status change must invalidate the cached plan"
    assert row(third)["open_action_count"] == row(first)["open_action_count"] - 1
