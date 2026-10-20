"""Security regression tests (route surface). Each test names the finding it pins."""
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

PW = "Correct-Horse-Battery-12"


def _client(tmp_path, role="owner", email="o@x.test"):
    url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(url)
    repo.save_user(User(id="U1", email=email, password_hash=hash_password(PW), role=role, created_at=datetime.now(UTC)))
    c = TestClient(create_app(db_url=url))
    c.headers["X-CSRF-Token"] = c.post("/api/auth/login", json={"email": email, "password": PW}).json()["csrf_token"]
    return c


def test_unknown_api_path_is_json_404_not_the_spa_shell(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>shell</html>")
    c = TestClient(create_app(db_url=f"sqlite:///{tmp_path}/t.db", frontend_dist=dist))
    for path in ("/api/nope", "/api"):
        r = c.get(path)
        assert r.status_code == 404 and r.headers["content-type"].startswith("application/json"), path
    assert c.get("/some/spa/route").text == "<html>shell</html>"


def test_security_headers_on_api_and_spa(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>shell</html>")
    c = TestClient(create_app(db_url=f"sqlite:///{tmp_path}/t.db", frontend_dist=dist))
    for path in ("/", "/api/capabilities", "/api/nope"):
        h = c.get(path).headers
        assert "script-src 'self'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["x-content-type-options"] == "nosniff" and h["referrer-policy"] == "no-referrer"
        assert "permissions-policy" in h and h["x-frame-options"] == "DENY"
        assert "strict-transport-security" not in h  # plain http: no HSTS
    assert "max-age=" in TestClient(create_app(db_url=f"sqlite:///{tmp_path}/t2.db"), base_url="https://testserver").get("/api/capabilities").headers["strict-transport-security"]


def test_report_downloads_keep_their_own_stricter_csp(tmp_path):
    c = _client(tmp_path)
    app_id = c.post("/api/applications", json={"name": "a"}).json()["id"]
    run_id = c.post(f"/api/applications/{app_id}/runs", json={}).json()["id"]
    csp = c.get(f"/api/applications/{app_id}/runs/{run_id}/report.html").headers["content-security-policy"]
    assert csp.startswith("default-src 'none'")


def test_api_docs_are_off_by_default_and_on_with_the_flag(tmp_path, monkeypatch):
    no_spa = tmp_path / "no-spa"  # a missing dist dir means no catch-all route, so a 404 here is the docs being off
    c = TestClient(create_app(db_url=f"sqlite:///{tmp_path}/t.db", frontend_dist=no_spa))
    assert all(c.get(p).status_code == 404 for p in ("/docs", "/redoc", "/openapi.json"))
    monkeypatch.setenv("KRESHEEN_API_DOCS", "1")
    c = TestClient(create_app(db_url=f"sqlite:///{tmp_path}/t2.db", frontend_dist=no_spa))
    assert c.get("/openapi.json").status_code == 200


def _login_cookie(tmp_path, name, monkeypatch, mode, scheme="http"):
    folder = tmp_path / name
    folder.mkdir()
    if mode:
        monkeypatch.setenv("KRESHEEN_COOKIE_SECURE", mode)
    else:
        monkeypatch.delenv("KRESHEEN_COOKIE_SECURE", raising=False)
    url = f"sqlite:///{folder}/t.db"
    SQLRepository(url).save_user(User(id="U1", email="o@x.test", password_hash=hash_password(PW), role="owner", created_at=datetime.now(UTC)))
    c = TestClient(create_app(db_url=url), base_url=f"{scheme}://testserver")
    return c.post("/api/auth/login", json={"email": "o@x.test", "password": PW}).headers["set-cookie"].lower()


def test_cookie_secure_follows_scheme_and_can_be_forced(tmp_path, monkeypatch):
    assert "; secure" not in _login_cookie(tmp_path, "plain", monkeypatch, None)
    assert "; secure" in _login_cookie(tmp_path, "tls", monkeypatch, None, scheme="https")
    assert "; secure" in _login_cookie(tmp_path, "proxy", monkeypatch, "always")  # TLS proxy: the app itself sees http
    assert "; secure" not in _login_cookie(tmp_path, "never", monkeypatch, "never", scheme="https")


def _login(client, email, pw=PW):
    r = client.post("/api/auth/login", json={"email": email, "password": pw})
    client.headers["X-CSRF-Token"] = r.json().get("csrf_token", "")
    return r


def _two_users(tmp_path):
    url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(url)
    repo.save_user(User(id="U1", email="o@x.test", password_hash=hash_password(PW), role="owner", created_at=datetime.now(UTC)))
    repo.save_user(User(id="U2", email="m@x.test", password_hash=hash_password(PW), role="member", created_at=datetime.now(UTC)))
    return url, repo


def test_api_token_is_limited_to_the_ci_routes(tmp_path):
    url, _ = _two_users(tmp_path)
    c = TestClient(create_app(db_url=url))
    _login(c, "o@x.test")
    secret = c.post("/api/tokens", json={"name": "ci"}).json()["secret"]
    app_id = c.post("/api/applications", json={"name": "a"}).json()["id"]
    bearer = TestClient(create_app(db_url=url), headers={"Authorization": f"Bearer {secret}"})
    allowed = [("get", "/api/applications"), ("get", f"/api/applications/{app_id}"), ("get", f"/api/applications/{app_id}/runs")]
    assert all(getattr(bearer, m)(p).status_code == 200 for m, p in allowed)
    assert bearer.post(f"/api/applications/{app_id}/runs", json={}).status_code == 200
    denied = [("get", "/api/users"), ("get", "/api/audit-log"), ("get", "/api/groups"),
              ("delete", f"/api/applications/{app_id}"), ("patch", f"/api/applications/{app_id}/group"),
              ("post", "/api/applications"), ("post", f"/api/applications/{app_id}/data-sources")]
    for m, p in denied:
        assert getattr(bearer, m)(p).status_code == 403, (m, p)


def test_password_change_revokes_api_tokens_and_expiry_is_honoured(tmp_path):
    url, repo = _two_users(tmp_path)
    c = TestClient(create_app(db_url=url))
    _login(c, "m@x.test")
    secret = c.post("/api/tokens", json={"name": "ci"}).json()["secret"]
    short = c.post("/api/tokens", json={"name": "short", "expires_in_days": 1}).json()
    assert short["expires_at"]
    ok = TestClient(create_app(db_url=url), headers={"Authorization": f"Bearer {secret}"})
    assert ok.get("/api/applications").status_code == 200
    assert c.post("/api/auth/change-password", json={"current_password": PW, "new_password": "A-brand-new-Passw0rd"}).status_code == 200
    assert ok.get("/api/applications").status_code == 401
    # expiry: an already-expired token is refused
    c2 = TestClient(create_app(db_url=url))
    _login(c2, "m@x.test", "A-brand-new-Passw0rd")
    t = c2.post("/api/tokens", json={"name": "old"}).json()
    stored = repo.list_api_tokens_for_user("U2")[0]
    repo.save_api_token(stored.model_copy(update={"expires_at": datetime.now(UTC).replace(year=2020)}))
    assert TestClient(create_app(db_url=url), headers={"Authorization": f"Bearer {t['secret']}"}).get("/api/applications").status_code == 401


def test_session_ids_are_not_stored_in_plaintext(tmp_path):
    import sqlite3
    url, _ = _two_users(tmp_path)
    c = TestClient(create_app(db_url=url))
    _login(c, "o@x.test")
    cookie = c.cookies.get("kresheen_session")
    rows = sqlite3.connect(f"{tmp_path}/t.db").execute("select id, data from sessions").fetchall()
    assert rows and all(cookie not in (r[0] + str(r[1])) for r in rows)
    assert c.get("/api/auth/me").status_code == 200  # still resolves by hash
    c.post("/api/auth/logout")
    assert c.get("/api/auth/me").status_code == 401


def test_github_owner_repo_and_ref_cannot_steer_the_request():
    import pytest as _pytest

    from kresheen.engine.ingest.github_repository_ingestor import validate_github_details as v
    v({"repo_url": "https://github.com/octo/repo", "ref": "feature/x-1.2"})
    for bad in ({"repo_url": "octo/repo", "ref": "../../orgs/x"}, {"repo_url": "octo/repo", "ref": "x?y=1"}, {"repo_url": "octo/repo", "ref": "x#f"},
                {"repo_url": "octo/repo", "ref": "-flag"}, {"repo_url": "https://github.com/../..", "ref": None}, {"repo_url": "octo\\evil.test/repo"}):
        with _pytest.raises(ValueError):
            v(bad)


def test_routine_write_flood_cannot_evict_security_events(tmp_path, monkeypatch):
    monkeypatch.setattr("kresheen.dashboard.audit.DEFAULT_MAX_ENTRIES", 30)
    url, _ = _two_users(tmp_path)
    c = TestClient(create_app(db_url=url))
    for _ in range(3):
        c.post("/api/auth/login", json={"email": "x@x.test", "password": "wrong-password-123"})
    _login(c, "o@x.test")
    c.post("/api/tokens", json={"name": "t"})
    for i in range(80):
        c.post("/api/groups", json={"name": f"g{i}"})
    actions = [e["action"] for e in c.get("/api/audit-log?limit=500").json()]
    assert actions.count("auth.login_failed") == 3 and "POST /api/tokens" in actions and "auth.login" in actions
    assert actions.count("POST /api/groups") <= 30  # routine rows are still capped


def test_lockouts_and_exports_are_audited(tmp_path, monkeypatch):
    monkeypatch.setenv("KRESHEEN_LOGIN_MAX_FAILURES_PER_ACCOUNT", "3")
    url, _ = _two_users(tmp_path)
    c = TestClient(create_app(db_url=url))
    for _ in range(6):
        c.post("/api/auth/login", json={"email": "m@x.test", "password": "wrong-password-123"})
    _login(c, "o@x.test")
    app_id = c.post("/api/applications", json={"name": "a"}).json()["id"]
    run_id = c.post(f"/api/applications/{app_id}/runs", json={}).json()["id"]
    c.get(f"/api/applications/{app_id}/runs/{run_id}/report.pdf")
    actions = [e["action"] for e in c.get("/api/audit-log?limit=500").json()]
    assert actions.count("auth.login_throttled") == 1  # once per window, not once per refused request
    assert "report.export" in actions


def test_healthz_is_unauthenticated_and_reveals_nothing(tmp_path):
    c = TestClient(create_app(db_url=f"sqlite:///{tmp_path}/t.db"))
    r = c.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_sqlite_database_file_is_owner_only(tmp_path):
    import os
    import stat

    path = tmp_path / "t.db"
    os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o644))
    SQLRepository(f"sqlite:///{path}")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
