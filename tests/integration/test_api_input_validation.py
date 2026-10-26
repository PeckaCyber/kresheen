from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

PW = "correct-password-1"  # nosec: test fixture


def _client(tmp_path, **kw):
    url = f"sqlite:///{tmp_path}/t.db"
    SQLRepository(url).save_user(
        User(id="U1", email="o@x.test", password_hash=hash_password(PW), role="owner", created_at=datetime.now(UTC))
    )
    c = TestClient(create_app(db_url=url), **kw)
    c.headers["X-CSRF-Token"] = c.post("/api/auth/login", json={"email": "o@x.test", "password": PW}).json()[
        "csrf_token"
    ]
    return c


def test_bad_query_parameters_are_422_not_500(tmp_path):
    c = _client(tmp_path)
    assert c.get("/api/applications?group_id=" + "x" * 5000).status_code in (200, 422)


def test_lone_surrogate_in_an_upload_is_422_not_500(tmp_path):
    c = _client(tmp_path)
    aid = c.post("/api/applications", json={"name": "a"}).json()["id"]
    body = '{"type":"manifest_upload","connection_details":{"content":"kind: x \\ud800","filename":"f"}}'
    r = c.post(f"/api/applications/{aid}/data-sources", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 422 and "Unicode" in r.text
    ok = '{"type":"manifest_upload","connection_details":{"content":"kind: x \\ud83d\\ude00","filename":"f"}}'  # a valid pair (emoji)
    assert (
        c.post(
            f"/api/applications/{aid}/data-sources", content=ok, headers={"content-type": "application/json"}
        ).status_code
        == 200
    )


def test_unexpected_errors_return_json_without_internals(tmp_path, monkeypatch):
    c = _client(tmp_path, raise_server_exceptions=False)
    repo = c.app.state.repo

    def boom():
        raise RuntimeError("secret internal detail /usr/local/lib/x.py")

    monkeypatch.setattr(repo, "list_applications", boom)
    r = c.get("/api/applications")
    assert r.status_code == 500
    assert r.headers["content-type"].startswith("application/json")
    assert r.json() == {"detail": "Internal server error"} and "secret" not in r.text
