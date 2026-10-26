from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.engine.provenance import compute_staleness, input_digest
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

PW = "correct-password-1"  # nosec: test fixture


def _login(tmp_path, monkeypatch=None, limit=None):
    if monkeypatch is not None and limit is not None:
        monkeypatch.setenv("KRESHEEN_MAX_REQUEST_BYTES", str(limit))
    url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(url)
    repo.save_user(
        User(id="U1", email="o@x.test", password_hash=hash_password(PW), role="owner", created_at=datetime.now(UTC))
    )
    c = TestClient(create_app(db_url=url))
    csrf = c.post("/api/auth/login", json={"email": "o@x.test", "password": PW}).json()["csrf_token"]
    c.headers["X-CSRF-Token"] = csrf
    return c, repo


def _app(c):
    return c.post("/api/applications", json={"name": "a"}).json()["id"]


def test_oversized_body_is_refused_with_413_before_it_is_stored(tmp_path, monkeypatch):
    c, repo = _login(tmp_path, monkeypatch, limit=10_000)
    aid = _app(c)
    r = c.post(
        f"/api/applications/{aid}/data-sources",
        json={"type": "documentation", "connection_details": {"content": "x" * 50_000, "filename": "f"}},
    )
    assert r.status_code == 413 and "too large" in r.json()["detail"].lower()
    assert repo.list_data_sources_for_application(aid) == []


def test_body_under_the_limit_is_accepted(tmp_path, monkeypatch):
    c, _ = _login(tmp_path, monkeypatch, limit=10_000)
    aid = _app(c)
    r = c.post(
        f"/api/applications/{aid}/data-sources",
        json={"type": "documentation", "connection_details": {"content": "x" * 1_000, "filename": "f"}},
    )
    assert r.status_code == 200


def test_chunked_body_without_content_length_is_cut_off(tmp_path, monkeypatch):
    c, _ = _login(tmp_path, monkeypatch, limit=10_000)
    aid = _app(c)

    def chunks():
        for _ in range(20):
            yield (
                b'{"type":"documentation","connection_details":{"content":"' + b"x" * 2_000 if _ == 0 else b"x" * 2_000
            )
        yield b'"}}'

    r = c.post(f"/api/applications/{aid}/data-sources", content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_data_source_gets_a_digest_and_staleness_uses_it_without_loading_content(tmp_path, monkeypatch):
    c, repo = _login(tmp_path)
    aid = _app(c)
    ds = c.post(
        f"/api/applications/{aid}/data-sources",
        json={"type": "documentation", "connection_details": {"content": "hello", "filename": "f"}},
    ).json()
    assert ds["digest"]
    stored = repo.get_data_source(ds["id"])
    assert stored is not None and stored.digest == input_digest(stored)
    assert repo.list_data_source_digests(aid) == [(ds["id"], stored.digest)]
    run = c.post(f"/api/applications/{aid}/runs", json={}).json()
    assert run["status"] == "completed"
    app = repo.get_application(aid)

    def boom(*_a, **_k):
        raise AssertionError("staleness loaded the full data source")

    monkeypatch.setattr(repo, "list_data_sources_for_application", boom)
    monkeypatch.setattr(repo, "get_data_source", boom)
    assert compute_staleness(app, repo).stale is False


def test_legacy_source_without_digest_still_works(tmp_path):
    c, repo = _login(tmp_path)
    aid = _app(c)
    ds = c.post(
        f"/api/applications/{aid}/data-sources",
        json={"type": "documentation", "connection_details": {"content": "hello", "filename": "f"}},
    ).json()
    c.post(f"/api/applications/{aid}/runs", json={})
    stored = repo.get_data_source(ds["id"])
    stored.digest = None
    repo.save_data_source(stored)
    assert compute_staleness(repo.get_application(aid), repo).stale is False
    stored.connection_details = {"content": "changed", "filename": "f"}
    repo.save_data_source(stored)
    assert compute_staleness(repo.get_application(aid), repo).stale is True
