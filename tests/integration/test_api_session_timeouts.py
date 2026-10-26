"""Session idle timeout, sliding refresh, absolute cap and last-seen write throttling."""

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import (
    generate_session,
    hash_password,
    session_idle_timeout,
    session_lifetime,
)
from kresheen.models.auth import Session
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository


def _setup(tmp_path):
    db_url = f"sqlite:///{tmp_path}/test.db"
    repo = SQLRepository(db_url)
    repo.save_user(
        User(
            id="USER-t",
            email="o@example.com",
            password_hash=hash_password("pw-long-enough-1"),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    return TestClient(create_app(db_url=db_url)), repo


def _session(repo, **changes) -> Session:
    session = generate_session("USER-t").model_copy(update=changes)
    repo.create_session(session)
    return session


def _get(client, session):
    client.cookies.clear()
    client.cookies.set("kresheen_session", session.id)
    return client.get("/api/auth/me")


def test_defaults_and_env_overrides(monkeypatch):
    assert session_idle_timeout() == timedelta(minutes=60)
    assert session_lifetime() == timedelta(hours=12)
    monkeypatch.setenv("KRESHEEN_SESSION_IDLE_MINUTES", "5")
    monkeypatch.setenv("KRESHEEN_SESSION_MAX_HOURS", "2")
    assert session_idle_timeout() == timedelta(minutes=5)
    assert session_lifetime() == timedelta(hours=2)
    monkeypatch.setenv("KRESHEEN_SESSION_IDLE_MINUTES", "junk")
    monkeypatch.setenv("KRESHEEN_SESSION_MAX_HOURS", "0")
    assert session_idle_timeout() == timedelta(minutes=60)
    assert session_lifetime() == timedelta(hours=12)


def test_new_session_uses_configured_absolute_lifetime(monkeypatch):
    monkeypatch.setenv("KRESHEEN_SESSION_MAX_HOURS", "2")
    session = generate_session("USER-t")
    assert timedelta(hours=1, minutes=59) < session.expires_at - session.created_at <= timedelta(hours=2)
    assert session.last_seen_at is not None


def test_idle_session_is_deleted_and_answers_401(tmp_path):
    client, repo = _setup(tmp_path)
    session = _session(repo, last_seen_at=datetime.now(UTC) - timedelta(minutes=61))
    assert _get(client, session).status_code == 401
    assert repo.get_session(session.id) is None
    assert _get(client, session).status_code == 401


def test_idle_timeout_follows_env(tmp_path, monkeypatch):
    client, repo = _setup(tmp_path)
    session = _session(repo, last_seen_at=datetime.now(UTC) - timedelta(minutes=10))
    assert _get(client, session).status_code == 200
    monkeypatch.setenv("KRESHEEN_SESSION_IDLE_MINUTES", "5")
    stale = _session(repo, last_seen_at=datetime.now(UTC) - timedelta(minutes=10))
    assert _get(client, stale).status_code == 401


def test_activity_slides_the_idle_window(tmp_path):
    client, repo = _setup(tmp_path)
    session = _session(repo, last_seen_at=datetime.now(UTC) - timedelta(minutes=50))
    assert _get(client, session).status_code == 200
    refreshed = repo.get_session(session.id)
    assert refreshed is not None and refreshed.last_seen_at is not None
    assert datetime.now(UTC) - refreshed.last_seen_at < timedelta(seconds=30)


def test_absolute_cap_still_applies_to_an_active_session(tmp_path):
    client, repo = _setup(tmp_path)
    session = _session(repo, expires_at=datetime.now(UTC) - timedelta(seconds=1), last_seen_at=datetime.now(UTC))
    assert _get(client, session).status_code == 401


def test_last_seen_write_is_throttled(tmp_path):
    client, _ = _setup(tmp_path)
    repo = client.app.state.repo  # type: ignore[attr-defined]
    writes: list[datetime] = []
    original = repo.touch_session
    repo.touch_session = lambda sid, at: (writes.append(at), original(sid, at))[1]
    session = _session(repo, last_seen_at=datetime.now(UTC) - timedelta(seconds=20))
    assert _get(client, session).status_code == 200
    assert _get(client, session).status_code == 200
    assert writes == []  # seen 20 seconds ago: no write
    old = _session(repo, last_seen_at=datetime.now(UTC) - timedelta(minutes=2))
    assert _get(client, old).status_code == 200
    assert _get(client, old).status_code == 200
    assert len(writes) == 1  # one write, then the fresh value suppresses the next


def test_session_without_last_seen_counts_from_creation(tmp_path):
    client, repo = _setup(tmp_path)
    session = _session(repo, last_seen_at=None, created_at=datetime.now(UTC) - timedelta(minutes=90))
    assert _get(client, session).status_code == 401
