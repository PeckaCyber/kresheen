from datetime import UTC, datetime, timedelta

from kresheen.dashboard.auth import generate_session, hash_password, verify_password
from kresheen.models.auth import Session
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository


def _repo(tmp_path) -> SQLRepository:
    return SQLRepository(f"sqlite:///{tmp_path}/test.db")


def test_hash_password_verifies_correct_password():
    hashed = hash_password("correct-horse-battery-staple")

    assert verify_password("correct-horse-battery-staple", hashed) is True


def test_hash_password_rejects_wrong_password():
    hashed = hash_password("correct-horse-battery-staple")

    assert verify_password("wrong-password", hashed) is False


def test_verify_password_rejects_garbage_hash():
    assert verify_password("anything", "not-a-real-argon2-hash") is False


def test_generate_session_produces_unique_tokens():
    a = generate_session("USER-a")
    b = generate_session("USER-a")

    assert a.id != b.id
    assert a.csrf_token != b.csrf_token
    assert a.expires_at > a.created_at


def test_get_user_by_email_returns_none_when_unset(tmp_path):
    repo = _repo(tmp_path)

    assert repo.get_user_by_email("nobody@example.com") is None


def test_save_and_get_user_roundtrips(tmp_path):
    repo = _repo(tmp_path)
    user = User(
        id="USER-1",
        email="owner@example.com",
        password_hash=hash_password("hunter2"),
        role="owner",
        created_at=datetime.now(UTC),
    )

    repo.save_user(user)

    assert repo.get_user("USER-1") == user
    assert repo.get_user_by_email("owner@example.com") == user


def test_save_user_overwrites_previous_value(tmp_path):
    repo = _repo(tmp_path)
    repo.save_user(
        User(
            id="USER-1",
            email="owner@example.com",
            password_hash=hash_password("old"),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    new = User(
        id="USER-1",
        email="owner@example.com",
        password_hash=hash_password("new"),
        role="owner",
        created_at=datetime.now(UTC),
    )

    repo.save_user(new)

    assert repo.get_user("USER-1") == new


def test_create_and_get_session_roundtrips(tmp_path):
    repo = _repo(tmp_path)
    session = generate_session("USER-1")

    repo.create_session(session)

    assert repo.get_session(session.id) == session


def test_get_session_returns_none_for_unknown_id(tmp_path):
    repo = _repo(tmp_path)

    assert repo.get_session("does-not-exist") is None


def test_get_session_returns_none_once_expired(tmp_path):
    repo = _repo(tmp_path)
    now = datetime.now(UTC)
    expired = Session(
        id="expired-session",
        user_id="USER-1",
        csrf_token="csrf",
        created_at=now - timedelta(hours=13),
        expires_at=now - timedelta(hours=1),
    )
    repo.create_session(expired)

    assert repo.get_session(expired.id) is None


def test_delete_session_removes_it(tmp_path):
    repo = _repo(tmp_path)
    session = generate_session("USER-1")
    repo.create_session(session)

    repo.delete_session(session.id)

    assert repo.get_session(session.id) is None
