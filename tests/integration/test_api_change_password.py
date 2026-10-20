"""`POST /api/auth/change-password` (Task E1): self-service password
rotation for the current session's own account.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password, verify_password
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

_EMAIL = "user@example.com"
_PASSWORD = "correct-password-1"  # nosec: test fixture, not a real credential
_NEW_PASSWORD = "a-new-strong-password-1"  # nosec: test fixture, not a real credential


def _repo_and_client(tmp_path) -> tuple[SQLRepository, TestClient]:
    db_url = f"sqlite:///{tmp_path}/test.db"
    return SQLRepository(db_url), TestClient(create_app(db_url=db_url))


def _login(client: TestClient, email: str) -> str:
    response = client.post("/api/auth/login", json={"email": email, "password": _PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def test_change_password_happy_path_and_new_password_logs_in(tmp_path):
    repo, client = _repo_and_client(tmp_path)
    repo.save_user(
        User(id="USER-1", email=_EMAIL, password_hash=hash_password(_PASSWORD), created_at=datetime.now(UTC))
    )
    csrf = _login(client, _EMAIL)

    response = client.post(
        "/api/auth/change-password",
        json={"current_password": _PASSWORD, "new_password": _NEW_PASSWORD},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 200, response.text
    assert "password_hash" not in response.json() and "new_password" not in response.json()

    stored = repo.get_user_by_email(_EMAIL)
    assert verify_password(_NEW_PASSWORD, stored.password_hash)
    assert not verify_password(_PASSWORD, stored.password_hash)

    fresh = TestClient(client.app)
    assert fresh.post("/api/auth/login", json={"email": _EMAIL, "password": _NEW_PASSWORD}).status_code == 200
    assert fresh.post("/api/auth/login", json={"email": _EMAIL, "password": _PASSWORD}).status_code == 401


def test_change_password_with_wrong_current_password_is_rejected(tmp_path):
    repo, client = _repo_and_client(tmp_path)
    repo.save_user(
        User(id="USER-1", email=_EMAIL, password_hash=hash_password(_PASSWORD), created_at=datetime.now(UTC))
    )
    csrf = _login(client, _EMAIL)

    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "not-the-password", "new_password": _NEW_PASSWORD},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 401
    stored = repo.get_user_by_email(_EMAIL)
    assert verify_password(_PASSWORD, stored.password_hash)


def test_change_password_is_refused_for_sso_users(tmp_path):
    repo, client = _repo_and_client(tmp_path)
    # SSO/SCIM accounts get an unusable random password (see models/user.py);
    # generate a real one here only so this test can still log in as them.
    repo.save_user(
        User(
            id="USER-sso", email=_EMAIL, password_hash=hash_password(_PASSWORD), auth_source="sso",
            created_at=datetime.now(UTC),
        )
    )
    csrf = _login(client, _EMAIL)

    response = client.post(
        "/api/auth/change-password",
        json={"current_password": _PASSWORD, "new_password": _NEW_PASSWORD},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 403


def test_change_password_rejects_a_short_new_password(tmp_path):
    repo, client = _repo_and_client(tmp_path)
    repo.save_user(
        User(id="USER-1", email=_EMAIL, password_hash=hash_password(_PASSWORD), created_at=datetime.now(UTC))
    )
    csrf = _login(client, _EMAIL)

    response = client.post(
        "/api/auth/change-password",
        json={"current_password": _PASSWORD, "new_password": "short"},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 422


def test_change_password_requires_csrf(tmp_path):
    repo, client = _repo_and_client(tmp_path)
    repo.save_user(
        User(id="USER-1", email=_EMAIL, password_hash=hash_password(_PASSWORD), created_at=datetime.now(UTC))
    )
    _login(client, _EMAIL)

    response = client.post(
        "/api/auth/change-password", json={"current_password": _PASSWORD, "new_password": _NEW_PASSWORD}
    )

    assert response.status_code == 403


def test_bearer_token_cannot_change_password(tmp_path):
    repo, client = _repo_and_client(tmp_path)
    repo.save_user(
        User(id="USER-1", email=_EMAIL, password_hash=hash_password(_PASSWORD), created_at=datetime.now(UTC))
    )
    csrf = _login(client, _EMAIL)
    secret = client.post("/api/tokens", json={"name": "ci"}, headers={"X-CSRF-Token": csrf}).json()["secret"]
    bearer = TestClient(client.app)
    bearer.headers["Authorization"] = f"Bearer {secret}"

    response = bearer.post(
        "/api/auth/change-password", json={"current_password": _PASSWORD, "new_password": _NEW_PASSWORD}
    )

    assert response.status_code == 403


def test_change_password_signs_out_other_sessions_but_keeps_the_callers(tmp_path):
    repo, client = _repo_and_client(tmp_path)
    repo.save_user(
        User(id="USER-1", email=_EMAIL, password_hash=hash_password(_PASSWORD), created_at=datetime.now(UTC))
    )
    other = TestClient(client.app)
    _login(other, _EMAIL)
    csrf = _login(client, _EMAIL)

    response = client.post(
        "/api/auth/change-password",
        json={"current_password": _PASSWORD, "new_password": _NEW_PASSWORD},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 200, response.text
    assert client.get("/api/auth/me").status_code == 200
    assert other.get("/api/auth/me").status_code == 401
