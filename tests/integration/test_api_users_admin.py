"""Owner-only user administration: `GET/POST /api/users`, `PATCH
/api/users/{id}` (Task E1). See `test_api_threat_modeling_platform.py`
("Users" section) for the pre-existing list/role-gate tests this extends.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

_OWNER_EMAIL = "owner@example.com"
_MEMBER_EMAIL = "member@example.com"
_PASSWORD = "correct-password-1"  # nosec: test fixture, not a real credential


def _login(client: TestClient, email: str) -> str:
    response = client.post("/api/auth/login", json={"email": email, "password": _PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def _owner(tmp_path, user_id: str = "USER-owner") -> tuple[TestClient, SQLRepository, str]:
    db_url = f"sqlite:///{tmp_path}/test.db"
    repo = SQLRepository(db_url)
    repo.save_user(
        User(
            id=user_id,
            email=_OWNER_EMAIL,
            password_hash=hash_password(_PASSWORD),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    client = TestClient(create_app(db_url=db_url))
    return client, repo, _login(client, _OWNER_EMAIL)


def _add_member(repo: SQLRepository) -> None:
    """Only saves the row -- does *not* log in on the owner's `client`
    (that would replace the owner's session cookie with the member's, since
    a `TestClient`'s cookie jar holds one session per app)."""
    repo.save_user(
        User(
            id="USER-member",
            email=_MEMBER_EMAIL,
            password_hash=hash_password(_PASSWORD),
            role="member",
            created_at=datetime.now(UTC),
        )
    )


def _member_client(app) -> tuple[TestClient, str]:
    """A separate `TestClient` against the same app/repo, logged in as the
    member added by `_add_member`."""
    client = TestClient(app)
    return client, _login(client, _MEMBER_EMAIL)


def _bearer_client(client: TestClient, csrf: str) -> TestClient:
    created = client.post("/api/tokens", json={"name": "ci"}, headers={"X-CSRF-Token": csrf})
    assert created.status_code == 200, created.text
    bearer = TestClient(client.app)
    bearer.headers["Authorization"] = f"Bearer {created.json()['secret']}"
    return bearer


# -- create ------------------------------------------------------------------


def test_owner_can_create_a_password_user_and_password_is_shown_once(tmp_path):
    client, _repo, csrf = _owner(tmp_path)

    response = client.post(
        "/api/users", json={"email": "new@example.com", "role": "member"}, headers={"X-CSRF-Token": csrf}
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["email"] == "new@example.com"
    assert body["role"] == "member"
    assert body["auth_source"] == "password"
    assert body["is_active"] is True
    assert isinstance(body["one_time_password"], str) and len(body["one_time_password"]) > 10
    assert "password_hash" not in body

    listed = client.get("/api/users").json()
    assert all("one_time_password" not in row and "password_hash" not in row for row in listed)


def test_member_cannot_create_a_user(tmp_path):
    client, repo, _owner_csrf = _owner(tmp_path)
    _add_member(repo)
    member_client, member_csrf = _member_client(client.app)

    response = member_client.post(
        "/api/users", json={"email": "new@example.com", "role": "member"}, headers={"X-CSRF-Token": member_csrf}
    )

    assert response.status_code == 403


def test_bearer_token_cannot_create_a_user(tmp_path):
    client, _repo, csrf = _owner(tmp_path)
    bearer = _bearer_client(client, csrf)

    response = bearer.post("/api/users", json={"email": "viatoken@example.com", "role": "member"})

    assert response.status_code == 403


def test_duplicate_email_is_rejected(tmp_path):
    client, _repo, csrf = _owner(tmp_path)

    client.post("/api/users", json={"email": "dup@example.com", "role": "member"}, headers={"X-CSRF-Token": csrf})
    response = client.post(
        "/api/users", json={"email": "dup@example.com", "role": "member"}, headers={"X-CSRF-Token": csrf}
    )

    assert response.status_code == 409


def test_create_user_without_csrf_is_rejected(tmp_path):
    client, _repo, _csrf = _owner(tmp_path)

    response = client.post("/api/users", json={"email": "new@example.com", "role": "member"})

    assert response.status_code == 403


# -- patch: role / active -----------------------------------------------------


def test_owner_can_deactivate_and_reactivate_a_member(tmp_path):
    client, repo, csrf = _owner(tmp_path)
    _add_member(repo)
    member = repo.get_user_by_email(_MEMBER_EMAIL)

    deactivated = client.patch(f"/api/users/{member.id}", json={"is_active": False}, headers={"X-CSRF-Token": csrf})
    assert deactivated.status_code == 200, deactivated.text
    assert deactivated.json()["is_active"] is False

    reactivated = client.patch(f"/api/users/{member.id}", json={"is_active": True}, headers={"X-CSRF-Token": csrf})
    assert reactivated.status_code == 200
    assert reactivated.json()["is_active"] is True


def test_deactivated_user_cannot_log_in(tmp_path):
    client, repo, csrf = _owner(tmp_path)
    _add_member(repo)
    member = repo.get_user_by_email(_MEMBER_EMAIL)

    client.patch(f"/api/users/{member.id}", json={"is_active": False}, headers={"X-CSRF-Token": csrf})

    response = TestClient(client.app).post("/api/auth/login", json={"email": _MEMBER_EMAIL, "password": _PASSWORD})
    assert response.status_code == 401


def test_deactivating_ends_the_users_open_sessions(tmp_path):
    client, repo, csrf = _owner(tmp_path)
    _add_member(repo)
    member = repo.get_user_by_email(_MEMBER_EMAIL)
    member_client, _member_csrf = _member_client(client.app)
    assert member_client.get("/api/auth/me").status_code == 200

    client.patch(f"/api/users/{member.id}", json={"is_active": False}, headers={"X-CSRF-Token": csrf})

    assert member_client.get("/api/auth/me").status_code == 401


def test_member_gets_403_patching_users(tmp_path):
    client, repo, _owner_csrf = _owner(tmp_path)
    _add_member(repo)
    member = repo.get_user_by_email(_MEMBER_EMAIL)
    member_client, member_csrf = _member_client(client.app)

    response = member_client.patch(
        f"/api/users/{member.id}", json={"role": "owner"}, headers={"X-CSRF-Token": member_csrf}
    )

    assert response.status_code == 403


def test_bearer_token_cannot_patch_users(tmp_path):
    client, repo, csrf = _owner(tmp_path)
    _add_member(repo)
    member = repo.get_user_by_email(_MEMBER_EMAIL)
    bearer = _bearer_client(client, csrf)

    response = bearer.patch(f"/api/users/{member.id}", json={"is_active": False})

    assert response.status_code == 403


def test_owner_cannot_deactivate_their_own_account(tmp_path):
    client, repo, csrf = _owner(tmp_path)
    owner = repo.get_user_by_email(_OWNER_EMAIL)

    response = client.patch(f"/api/users/{owner.id}", json={"is_active": False}, headers={"X-CSRF-Token": csrf})

    assert response.status_code == 422


def test_cannot_demote_the_last_active_owner(tmp_path):
    """The only reachable "last active owner" case: since the caller must
    themselves be an active owner to reach this route at all, any *other*
    account they deactivate/demote always still leaves the caller as an
    active owner -- the guard's only bite is against self-demotion when
    the caller is the sole owner (self-*deactivation* is refused
    unconditionally by a separate, simpler rule; see the test above)."""
    client, repo, csrf = _owner(tmp_path)
    owner = repo.get_user_by_email(_OWNER_EMAIL)

    response = client.patch(f"/api/users/{owner.id}", json={"role": "member"}, headers={"X-CSRF-Token": csrf})

    assert response.status_code == 422
    assert repo.get_user_by_email(_OWNER_EMAIL).role == "owner"


def test_demoting_one_of_several_owners_is_allowed(tmp_path):
    client, repo, csrf = _owner(tmp_path)
    second = User(
        id="USER-owner-2",
        email="owner2@example.com",
        password_hash=hash_password(_PASSWORD),
        role="owner",
        created_at=datetime.now(UTC),
    )
    repo.save_user(second)

    response = client.patch(f"/api/users/{second.id}", json={"role": "member"}, headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200
    assert response.json()["role"] == "member"


def test_patch_unknown_user_is_404(tmp_path):
    client, _repo, csrf = _owner(tmp_path)

    response = client.patch("/api/users/USER-nope", json={"is_active": False}, headers={"X-CSRF-Token": csrf})

    assert response.status_code == 404
