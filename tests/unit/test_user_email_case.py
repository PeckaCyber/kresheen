"""Email addresses match case-insensitively; new accounts are stored lower-cased."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User, normalize_email
from kresheen.storage.sql_repo import SQLRepository

_PASSWORD = "correct-password-1"  # nosec: test fixture, not a real credential


def _user(user_id: str, email: str) -> User:
    return User(id=user_id, email=email, password_hash=hash_password(_PASSWORD), created_at=datetime.now(UTC))


def test_normalize_email_trims_and_lowercases():
    assert normalize_email("  Bob@Example.COM ") == "bob@example.com"


def test_lookup_is_case_insensitive(tmp_path):
    repo = SQLRepository(f"sqlite:///{tmp_path}/t.db")
    repo.save_user(_user("USER-1", "bob@example.com"))
    assert repo.get_user_by_email("Bob@Example.com").id == "USER-1"


def test_exact_match_wins_and_case_only_duplicates_are_ambiguous(tmp_path):
    repo = SQLRepository(f"sqlite:///{tmp_path}/t.db")
    repo.save_user(_user("USER-1", "Bob@example.com"))
    repo.save_user(_user("USER-2", "bob@Example.com"))
    assert repo.get_user_by_email("Bob@example.com").id == "USER-1"
    assert repo.get_user_by_email("bob@Example.com").id == "USER-2"
    assert repo.get_user_by_email("BOB@EXAMPLE.COM") is None


def test_login_accepts_a_differently_cased_email(tmp_path):
    db_url = f"sqlite:///{tmp_path}/t.db"
    SQLRepository(db_url).save_user(_user("USER-1", "bob@example.com"))
    client = TestClient(create_app(db_url=db_url))
    response = client.post("/api/auth/login", json={"email": "Bob@Example.com", "password": _PASSWORD})
    assert response.status_code == 200


def test_owner_cannot_add_a_case_variant_of_an_existing_user(tmp_path):
    db_url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(db_url)
    owner = _user("USER-1", "owner@example.com").model_copy(update={"role": "owner"})
    repo.save_user(owner)
    repo.save_user(_user("USER-2", "bob@example.com"))
    client = TestClient(create_app(db_url=db_url))
    csrf = client.post("/api/auth/login", json={"email": "owner@example.com", "password": _PASSWORD}).json()[
        "csrf_token"
    ]
    response = client.post(
        "/api/users", json={"email": "BOB@example.com", "role": "member"}, headers={"X-CSRF-Token": csrf}
    )
    assert response.status_code == 409
    created = client.post(
        "/api/users", json={"email": " New.Person@Example.com ", "role": "member"}, headers={"X-CSRF-Token": csrf}
    )
    assert created.status_code == 200, created.text
    assert created.json()["email"] == "new.person@example.com"
