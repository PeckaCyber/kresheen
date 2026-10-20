from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

_TEST_EMAIL = "owner@example.com"
_TEST_PASSWORD = "correct-password"  # nosec: test fixture, not a real credential


def _client_with_user(tmp_path, email: str, password: str) -> TestClient:
    db_url = f"sqlite:///{tmp_path}/test.db"
    repo = SQLRepository(db_url)
    repo.save_user(
        User(
            id="USER-test",
            email=email,
            password_hash=hash_password(password),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    return TestClient(create_app(db_url=db_url))


def test_login_with_correct_password_sets_session_cookie(tmp_path):
    client = _client_with_user(tmp_path, _TEST_EMAIL, _TEST_PASSWORD)

    response = client.post("/api/auth/login", json={"email": _TEST_EMAIL, "password": _TEST_PASSWORD})

    assert response.status_code == 200
    assert "kresheen_session" in response.cookies
    assert "csrf_token" in response.json()
    assert response.json()["role"] == "owner"


def test_login_with_wrong_password_is_rejected(tmp_path):
    client = _client_with_user(tmp_path, _TEST_EMAIL, _TEST_PASSWORD)

    response = client.post("/api/auth/login", json={"email": _TEST_EMAIL, "password": "wrong-password"})

    assert response.status_code == 401
    assert "kresheen_session" not in response.cookies


def test_login_with_unknown_email_is_rejected(tmp_path):
    db_url = f"sqlite:///{tmp_path}/test.db"
    client = TestClient(create_app(db_url=db_url))

    response = client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "anything"})

    assert response.status_code == 401


def test_api_requires_authentication(tmp_path):
    client = _client_with_user(tmp_path, _TEST_EMAIL, _TEST_PASSWORD)

    response = client.get("/api/applications")

    assert response.status_code == 401


def test_me_requires_authentication(tmp_path):
    client = _client_with_user(tmp_path, _TEST_EMAIL, _TEST_PASSWORD)

    assert client.get("/api/auth/me").status_code == 401


def _logged_in_client(tmp_path) -> tuple[TestClient, str]:
    client = _client_with_user(tmp_path, _TEST_EMAIL, _TEST_PASSWORD)
    login = client.post("/api/auth/login", json={"email": _TEST_EMAIL, "password": _TEST_PASSWORD})
    return client, login.json()["csrf_token"]


def test_authenticated_get_succeeds(tmp_path):
    client, _csrf_token = _logged_in_client(tmp_path)

    response = client.get("/api/applications")

    assert response.status_code == 200
    assert response.json() == []


def test_post_without_csrf_token_is_rejected(tmp_path):
    client, _csrf_token = _logged_in_client(tmp_path)

    response = client.post("/api/groups", json={"name": "team"})

    assert response.status_code == 403


def test_post_with_valid_csrf_token_roundtrips(tmp_path):
    client, csrf_token = _logged_in_client(tmp_path)

    response = client.post("/api/groups", json={"name": "team"}, headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 200

    fetched = client.get("/api/groups")
    assert [g["name"] for g in fetched.json()["groups"]] == ["team"]


def test_post_with_wrong_csrf_token_is_rejected(tmp_path):
    client, _csrf_token = _logged_in_client(tmp_path)

    response = client.post("/api/groups", json={"name": "team"}, headers={"X-CSRF-Token": "not-the-real-token"})

    assert response.status_code == 403


def test_logout_clears_session(tmp_path):
    client, csrf_token = _logged_in_client(tmp_path)

    logout = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout.status_code == 200

    response = client.get("/api/applications")
    assert response.status_code == 401
