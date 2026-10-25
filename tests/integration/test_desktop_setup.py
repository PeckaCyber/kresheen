"""First-run setup of a desktop install (`POST /api/auth/setup`) and the `kresheen desktop` helpers."""

import os
import stat
import sys
import threading

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from kresheen.cli import desktop as desktop_module
from kresheen.dashboard.app import create_app
from kresheen.storage.sql_repo import SQLRepository

_TOKEN = "setup-token-for-tests"  # nosec: test fixture
_EMAIL = "Owner@Example.com"
_PASSWORD = "a-long-enough-password"  # nosec: test fixture
_LOCAL = ("127.0.0.1", 50000)


def _client(tmp_path, *, token: str | None = _TOKEN, client=_LOCAL) -> tuple[TestClient, SQLRepository]:
    db_url = f"sqlite:///{tmp_path}/test.db"
    app = create_app(db_url=db_url, setup_token=token)
    return TestClient(app, client=client), app.state.repo


def _setup(client: TestClient, **overrides):
    body = {"token": _TOKEN, "email": _EMAIL, "password": _PASSWORD, **overrides}
    return client.post("/api/auth/setup", json=body)


def test_setup_creates_the_owner_once_and_then_closes(tmp_path):
    client, repo = _client(tmp_path)
    assert client.get("/api/auth/setup").json() == {"needed": True}

    assert _setup(client).status_code == 201
    users = repo.list_users()
    assert [(u.email, u.role) for u in users] == [("owner@example.com", "owner")]
    login = client.post("/api/auth/login", json={"email": "owner@example.com", "password": _PASSWORD})
    assert login.status_code == 200

    assert client.get("/api/auth/setup").json() == {"needed": False}
    assert _setup(client, email="second@example.com").status_code == 404
    assert len(repo.list_users()) == 1
    actions = [event.action for event in repo.list_audit_events()]
    assert "auth.setup_owner" in actions


def test_setup_is_closed_without_a_launcher_token(tmp_path):
    client, repo = _client(tmp_path, token=None)  # `kresheen serve` never sets one
    assert client.get("/api/auth/setup").json() == {"needed": False}
    assert _setup(client).status_code == 404
    assert repo.list_users() == []


def test_setup_refuses_a_wrong_token(tmp_path):
    client, repo = _client(tmp_path)
    assert _setup(client, token="guess").status_code == 403
    assert repo.list_users() == []
    assert client.get("/api/auth/setup").json() == {"needed": True}  # a wrong guess does not burn the real token


def test_setup_refuses_a_request_from_another_machine(tmp_path):
    client, repo = _client(tmp_path, client=("192.0.2.10", 50000))
    assert client.get("/api/auth/setup").json() == {"needed": False}
    assert _setup(client).status_code == 403
    assert repo.list_users() == []


def test_setup_is_closed_once_any_account_exists(tmp_path):
    client, repo = _client(tmp_path)
    from kresheen.cli.main import cli

    result = CliRunner().invoke(cli, ["create-user", "--email", "a@example.com", "--db", f"sqlite:///{tmp_path}/test.db"])
    assert result.exit_code == 0
    assert _setup(client).status_code == 404
    assert [u.email for u in repo.list_users()] == ["a@example.com"]


def test_setup_checks_the_password_length(tmp_path):
    client, repo = _client(tmp_path)
    assert _setup(client, password="short").status_code == 422
    assert repo.list_users() == []


def test_racing_setups_create_one_owner(tmp_path):
    client, repo = _client(tmp_path)
    results: list[int] = []
    threads = [
        threading.Thread(target=lambda i=i: results.append(_setup(client, email=f"u{i}@example.com").status_code))
        for i in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [201, 404, 404, 404]
    assert len(repo.list_users()) == 1


# -- launcher helpers ------------------------------------------------------------------------------------------------


def test_data_dir_honours_kresheen_home(tmp_path, monkeypatch):
    monkeypatch.setenv("KRESHEEN_HOME", str(tmp_path / "home"))
    assert desktop_module.data_dir() == tmp_path / "home"


def test_data_dir_default_is_per_user(monkeypatch, tmp_path):
    monkeypatch.delenv("KRESHEEN_HOME", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(sys, "platform", "linux")
    assert desktop_module.data_dir() == tmp_path / "xdg" / "kresheen"
    monkeypatch.setattr(sys, "platform", "darwin")
    assert desktop_module.data_dir().parts[-3:] == ("Library", "Application Support", "Kresheen")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert desktop_module.data_dir() == tmp_path / "local" / "Kresheen"


def test_secret_key_is_created_once_and_private(tmp_path):
    from cryptography.fernet import Fernet

    first = desktop_module.load_or_create_secret_key(tmp_path)
    Fernet(first.encode())  # a valid key
    assert desktop_module.load_or_create_secret_key(tmp_path) == first
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "secret.key").stat().st_mode) == 0o600


@pytest.mark.parametrize("users", [False, True])
def test_desktop_starts_with_a_setup_link_only_when_there_is_no_account(tmp_path, monkeypatch, users):
    monkeypatch.setenv("KRESHEEN_HOME", str(tmp_path))
    for name in ("KRESHEEN_SECRET_KEY", "GRYPE_DB_CACHE_DIR", "GRYPE_CHECK_FOR_APP_UPDATE"):
        monkeypatch.delenv(name, raising=False)  # the launcher sets them; undone after the test
    if users:
        from kresheen.cli.main import cli

        CliRunner().invoke(cli, ["create-user", "--email", "a@example.com", "--db", f"sqlite:///{tmp_path}/kresheen.db"])
    seen = {}

    def fake_run(app, **kwargs):
        seen["token"] = app.state.setup_token
        seen["kwargs"] = kwargs

    monkeypatch.setattr(desktop_module.uvicorn, "run", fake_run)
    monkeypatch.setattr("kresheen.engine.threats.warmup.start_warmup", lambda repo: None)
    monkeypatch.setattr(desktop_module, "_port_free", lambda port: True)
    monkeypatch.setattr(desktop_module, "_open_when_ready", lambda *args: seen.setdefault("target", args[1]))
    monkeypatch.setattr(desktop_module.threading, "Thread", lambda target, args, daemon: type(
        "T", (), {"start": lambda self: target(*args)})())

    result = CliRunner().invoke(desktop_module.desktop, ["--no-browser"])

    assert result.exit_code == 0, result.output
    assert seen["kwargs"]["host"] == "127.0.0.1"
    assert seen["kwargs"]["proxy_headers"] is False
    assert (tmp_path / "secret.key").exists()
    if users:
        assert seen["token"] is None
        assert seen["target"] == "http://127.0.0.1:8765"
        assert not (tmp_path / "setup-token").exists()
    else:
        assert seen["token"]
        assert seen["target"] == f"http://127.0.0.1:8765/setup#token={seen['token']}"
        assert (tmp_path / "setup-token").read_text() == seen["token"]
