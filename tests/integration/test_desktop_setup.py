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


def _client(
    tmp_path, *, token: str | None = _TOKEN, client=_LOCAL, desktop: bool = False
) -> tuple[TestClient, SQLRepository]:
    db_url = f"sqlite:///{tmp_path}/test.db"
    app = create_app(db_url=db_url, setup_token=token, desktop=desktop)
    return TestClient(app, client=client), app.state.repo


def _setup(client: TestClient, **overrides):
    body = {"token": _TOKEN, "email": _EMAIL, "password": _PASSWORD, **overrides}
    return client.post("/api/auth/setup", json=body)


def test_setup_creates_the_owner_once_and_then_closes(tmp_path):
    client, repo = _client(tmp_path)
    assert client.get("/api/auth/setup").json() == {"needed": True, "desktop": False}

    assert _setup(client).status_code == 201
    users = repo.list_users()
    assert [(u.email, u.role) for u in users] == [("owner@example.com", "owner")]
    login = client.post("/api/auth/login", json={"email": "owner@example.com", "password": _PASSWORD})
    assert login.status_code == 200

    assert client.get("/api/auth/setup").json() == {"needed": False, "desktop": False}
    assert _setup(client, email="second@example.com").status_code == 404
    assert len(repo.list_users()) == 1
    actions = [event.action for event in repo.list_audit_events()]
    assert "auth.setup_owner" in actions


def test_setup_is_closed_without_a_launcher_token(tmp_path):
    client, repo = _client(tmp_path, token=None)  # `kresheen serve` never sets one
    assert client.get("/api/auth/setup").json() == {"needed": False, "desktop": False}
    assert _setup(client).status_code == 404
    assert repo.list_users() == []


def test_setup_refuses_a_wrong_token(tmp_path):
    client, repo = _client(tmp_path)
    assert _setup(client, token="guess").status_code == 403
    assert repo.list_users() == []
    assert client.get("/api/auth/setup").json() == {
        "needed": True,
        "desktop": False,
    }  # a wrong guess does not burn the real token


def test_setup_refuses_a_request_from_another_machine(tmp_path):
    client, repo = _client(tmp_path, client=("192.0.2.10", 50000))
    assert client.get("/api/auth/setup").json() == {"needed": False, "desktop": False}
    assert _setup(client).status_code == 403
    assert repo.list_users() == []


def test_setup_is_closed_once_any_account_exists(tmp_path):
    client, repo = _client(tmp_path)
    from kresheen.cli.main import cli

    result = CliRunner().invoke(
        cli, ["create-user", "--email", "a@example.com", "--db", f"sqlite:///{tmp_path}/test.db"]
    )
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

        CliRunner().invoke(
            cli, ["create-user", "--email", "a@example.com", "--db", f"sqlite:///{tmp_path}/kresheen.db"]
        )
    seen = {}

    def fake_run(app, **kwargs):
        seen["token"] = app.state.setup_token
        seen["kwargs"] = kwargs

    monkeypatch.setattr(desktop_module.uvicorn, "run", fake_run)
    monkeypatch.setattr("kresheen.engine.threats.warmup.start_warmup", lambda repo: None)
    monkeypatch.setattr(desktop_module, "_port_free", lambda port: True)
    monkeypatch.setattr(desktop_module, "_open_when_ready", lambda *args: seen.setdefault("target", args[1]))
    monkeypatch.setattr(
        desktop_module.threading,
        "Thread",
        lambda target, args, daemon: type("T", (), {"start": lambda self: target(*args)})(),
    )

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


def test_desktop_flag_is_reported_only_to_this_machine(tmp_path):
    client, _ = _client(tmp_path, desktop=True)
    assert client.get("/api/auth/setup").json() == {"needed": True, "desktop": True}
    (tmp_path / "other").mkdir()
    remote, _ = _client(tmp_path / "other", desktop=True, client=("192.0.2.10", 50000))
    assert remote.get("/api/auth/setup").json() == {"needed": False, "desktop": False}


def test_desktop_flag_stays_true_once_an_account_exists(tmp_path):
    client, _ = _client(tmp_path, desktop=True)
    assert _setup(client).status_code == 201
    assert client.get("/api/auth/setup").json() == {"needed": False, "desktop": True}


def test_desktop_command_prints_accounts_and_recovery_hint(tmp_path, monkeypatch):
    monkeypatch.setenv("KRESHEEN_HOME", str(tmp_path))
    for name in ("KRESHEEN_SECRET_KEY", "GRYPE_DB_CACHE_DIR", "GRYPE_CHECK_FOR_APP_UPDATE"):
        monkeypatch.delenv(name, raising=False)
    SQLRepository(f"sqlite:///{tmp_path}/kresheen.db")
    from kresheen.cli.main import cli

    CliRunner().invoke(cli, ["create-user", "--email", "a@example.com"])
    seen = {}
    monkeypatch.setattr(
        desktop_module.uvicorn, "run", lambda app, **kwargs: seen.setdefault("desktop", app.state.desktop)
    )
    monkeypatch.setattr("kresheen.engine.threats.warmup.start_warmup", lambda repo: None)
    monkeypatch.setattr(desktop_module, "_port_free", lambda port: True)
    monkeypatch.setattr(
        desktop_module.threading, "Thread", lambda target, args, daemon: type("T", (), {"start": lambda self: None})()
    )
    result = CliRunner().invoke(desktop_module.desktop, ["--no-browser"])
    assert result.exit_code == 0, result.output
    assert seen["desktop"] is True
    assert "a@example.com" in result.output
    assert "reset-password --email" in result.output


# -- reset-password --------------------------------------------------------------------------------------------------


def _cli(tmp_path, *args):
    from kresheen.cli.main import cli

    return CliRunner().invoke(cli, [*args, "--db", f"sqlite:///{tmp_path}/test.db"])


def test_reset_password_lists_accounts_or_says_there_are_none(tmp_path):
    empty = _cli(tmp_path, "reset-password")
    assert empty.exit_code == 0
    assert "no accounts" in empty.output and "setup page" in empty.output
    _cli(tmp_path, "create-user", "--email", "a@example.com", "--password", _PASSWORD)
    _cli(tmp_path, "create-user", "--email", "b@example.com", "--password", _PASSWORD)
    listed = _cli(tmp_path, "reset-password")
    assert listed.exit_code == 0
    assert "a@example.com  role=owner  active" in listed.output
    assert "b@example.com  role=member  active" in listed.output


def test_reset_password_sets_a_new_password_and_signs_out(tmp_path):
    client, repo = _client(tmp_path)
    assert _setup(client).status_code == 201
    assert client.post("/api/auth/login", json={"email": "owner@example.com", "password": _PASSWORD}).status_code == 200
    assert client.get("/api/auth/me").status_code == 200

    result = _cli(tmp_path, "reset-password", "--email", "OWNER@example.com", "--password", "another-long-password")
    assert result.exit_code == 0, result.output
    assert "KRESHEEN_USER_PASSWORD=another-long-password" in result.output

    assert client.get("/api/auth/me").status_code == 401  # the old session is gone
    old = client.post("/api/auth/login", json={"email": "owner@example.com", "password": _PASSWORD})
    assert old.status_code == 401
    new = client.post("/api/auth/login", json={"email": "owner@example.com", "password": "another-long-password"})
    assert new.status_code == 200
    assert "auth.reset_password_cli" in [event.action for event in repo.list_audit_events()]


def test_reset_password_generates_a_password_when_none_is_given(tmp_path):
    _cli(tmp_path, "create-user", "--email", "a@example.com", "--password", _PASSWORD)
    result = _cli(tmp_path, "reset-password", "--email", "a@example.com")
    assert result.exit_code == 0
    line = next(x for x in result.output.splitlines() if x.startswith("KRESHEEN_USER_PASSWORD="))
    assert len(line.split("=", 1)[1]) >= 12


def test_reset_password_refuses_an_unknown_email_and_a_short_password(tmp_path):
    _cli(tmp_path, "create-user", "--email", "a@example.com", "--password", _PASSWORD)
    unknown = _cli(tmp_path, "reset-password", "--email", "nobody@example.com")
    assert unknown.exit_code != 0 and "No account" in unknown.output
    short = _cli(tmp_path, "reset-password", "--email", "a@example.com", "--password", "short")
    assert short.exit_code != 0 and "at least 12" in short.output


def test_account_commands_default_to_the_desktop_database(tmp_path, monkeypatch):
    from kresheen.cli.main import cli

    monkeypatch.delenv("KRESHEEN_DB_URL", raising=False)
    monkeypatch.delenv("KRESHEEN_HOME", raising=False)
    monkeypatch.chdir(tmp_path)
    home = tmp_path / "home"
    home.mkdir()

    CliRunner().invoke(cli, ["create-user", "--email", "plain@example.com", "--password", _PASSWORD])
    assert (tmp_path / "kresheen.db").exists() and not (home / "kresheen.db").exists()

    monkeypatch.setenv("KRESHEEN_HOME", str(home))
    assert CliRunner().invoke(cli, ["create-user", "--email", "a@example.com", "--password", _PASSWORD]).exit_code == 0
    assert [u.email for u in SQLRepository(f"sqlite:///{home}/kresheen.db").list_users()] == ["a@example.com"]

    monkeypatch.delenv("KRESHEEN_HOME")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(desktop_module, "data_dir", lambda: home)
    monkeypatch.setattr("kresheen.cli.main.data_dir", lambda: home)
    result = CliRunner().invoke(cli, ["reset-password"])
    assert "a@example.com" in result.output

    monkeypatch.setenv("KRESHEEN_DB_URL", f"sqlite:///{tmp_path}/kresheen.db")  # the env var still wins
    assert "plain@example.com" in CliRunner().invoke(cli, ["reset-password"]).output
