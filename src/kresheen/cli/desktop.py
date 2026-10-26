"""`kresheen desktop`: run Kresheen as a single-user app on this computer.

What the installers start. It keeps everything in one per-user folder (the SQLite database, the secret key, Grype's
vulnerability database), serves on 127.0.0.1 only, and opens the browser. On the first start there is no account
yet, so it opens a one-time setup link whose token only this process knows (see `POST /api/auth/setup`). For a
shared server use `kresheen serve` (or the container image) instead.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import secrets
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

import click
import uvicorn
from cryptography.fernet import Fernet

DEFAULT_PORT = 8765
_HOST = "127.0.0.1"


def data_dir() -> Path:
    """The per-user folder for a desktop install. KRESHEEN_HOME overrides it."""
    override = os.environ.get("KRESHEEN_HOME")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "Kresheen"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Kresheen"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "kresheen"


def load_or_create_secret_key(folder: Path) -> str:
    """The Fernet key that encrypts stored secrets, kept in `secret.key` (owner-only permissions). Losing it makes
    the stored tokens and API keys unreadable, so it is created once and never replaced."""
    path = folder / "secret.key"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text(encoding="ascii").strip()
    key = Fernet.generate_key().decode("ascii")
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(key + "\n")
    return key


def _write_private(path: Path, text: str) -> None:
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(text)


def _bundled_tools_dir() -> Path | None:
    """In a frozen build (the installers), the folder holding the bundled `grype` binary."""
    if not getattr(sys, "frozen", False):
        return None
    folder = Path(sys.executable).resolve().parent
    return folder if (folder / ("grype.exe" if sys.platform == "win32" else "grype")).exists() else None


def _get(port: int, path: str) -> tuple[int, bytes] | None:
    connection = http.client.HTTPConnection(_HOST, port, timeout=1)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    except OSError:
        return None
    finally:
        connection.close()


def _healthy(port: int) -> bool:
    result = _get(port, "/healthz")
    return result is not None and result[0] == 200


def _setup_pending(port: int) -> bool:
    result = _get(port, "/api/auth/setup")
    try:
        return result is not None and result[0] == 200 and json.loads(result[1]).get("needed") is True
    except ValueError:
        return False


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((_HOST, port))
        except OSError:
            return False
    return True


def _open_when_ready(port: int, target: str, open_browser: bool) -> None:
    for _ in range(120):
        if _healthy(port):
            break
        time.sleep(0.5)
    click.echo(f"Kresheen is running at {target}")
    click.echo("Press Ctrl+C or close this window to stop it.")
    if open_browser:
        webbrowser.open(target)


@click.command()
@click.option(
    "--port",
    default=DEFAULT_PORT,
    show_default=True,
    envvar="KRESHEEN_DESKTOP_PORT",
    help="Port on 127.0.0.1. If it is taken by another program, a free one is used.",
)
@click.option("--no-browser", is_flag=True, help="Do not open the browser; print the address instead.")
def desktop(port: int, no_browser: bool):
    """Run Kresheen on this computer only (what the installers start)."""
    logging.getLogger().setLevel(logging.WARNING)  # a console window for people, not a server log
    folder = data_dir()
    folder.mkdir(parents=True, exist_ok=True)
    try:
        folder.chmod(0o700)
    except OSError:
        pass
    base_url = f"http://{_HOST}:{port}"
    if not _port_free(port):
        if _healthy(port):  # Kresheen is already running (a second launch): just show it
            # Still waiting for setup: reopen the setup link the first launch wrote, or that window is lost.
            token_file = folder / "setup-token"
            target = base_url
            if token_file.exists() and _setup_pending(port):
                target = f"{base_url}/setup#token={token_file.read_text().strip()}"
            click.echo(f"Kresheen is already running at {target}")
            if not no_browser:
                webbrowser.open(target)
            return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((_HOST, 0))
            port = probe.getsockname()[1]
        base_url = f"http://{_HOST}:{port}"

    os.environ.setdefault("KRESHEEN_SECRET_KEY", load_or_create_secret_key(folder))
    os.environ.setdefault("GRYPE_DB_CACHE_DIR", str(folder / "grype-db"))
    os.environ.setdefault("GRYPE_CHECK_FOR_APP_UPDATE", "false")
    tools = _bundled_tools_dir()
    if tools is not None:
        os.environ["PATH"] = f"{tools}{os.pathsep}{os.environ.get('PATH', '')}"

    from kresheen.dashboard import create_app
    from kresheen.engine.threats.warmup import start_warmup
    from kresheen.storage import SQLRepository

    db_url = f"sqlite:///{(folder / 'kresheen.db').as_posix()}"
    # The token goes in the URL fragment: browsers never send a fragment to the server, so it stays out of logs.
    setup_token = None if SQLRepository(db_url).list_users() else secrets.token_urlsafe(32)
    # Kept (owner-only) for a second launch while setup is pending; useless once an account exists.
    if setup_token:
        _write_private(folder / "setup-token", setup_token)
    else:
        (folder / "setup-token").unlink(missing_ok=True)
    app = create_app(db_url=db_url, setup_token=setup_token)
    start_warmup(app.state.repo)
    target = f"{base_url}/setup#token={setup_token}" if setup_token else base_url
    click.echo(f"Data folder: {folder}")
    threading.Thread(target=_open_when_ready, args=(port, target, not no_browser), daemon=True).start()
    # No proxy headers: nothing sits in front of a desktop install, so the client address is always the real one.
    uvicorn.run(app, host=_HOST, port=port, proxy_headers=False, log_level="warning")
