"""CLI entry point: `kresheen create-user|serve|ci|audit-prune|db`."""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime

import click
import uvicorn

from kresheen.cli.ci import ci as ci_command
from kresheen.cli.db import db_group
from kresheen.dashboard import create_app
from kresheen.dashboard.auth import MIN_PASSWORD_LENGTH, hash_password
from kresheen.dashboard.workers import MultiWorkerError
from kresheen.engine.threats.warmup import start_warmup
from kresheen.models.user import User, new_user_id, normalize_email
from kresheen.plugins import load_plugins
from kresheen.storage import SQLRepository
from kresheen.storage.migrate import MigrationError

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

_DB_OPTION = click.option(
    "--db",
    default="sqlite:///kresheen.db",
    envvar="KRESHEEN_DB_URL",
    help="SQLAlchemy database URL (sqlite:///... or postgresql+psycopg://...).",
)


class _Group(click.Group):
    """A database that cannot be used (needs a migration, or is newer than this version) is a plain error message,
    not a traceback."""

    def invoke(self, ctx: click.Context):
        try:
            return super().invoke(ctx)
        except MigrationError as exc:
            raise click.ClickException(str(exc)) from exc


@click.group(cls=_Group)
@click.version_option(package_name="kresheen", prog_name="kresheen")
def cli():
    """Threat-modeling platform."""


@cli.command("create-user")
@click.option("--email", required=True, help="Login email for the new account.")
@click.option(
    "--password",
    default=None,
    help=f"Password to set (at least {MIN_PASSWORD_LENGTH} characters). Randomly generated and printed once if not given.",
)
@click.option(
    "--role",
    type=click.Choice(["owner", "member"]),
    default="member",
    help="Ignored for the very first account in a deployment, which is always made owner.",
)
@_DB_OPTION
def create_user(email: str, password: str | None, role: str, db: str):
    """Bootstrap a dashboard login. The first account created in a deployment is always
    "owner" regardless of --role, so there's always at least one account
    that can manage other users/administrative Settings.
    """
    if password is not None and len(password) < MIN_PASSWORD_LENGTH:
        raise click.UsageError(f"The password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    password = password or secrets.token_urlsafe(18)
    email = normalize_email(email)
    repo = SQLRepository(db)
    if repo.get_user_by_email(email) is not None:
        raise click.UsageError(f"A user with email {email!r} already exists.")
    effective_role = "owner" if not repo.list_users() else role
    repo.save_user(
        User(
            id=new_user_id(),
            email=email,
            password_hash=hash_password(password),
            role=effective_role,  # type: ignore[arg-type]
            created_at=datetime.now(UTC),
        )
    )
    click.echo(f"KRESHEEN_USER_EMAIL={email}")
    click.echo(f"KRESHEEN_USER_PASSWORD={password}")
    click.echo(f"role={effective_role}")
    click.echo("Save this now -- the password will not be shown again.")


@cli.command()
@click.option("--host", default="127.0.0.1", help="Interface to bind the dashboard to.")
@click.option("--port", default=8000, help="Port to bind the dashboard to.")
@click.option(
    "--frontend-dist",
    default=None,
    envvar="KRESHEEN_FRONTEND_DIST",
    help="Path to the built frontend (frontend/dist). Defaults to the repo-relative "
    "location; override for a Docker image that copies it elsewhere.",
)
@click.option(
    "--forwarded-allow-ips",
    default="127.0.0.1",
    show_default=True,
    envvar="KRESHEEN_FORWARDED_ALLOW_IPS",
    help="Reverse proxies (comma-separated IPs, or *) whose X-Forwarded-Proto/-For headers are trusted. Set this "
    "when a TLS-terminating proxy sits in front, so the session cookie gets Secure and the login throttle and "
    "audit log see real client addresses. Only trust a proxy that overwrites those headers.",
)
@_DB_OPTION
def serve(host: str, port: int, frontend_dist: str | None, forwarded_allow_ips: str, db: str):
    """Run the web dashboard."""
    try:
        app = create_app(db_url=db, frontend_dist=frontend_dist)
    except MultiWorkerError as exc:
        raise click.ClickException(str(exc)) from exc
    start_warmup(app.state.repo)  # fill the threats cache in the background (see engine/threats/warmup.py)
    uvicorn.run(app, host=host, port=port, proxy_headers=True, forwarded_allow_ips=forwarded_allow_ips)


cli.add_command(ci_command)
cli.add_command(db_group)
for _command in load_plugins().cli_commands():
    cli.add_command(_command)


@cli.command("audit-prune")
@click.option("--days", required=True, type=click.IntRange(min=1), help="Delete audit events older than this many days.")
@click.option("--db", default="sqlite:///kresheen.db", envvar="KRESHEEN_DB_URL", show_default=True)
def audit_prune(days: int, db: str):
    """Delete old audit-log rows (or set KRESHEEN_AUDIT_RETENTION_DAYS for automatic pruning)."""
    from kresheen.dashboard.audit import prune_audit_log

    click.echo(f"Deleted {prune_audit_log(SQLRepository(db), days)} audit events older than {days} days.")


if __name__ == "__main__":
    cli()
