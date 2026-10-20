"""`kresheen db ...`: inspect and run database schema upgrades by hand (also what the Helm migration Job runs)."""

from __future__ import annotations

import click

from kresheen import plugins
from kresheen.storage import migrate
from kresheen.storage.sql_repo import _create_engine

_DB_OPTION = click.option(
    "--db",
    default="sqlite:///kresheen.db",
    envvar="KRESHEEN_DB_URL",
    help="SQLAlchemy database URL (sqlite:///... or postgresql+psycopg://...).",
)


def _locations() -> list[plugins.MigrationLocation]:
    """The core's tree plus every active plugin's (Pro, when licensed)."""
    return [migrate.core_location(), *plugins.load_plugins().migration_locations()]


@click.group("db")
def db_group() -> None:
    """Database schema: upgrade, show the current revision, list revisions."""


@db_group.command("upgrade")
@_DB_OPTION
def upgrade(db: str) -> None:
    """Bring the database schema to the latest revision (backs up SQLite first). Safe to run repeatedly."""
    engine = _create_engine(db)
    try:
        states = migrate.upgrade_to_head(engine, _locations(), auto_migrate=True)
    finally:
        engine.dispose()
    changed = [s for s in states if s.status in ("fresh", "behind")]
    if not changed:
        click.echo("Database schema is already up to date.")
    for state in changed:
        click.echo(f"{state.location.name}: {state.current or 'empty'} -> {state.head}")


@db_group.command("current")
@_DB_OPTION
def current(db: str) -> None:
    """Show each schema's recorded revision and whether it is the latest."""
    engine = _create_engine(db)
    try:
        states = migrate.inspect_all(engine, _locations())
    finally:
        engine.dispose()
    for state in states:
        label = {
            "fresh": "no tables yet",
            "current": f"{state.current} (latest)",
            "behind": f"{state.current} (latest is {state.head}; run `kresheen db upgrade`)",
            "ahead": f"{state.current} (newer than this version, latest known is {state.head})",
            "unversioned": "tables present but no revision recorded (see docs/upgrading.md)",
        }[state.status]
        click.echo(f"{state.location.name}: {label}")


@db_group.command("history")
def history() -> None:
    """List the schema revisions this version knows, newest first."""
    for location in _locations():
        click.echo(f"{location.name}:")
        for revision, summary in migrate.history(location):
            click.echo(f"  {revision}  {summary}")


@db_group.command("stamp-baseline")
@_DB_OPTION
def stamp_baseline(db: str) -> None:
    """For your own development or demo database created before schemas were versioned: check the live schema
    matches the baseline exactly, then record it as the baseline. Refuses, listing the differences, if it does not."""
    engine = _create_engine(db)
    try:
        notes = migrate.stamp_baseline(engine, _locations())
    finally:
        engine.dispose()
    for note in notes:
        click.echo(note)
