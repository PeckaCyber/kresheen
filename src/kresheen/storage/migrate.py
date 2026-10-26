"""Database schema upgrades: Alembic, driven from code.

The schema is split into independent migration trees (`MigrationLocation`): the core's, and one per plugin that owns
tables. Each tree records its revision in its own version table, so they upgrade independently.

`upgrade_to_head` is what the application runs at startup. It never guesses:

- a database that is empty is built from nothing up to the latest revision;
- a database that is behind is upgraded (after a backup, on SQLite) unless `KRESHEEN_AUTO_MIGRATE=0`, in which case
  startup refuses and tells the operator to run `kresheen db upgrade` first;
- a database that is newer than this code, or that has tables but no version record (it predates versioned
  schemas), is refused with a message saying why. Neither is touched.

Migrations only go forward. There is no downgrade path; restore the backup instead.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.script.revision import RevisionError
from alembic.util import CommandError
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection, Engine

from kresheen.plugins import MigrationLocation, get_registry
from kresheen.storage.alembic_env import make_include_object

logger = logging.getLogger(__name__)

AUTO_MIGRATE_ENV = "KRESHEEN_AUTO_MIGRATE"
KEEP_BACKUPS = 3
# Arbitrary constant: every process that migrates takes the same Postgres advisory lock.
_ADVISORY_LOCK_KEY = 0x4B52455348454E  # "KRESHEN" as bytes

Status = Literal["fresh", "current", "behind", "ahead", "unversioned"]


class MigrationError(RuntimeError):
    """The database cannot be (or must not be) upgraded by this process. The message says what to do."""


@dataclass(frozen=True)
class TreeState:
    location: MigrationLocation
    current: str | None
    head: str
    status: Status


def core_location() -> MigrationLocation:
    from kresheen.storage.sql_repo import metadata  # lazy: sql_repo imports this module

    return MigrationLocation("core", Path(__file__).parent / "migrations", "alembic_version", metadata)


def all_locations() -> list[MigrationLocation]:
    """The core's tree plus every active plugin's."""
    return [core_location(), *get_registry().migration_locations()]


def auto_migrate_enabled() -> bool:
    return os.environ.get(AUTO_MIGRATE_ENV, "1").strip().lower() not in ("0", "false", "no", "off")


def _config(location: MigrationLocation, connection: Connection | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(location.script_location).replace("%", "%%"))
    cfg.attributes["target_metadata"] = location.metadata
    cfg.attributes["version_table"] = location.version_table
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def _script(location: MigrationLocation) -> ScriptDirectory:
    return ScriptDirectory.from_config(_config(location))


def _head(script: ScriptDirectory, location: MigrationLocation) -> str:
    heads = script.get_heads()
    if len(heads) != 1:
        raise MigrationError(
            f"The {location.name} migrations have {len(heads)} heads ({', '.join(heads)}); expected one."
        )
    return heads[0]


def baseline_revision(location: MigrationLocation) -> str:
    bases = _script(location).get_bases()
    if len(bases) != 1:
        raise MigrationError(f"The {location.name} migrations have {len(bases)} base revisions; expected one.")
    return bases[0]


def _current_revision(conn: Connection, location: MigrationLocation) -> str | None:
    context = MigrationContext.configure(conn, opts={"version_table": location.version_table})
    heads = context.get_current_heads()
    if len(heads) > 1:
        raise MigrationError(
            f"The {location.name} schema records several revisions ({', '.join(heads)}); fix the "
            f"{location.version_table} table by hand or restore a backup."
        )
    return heads[0] if heads else None


def inspect_tree(conn: Connection, location: MigrationLocation) -> TreeState:
    script = _script(location)
    head = _head(script, location)
    current = _current_revision(conn, location)
    if current is None:
        existing = set(inspect(conn).get_table_names())
        owned = existing & set(location.metadata.tables)
        status: Status = "unversioned" if owned else "fresh"
        return TreeState(location, None, head, status)
    try:
        script.get_revision(current)
    except (CommandError, RevisionError):  # the database names a revision this code has no file for
        return TreeState(location, current, head, "ahead")
    return TreeState(location, current, head, "current" if current == head else "behind")


def _refusal(state: TreeState) -> str | None:
    loc = state.location
    if state.status == "ahead":
        return (
            f"The database's {loc.name} schema is at revision {state.current!r}, which this version of Kresheen does "
            f"not know (the newest it knows is {state.head!r}). The database was written by a newer release. Run that "
            "release, or restore a backup taken before the upgrade. Kresheen never downgrades a database."
        )
    if state.status == "unversioned":
        tables = ", ".join(sorted(set(loc.metadata.tables)))
        return (
            f"The database has {loc.name} tables but no {loc.version_table} record, so it predates versioned "
            f"schemas (tables: {tables}). Kresheen will not guess its shape. See docs/upgrading.md. If this is your "
            "own development or demo database, `kresheen db stamp-baseline` checks the schema and records it."
        )
    return None


def _describe(states: Sequence[TreeState]) -> str:
    return "; ".join(f"{s.location.name}: {s.current or 'empty'} -> {s.head}" for s in states)


# -- SQLite backup ------------------------------------------------------------------------------------------------


def _sqlite_path(engine: Engine) -> Path | None:
    if engine.dialect.name != "sqlite":
        return None
    database = engine.url.database
    if not database or database == ":memory:" or database.startswith("file:"):
        return None
    path = Path(database)
    return path if path.is_file() else None


def backup_sqlite(path: Path, label: str, keep: int = KEEP_BACKUPS) -> Path:
    """Copy the database to `<db>.pre-<label>.bak` (mode 0600) with SQLite's online backup API, which reads a
    consistent snapshot even when the database is in WAL mode and other connections are open. Then keep only the
    `keep` newest backups of this database."""
    safe = re.sub(r"[^A-Za-z0-9_.+-]", "_", label)
    dest = path.with_name(f"{path.name}.pre-{safe}.bak")
    tmp = dest.with_name(dest.name + ".tmp")
    os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))  # created owner-only before any data lands
    source = sqlite3.connect(str(path))
    target = sqlite3.connect(str(tmp))
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)
    _prune_backups(path, keep=keep, newest=dest)
    return dest


def _prune_backups(path: Path, *, keep: int, newest: Path) -> None:
    others = [p for p in path.parent.glob(f"{glob_escape(path.name)}.pre-*.bak") if p != newest]
    others.sort(key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)
    for old in others[max(keep - 1, 0) :]:
        try:
            old.unlink()
        except OSError:
            logger.warning("Could not remove the old database backup %s", old)


def glob_escape(name: str) -> str:
    return re.sub(r"([*?\[])", r"[\1]", name)


# -- locking ------------------------------------------------------------------------------------------------------


@contextmanager
def migration_lock(engine: Engine) -> Iterator[None]:
    """On Postgres, hold a session-level advisory lock while migrating, so several replicas starting together never
    migrate at once: the others wait, then find nothing left to do. SQLite is a single-instance database, no lock."""
    if engine.dialect.name != "postgresql":
        yield
        return
    with engine.connect() as lock_conn:
        lock_conn.execute(text("SELECT pg_advisory_lock(:key)"), {"key": _ADVISORY_LOCK_KEY})
        lock_conn.commit()
        try:
            yield
        finally:
            try:
                lock_conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": _ADVISORY_LOCK_KEY})
                lock_conn.commit()
            except Exception:  # noqa: BLE001 - whatever went wrong, drop the connection so the lock cannot linger
                lock_conn.invalidate()  # closing the session releases its advisory locks


# -- public operations --------------------------------------------------------------------------------------------


def inspect_all(engine: Engine, locations: Sequence[MigrationLocation] | None = None) -> list[TreeState]:
    locs = list(locations) if locations is not None else all_locations()
    with engine.connect() as conn:
        return [inspect_tree(conn, loc) for loc in locs]


def upgrade_to_head(
    engine: Engine,
    locations: Sequence[MigrationLocation] | None = None,
    *,
    auto_migrate: bool | None = None,
) -> list[TreeState]:
    """Bring every migration tree to its latest revision, or refuse. Returns the states found before upgrading.

    `auto_migrate=None` reads `KRESHEEN_AUTO_MIGRATE` (default on). When off, nothing is changed: the call only
    checks that the database is already current."""
    locs = list(locations) if locations is not None else all_locations()
    auto = auto_migrate_enabled() if auto_migrate is None else auto_migrate
    with migration_lock(engine):
        states = inspect_all(engine, locs)
        for state in states:
            problem = _refusal(state)
            if problem:
                raise MigrationError(problem)
        pending = [s for s in states if s.status in ("fresh", "behind")]
        if not pending:
            return states
        if not auto:
            raise MigrationError(
                f"The database schema is not up to date ({_describe(pending)}) and {AUTO_MIGRATE_ENV}=0, so "
                "Kresheen will not change it on startup. Run `kresheen db upgrade` (with the same database URL), "
                "then start again."
            )
        _backup_before(engine, pending)
        for state in pending:
            logger.info("Upgrading the %s schema: %s -> %s", state.location.name, state.current or "empty", state.head)
            _run_upgrade(engine, state.location)
        logger.info("Database schema is up to date")
        return states


def _backup_before(engine: Engine, pending: Sequence[TreeState]) -> None:
    existing = [s for s in pending if s.current is not None]  # only a schema that already holds data needs a backup
    if engine.dialect.name == "postgresql":
        if existing:
            logger.warning(
                "Upgrading a PostgreSQL database (%s). Kresheen does not back up PostgreSQL: take a pg_dump first; "
                "you own that backup.",
                _describe(existing),
            )
        return
    path = _sqlite_path(engine)
    if path is None or not existing:
        return
    label = "+".join(s.head for s in existing)
    try:
        dest = backup_sqlite(path, label)
    except Exception as exc:
        raise MigrationError(
            f"Could not back up {path} before upgrading ({exc}); the database was not changed."
        ) from exc
    logger.warning("Backed up the database to %s before upgrading (%s)", dest, _describe(existing))


def _run_upgrade(engine: Engine, location: MigrationLocation) -> None:
    with engine.connect() as conn:
        command.upgrade(_config(location, conn), "head")
        conn.commit()


def schema_differences(conn: Connection, location: MigrationLocation) -> list[str]:
    """What differs between the live database and the tables this tree declares (this code's models), as readable
    lines. Empty when they match. Tables the tree does not declare are ignored."""
    context = MigrationContext.configure(
        conn,
        opts={
            "version_table": location.version_table,
            "compare_type": True,
            "include_object": make_include_object(location.metadata),
        },
    )
    return [_format_diff(d) for d in compare_metadata(context, location.metadata)]


def _format_diff(diff: Any) -> str:
    items = diff if isinstance(diff, list) else [diff]  # a modify_* diff arrives as a list of tuples
    return "; ".join(_format_item(item) for item in items)


def _format_item(item: tuple[Any, ...]) -> str:
    kind, *rest = item
    bits: list[str] = []
    for part in rest:
        if part is None or isinstance(part, dict):
            continue
        table = getattr(part, "table", None)
        name = getattr(part, "name", None)
        bits.append(f"{table.name}.{name}" if table is not None and name else str(name or part))
    return f"{kind} {' '.join(bits)}".strip()


def stamp_baseline(engine: Engine, locations: Sequence[MigrationLocation] | None = None) -> list[str]:
    """Record the baseline revision for a database created before schemas were versioned, but only after checking its
    live schema matches the baseline exactly. Meant for the owner's own development and demo databases. Returns a
    line per tree saying what was done. Raises `MigrationError`, listing every difference, if any tree does not match."""
    locs = list(locations) if locations is not None else all_locations()
    notes: list[str] = []
    with migration_lock(engine):
        stamps: list[tuple[MigrationLocation, str]] = []
        problems: list[str] = []
        with engine.connect() as conn:
            for loc in locs:
                state = inspect_tree(conn, loc)
                if state.status == "ahead":
                    raise MigrationError(_refusal(state) or "")
                if state.status == "fresh":
                    notes.append(f"{loc.name}: no tables, nothing to stamp (`kresheen db upgrade` creates them)")
                    continue
                if state.status != "unversioned":
                    notes.append(f"{loc.name}: already versioned at {state.current}, left alone")
                    continue
                base = baseline_revision(loc)
                if base != state.head:
                    raise MigrationError(
                        f"The {loc.name} schema has moved past its baseline ({base} -> {state.head}), so the live "
                        "tables cannot be checked against the baseline alone. Stamp with the release that matches "
                        "the database, then upgrade."
                    )
                diffs = schema_differences(conn, loc)
                if diffs:
                    problems.append(f"{loc.name}:\n  " + "\n  ".join(diffs))
                else:
                    stamps.append((loc, base))
        if problems:
            raise MigrationError(
                "Not stamping: the database schema does not match the baseline. Differences (model vs database):\n"
                + "\n".join(problems)
            )
        for loc, base in stamps:
            with engine.connect() as conn:
                command.stamp(_config(loc, conn), base)
                conn.commit()
            notes.append(f"{loc.name}: schema matches, stamped {base}")
    return notes


def history(location: MigrationLocation) -> list[tuple[str, str]]:
    """(revision, first line of its description), newest first."""
    return [
        (rev.revision, (rev.doc or "").strip().splitlines()[0] if rev.doc else "")
        for rev in _script(location).walk_revisions()
    ]
