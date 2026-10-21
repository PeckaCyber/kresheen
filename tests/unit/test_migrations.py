"""Database migrations, on SQLite and (through testcontainers) Postgres.

Covers the startup rules in `storage/migrate.py`: a fresh install, a restart, an upgrade over a throwaway migration
that adds a column and rewrites JSON blobs in batches, the refusals (newer database, pre-versioning database,
`KRESHEEN_AUTO_MIGRATE=0` when behind), `stamp-baseline`, the SQLite backup and the Postgres advisory lock.
The Postgres cases skip, saying why, when Docker is not reachable.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic.script import ScriptDirectory
from click.testing import CliRunner
from sqlalchemy import create_engine, inspect, text

from kresheen.cli.main import cli
from kresheen.models.application import Application
from kresheen.models.user import User
from kresheen.plugins import MigrationLocation
from kresheen.storage import migrate
from kresheen.storage.migrate import (
    MigrationError,
    backup_sqlite,
    schema_differences,
    upgrade_to_head,
)
from kresheen.storage.sql_repo import SQLRepository, _create_engine, metadata

try:
    import docker as _docker

    _docker.from_env().ping()
    _DOCKER_SKIP = None
except Exception as _exc:  # noqa: BLE001 -- any failure just means "skip the Postgres cases"
    _DOCKER_SKIP = f"Docker is not reachable ({type(_exc).__name__}); the Postgres migration tests need it"

BASELINE = "0001_v1_baseline"


@pytest.fixture(scope="module")
def _postgres_server():
    if _DOCKER_SKIP:
        pytest.skip(_DOCKER_SKIP)
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer("postgres:18-alpine", driver="psycopg") as postgres:
        yield postgres


@pytest.fixture(params=["sqlite", "postgres"])
def db_url(request, tmp_path):
    """A brand-new, empty database on each dialect."""
    if request.param == "sqlite":
        yield f"sqlite:///{tmp_path}/kresheen.db"
        return
    server = request.getfixturevalue("_postgres_server")
    name = f"t_{uuid.uuid4().hex[:12]}"
    base_url = server.get_connection_url()
    admin = create_engine(base_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    yield base_url.rsplit("/", 1)[0] + "/" + name
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
    admin.dispose()


@pytest.fixture
def sqlite_url(tmp_path):
    return f"sqlite:///{tmp_path}/kresheen.db"


@pytest.fixture(autouse=True)
def _auto_migrate_on(monkeypatch):
    monkeypatch.delenv("KRESHEEN_AUTO_MIGRATE", raising=False)


def _engine(url):
    return _create_engine(url)


def _versions(url) -> dict[str, str | None]:
    engine = _engine(url)
    try:
        with engine.connect() as conn:
            tables = inspect(conn).get_table_names()
            return {
                "core": conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
                if "alembic_version" in tables
                else None
            }
    finally:
        engine.dispose()


def _head() -> str:
    return ScriptDirectory.from_config(migrate._config(migrate.core_location())).get_current_head()


def _user(i: int = 1) -> User:
    return User(id=f"U{i}", email=f"u{i}@example.test", password_hash="x", role="owner", created_at=datetime.now(UTC))


def _app(i: int) -> Application:
    now = datetime.now(UTC)
    return Application(
        id=f"APP-{i}", name=f"App {i}", description=f"desc {i}", owner_user_id="U1", created_at=now, updated_at=now
    )


# -- the shipped baseline -----------------------------------------------------------------------------------------


def test_baseline_matches_the_models(db_url):
    """Building from nothing through the migrations gives exactly the schema the models declare (alembic's own
    comparison: tables, columns, types, nullability, indexes, uniqueness)."""
    repo = SQLRepository(db_url)
    with repo.engine.connect() as conn:
        assert schema_differences(conn, migrate.core_location()) == []
        names = set(inspect(conn).get_table_names())
    assert set(metadata.tables) <= names
    assert _versions(db_url)["core"] == _head()


def test_fresh_install_then_restart_is_a_noop(sqlite_url, tmp_path):
    repo = SQLRepository(sqlite_url)
    repo.save_user(_user())
    repo.engine.dispose()
    assert not list(tmp_path.glob("*.bak"))  # nothing existed to protect on a fresh install

    again = SQLRepository(sqlite_url)  # restart
    assert again.get_user("U1") is not None
    assert not list(tmp_path.glob("*.bak"))  # at head: no upgrade, so no backup
    assert [s.status for s in migrate.inspect_all(again.engine)] == ["current"]


def test_migration_runs_log_nothing_when_current(db_url, caplog):
    SQLRepository(db_url)
    caplog.clear()
    with caplog.at_level("INFO", logger="kresheen.storage.migrate"):
        SQLRepository(db_url)
    assert "Upgrading" not in caplog.text


# -- an upgrade over a throwaway migration ------------------------------------------------------------------------

_TEST_MIGRATION = '''
import sqlalchemy as sa
from alembic import op

revision = "0002_test_nickname"
down_revision = "0001_v1_baseline"
branch_labels = None
depends_on = None

BATCH = 2


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("nickname", sa.String(), nullable=True))
    bind = op.get_bind()
    apps = sa.table("applications", sa.column("id", sa.String), sa.column("data", sa.JSON))
    last = ""
    while True:  # rewrite the stored blobs a few rows at a time, keyed on id
        rows = bind.execute(sa.select(apps.c.id, apps.c.data).where(apps.c.id > last).order_by(apps.c.id).limit(BATCH)).all()
        if not rows:
            break
        for row_id, data in rows:
            data = dict(data)
            data["description"] = data["description"] + " (migrated)"
            bind.execute(apps.update().where(apps.c.id == row_id).values(data=data))
        last = rows[-1][0]
'''


@pytest.fixture
def extra_migration(tmp_path, monkeypatch):
    """A copy of the core migration tree plus one more revision, standing in for the next release's migration."""
    tree = tmp_path / "migrations_with_0002"
    shutil.copytree(
        migrate.core_location().script_location, tree, ignore=shutil.ignore_patterns("__pycache__")
    )
    (tree / "versions" / "0002_test_nickname.py").write_text(_TEST_MIGRATION)
    location = MigrationLocation("core", tree, "alembic_version", metadata)
    return location, monkeypatch


def test_upgrade_over_a_data_migration(db_url, extra_migration):
    location, monkeypatch = extra_migration
    before = SQLRepository(db_url)  # a v1.0.0 database, built by the shipped baseline
    before.save_user(_user())
    for i in range(5):
        before.save_application(_app(i))
    before.engine.dispose()

    monkeypatch.setattr(migrate, "core_location", lambda: location)  # "the next release"
    after = SQLRepository(db_url)  # startup upgrades it

    assert _versions(db_url)["core"] == "0002_test_nickname"
    assert "nickname" in {c["name"] for c in inspect(after.engine).get_columns("users")}
    apps = sorted(after.list_applications(), key=lambda a: a.id)
    assert [a.description for a in apps] == [f"desc {i} (migrated)" for i in range(5)]
    assert [a.name for a in apps] == [f"App {i}" for i in range(5)]
    user = after.get_user("U1")
    assert user is not None and user.email == "u1@example.test"


def test_sqlite_upgrade_backs_up_first(sqlite_url, tmp_path, extra_migration):
    location, monkeypatch = extra_migration
    before = SQLRepository(sqlite_url)
    for i in range(3):
        before.save_application(_app(i))
    before.engine.dispose()

    monkeypatch.setattr(migrate, "core_location", lambda: location)
    SQLRepository(sqlite_url)

    backups = list(tmp_path.glob("kresheen.db.pre-*.bak"))
    assert [b.name for b in backups] == ["kresheen.db.pre-0002_test_nickname.bak"]
    assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600
    with sqlite3.connect(backups[0]) as conn:  # the copy is the pre-upgrade state, readable on its own
        assert conn.execute("SELECT count(*) FROM applications").fetchone()[0] == 3
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone()[0] == BASELINE
        assert "nickname" not in [r[1] for r in conn.execute("PRAGMA table_info(users)")]


def test_sqlite_backup_is_consistent_in_wal_mode(sqlite_url, tmp_path):
    repo = SQLRepository(sqlite_url)  # the engine opens the file in WAL mode
    repo.save_application(_app(1))
    with repo.engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        dest = backup_sqlite(tmp_path / "kresheen.db", "wal")  # engine still open, rows possibly only in the -wal file
    with sqlite3.connect(dest) as copy:
        assert copy.execute("SELECT count(*) FROM applications").fetchone()[0] == 1
        assert copy.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_sqlite_keeps_the_last_three_backups(sqlite_url, tmp_path):
    SQLRepository(sqlite_url).engine.dispose()
    db = tmp_path / "kresheen.db"
    made = []
    for i in range(5):
        dest = backup_sqlite(db, f"rev{i}")
        os.utime(dest, (1_000_000 + i, 1_000_000 + i))
        made.append(dest)
    left = sorted(p.name for p in tmp_path.glob("kresheen.db.pre-*.bak"))
    assert left == ["kresheen.db.pre-rev2.bak", "kresheen.db.pre-rev3.bak", "kresheen.db.pre-rev4.bak"]
    assert not list(tmp_path.glob("*.tmp"))


# -- refusals -----------------------------------------------------------------------------------------------------


def test_newer_database_is_refused_and_untouched(db_url):
    SQLRepository(db_url).engine.dispose()
    engine = _engine(db_url)
    with engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = '9999_from_the_future'"))
    engine.dispose()

    with pytest.raises(MigrationError) as err:
        SQLRepository(db_url)

    assert "9999_from_the_future" in str(err.value) and _head() in str(err.value)
    assert _versions(db_url)["core"] == "9999_from_the_future"


def test_database_without_a_version_record_is_refused(db_url):
    engine = _engine(db_url)
    metadata.create_all(engine)  # what the pre-release code did
    engine.dispose()

    with pytest.raises(MigrationError) as err:
        SQLRepository(db_url)

    assert "stamp-baseline" in str(err.value) and "docs/upgrading.md" in str(err.value)
    engine = _engine(db_url)
    assert "alembic_version" not in inspect(engine).get_table_names()  # refusing changed nothing
    engine.dispose()


def test_auto_migrate_off_refuses_when_behind(db_url, extra_migration, monkeypatch):
    location, patcher = extra_migration
    SQLRepository(db_url).engine.dispose()
    patcher.setattr(migrate, "core_location", lambda: location)
    monkeypatch.setenv("KRESHEEN_AUTO_MIGRATE", "0")

    with pytest.raises(MigrationError) as err:
        SQLRepository(db_url)

    assert "kresheen db upgrade" in str(err.value)
    assert _versions(db_url)["core"] == BASELINE  # not changed

    migrate_engine = _engine(db_url)  # the explicit command still works, then startup is happy
    upgrade_to_head(migrate_engine, auto_migrate=True)
    migrate_engine.dispose()
    SQLRepository(db_url)


def test_auto_migrate_off_refuses_an_empty_database(db_url, monkeypatch):
    monkeypatch.setenv("KRESHEEN_AUTO_MIGRATE", "0")
    with pytest.raises(MigrationError, match="kresheen db upgrade"):
        SQLRepository(db_url)


def test_auto_migrate_off_accepts_a_current_database(db_url, monkeypatch):
    SQLRepository(db_url).engine.dispose()
    monkeypatch.setenv("KRESHEEN_AUTO_MIGRATE", "0")
    SQLRepository(db_url)


# -- stamp-baseline -----------------------------------------------------------------------------------------------


def test_stamp_baseline_accepts_a_matching_schema(db_url):
    engine = _engine(db_url)
    metadata.create_all(engine)
    notes = migrate.stamp_baseline(engine, [migrate.core_location()])
    engine.dispose()
    assert any("stamped" in n for n in notes)
    assert _versions(db_url)["core"] == BASELINE
    SQLRepository(db_url)  # and startup now accepts it


def test_stamp_baseline_refuses_a_mismatch_and_lists_it(db_url):
    engine = _engine(db_url)
    metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN stray VARCHAR"))
        conn.execute(text("DROP TABLE diagrams"))
        conn.execute(text("DROP INDEX ix_applications_status"))
    with pytest.raises(MigrationError) as err:
        migrate.stamp_baseline(engine, [migrate.core_location()])
    engine.dispose()
    message = str(err.value)
    assert "stray" in message and "diagrams" in message and "ix_applications_status" in message
    assert _versions(db_url)["core"] is None  # nothing was stamped


# -- Postgres advisory lock ---------------------------------------------------------------------------------------

_LOCK_PROBE = '''
import sqlalchemy as sa
from alembic import op

revision = "0002_probe"
down_revision = "0001_v1_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    held = op.get_bind().execute(sa.text("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted")).scalar()
    op.get_bind().execute(sa.text("CREATE TABLE lock_probe (held integer)"))
    op.get_bind().execute(sa.text("INSERT INTO lock_probe VALUES (:h)"), {"h": held})
'''


def test_postgres_takes_an_advisory_lock_while_migrating(db_url, tmp_path, extra_migration):
    if not db_url.startswith("postgresql"):
        pytest.skip("advisory locks are Postgres only")
    location, _ = extra_migration
    (Path(location.script_location) / "versions" / "0002_test_nickname.py").unlink()
    (Path(location.script_location) / "versions" / "0002_probe.py").write_text(_LOCK_PROBE)
    SQLRepository(db_url).engine.dispose()
    engine = _engine(db_url)
    upgrade_to_head(engine, [location])
    with engine.connect() as conn:
        assert conn.execute(text("SELECT held FROM lock_probe")).scalar() >= 1
        free = conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": migrate._ADVISORY_LOCK_KEY}).scalar()
        assert free  # released afterwards (this very call took it, so it was free)
        conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": migrate._ADVISORY_LOCK_KEY})
    engine.dispose()


def test_postgres_second_migrator_waits_for_the_lock(db_url):
    if not db_url.startswith("postgresql"):
        pytest.skip("advisory locks are Postgres only")
    holder = _engine(db_url)
    other = _engine(db_url)
    done = threading.Event()
    with holder.connect() as conn:
        conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": migrate._ADVISORY_LOCK_KEY})
        conn.commit()

        def run() -> None:
            upgrade_to_head(other, [migrate.core_location()])
            done.set()

        worker = threading.Thread(target=run)
        worker.start()
        time.sleep(1.5)
        assert not done.is_set()  # blocked behind the lock holder
        conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": migrate._ADVISORY_LOCK_KEY})
        conn.commit()
    worker.join(30)
    assert done.is_set()
    holder.dispose()
    other.dispose()


# -- CLI ----------------------------------------------------------------------------------------------------------


def test_db_commands(sqlite_url):
    runner = CliRunner()
    current = runner.invoke(cli, ["db", "current", "--db", sqlite_url])
    assert current.exit_code == 0 and "core: no tables yet" in current.output

    upgrade = runner.invoke(cli, ["db", "upgrade", "--db", sqlite_url])
    assert upgrade.exit_code == 0 and f"core: empty -> {BASELINE}" in upgrade.output

    again = runner.invoke(cli, ["db", "upgrade", "--db", sqlite_url])
    assert "already up to date" in again.output

    current = runner.invoke(cli, ["db", "current", "--db", sqlite_url])
    assert f"core: {BASELINE} (latest)" in current.output

    history = runner.invoke(cli, ["db", "history"])
    assert BASELINE in history.output


def test_db_stamp_baseline_command_and_pre_v1_message(sqlite_url):
    engine = _engine(sqlite_url)
    metadata.create_all(engine)
    engine.dispose()
    runner = CliRunner()

    served = runner.invoke(cli, ["create-user", "--email", "a@example.test", "--db", sqlite_url])
    assert served.exit_code != 0 and "stamp-baseline" in served.output  # a message, not a traceback

    stamped = runner.invoke(cli, ["db", "stamp-baseline", "--db", sqlite_url])
    assert stamped.exit_code == 0 and "stamped" in stamped.output
    assert runner.invoke(cli, ["create-user", "--email", "a@example.test", "--db", sqlite_url]).exit_code == 0
