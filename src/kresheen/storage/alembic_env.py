"""Shared body of the Alembic `env.py` files (core and plugins).

Each migration tree has its own `env.py`, which only calls `run_env`. The caller (`storage/migrate.py`) hands the
connection, the `MetaData` to compare against and the version-table name in through `config.attributes`; running
`alembic` by hand (see `alembic.ini`) falls back to `KRESHEEN_DB_URL` and the defaults the `env.py` passes in.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from sqlalchemy import MetaData, create_engine


def make_include_object(metadata: MetaData) -> Callable[..., bool]:
    """Autogenerate filter: the database also holds other trees' tables (core, plugins) and their version tables. A
    table this tree does not declare is not this tree's business, so it is never reported as "to be dropped"."""

    def include_object(obj: Any, name: str | None, type_: str, reflected: bool, compare_to: Any) -> bool:
        if type_ == "table" and reflected:
            return name in metadata.tables
        return True

    return include_object


def run_env(context: Any, *, default_metadata: MetaData, default_version_table: str = "alembic_version") -> None:
    config = context.config
    if context.is_offline_mode():
        raise RuntimeError("Offline (SQL script) migrations are not supported; run against a database.")
    metadata: MetaData = config.attributes.get("target_metadata", default_metadata)
    version_table: str = config.attributes.get("version_table", default_version_table)

    def migrate(connection: Any) -> None:
        context.configure(
            connection=connection,
            target_metadata=metadata,
            version_table=version_table,
            render_as_batch=True,  # SQLite cannot ALTER most things in place; batch mode recreates the table
            compare_type=True,
            include_object=make_include_object(metadata),
        )
        with context.begin_transaction():
            context.run_migrations()

    connection = config.attributes.get("connection")
    if connection is not None:
        migrate(connection)
        return
    engine = create_engine(os.environ.get("KRESHEEN_DB_URL", "sqlite:///kresheen.db"))
    try:
        with engine.connect() as conn:
            migrate(conn)
            conn.commit()
    finally:
        engine.dispose()
