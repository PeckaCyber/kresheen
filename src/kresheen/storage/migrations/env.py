"""Alembic environment for the core schema. The logic lives in `kresheen.storage.alembic_env`."""

from alembic import context

from kresheen.storage.alembic_env import run_env
from kresheen.storage.sql_repo import metadata

run_env(context, default_metadata=metadata)
