"""SQLAlchemy-backed Repository -- SQLite or Postgres, same class.

Each record type is stored as a JSON blob (the Pydantic model, serialized)
alongside a handful of indexed columns used for filtering. This is a
document-store-over-SQL approach deliberately kept simple: the normalized
schema is still expected to evolve, and full relational normalization would
be premature.

One class, not `SQLiteRepository` + `PostgresRepository`: both dialects'
`insert(...).on_conflict_do_update(index_elements=..., set_=...)` calls have
the identical shape, so the only dialect-specific piece is which `insert`
function to use -- picked at runtime from `engine.dialect.name`. This keeps
SQLite fully working for local dev and fast tests (just a `sqlite:///...`
URL) while Postgres (`postgresql+psycopg://...`) is the real target for a
k8s deployment, with zero duplicated CRUD logic between them.

Schema evolution: the tables are built and upgraded by Alembic (`storage/migrate.py`, revisions in
`storage/migrations/versions/`), never by `create_all`. Any change to a table below (a column, an index, a new
table) needs a new revision in the same change; a test fails when the models and the migrations disagree. Reshaping a
field inside a JSON `data` blob needs a data migration that rewrites the stored rows (see docs/upgrading.md).
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    MetaData,
    String,
    Table,
    create_engine,
    event,
    false,
    func,
    not_,
    or_,
    select,
)
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine

from kresheen.models.action_plan import ActionStatusRecord
from kresheen.models.agent_config import AgentConfig
from kresheen.models.application import Application
from kresheen.models.application_group import ApplicationGroup
from kresheen.models.asset import Asset, AssetFlow
from kresheen.models.audit import AuditEvent
from kresheen.models.auth import ApiToken, Session
from kresheen.models.data_source import DataSourceConfig
from kresheen.models.diagram import Diagram
from kresheen.models.diagram_layout import DiagramElementLayout
from kresheen.models.element_properties import ElementPropertiesRecord
from kresheen.models.facts import FactEdge, FactNode
from kresheen.models.finding import Domain, Finding
from kresheen.models.manual_flow import ManualFlow
from kresheen.models.snapshot import ThreatSnapshot
from kresheen.models.threat import ManualThreat, ThreatStatusRecord
from kresheen.models.threat_kb import ThreatKBEntry
from kresheen.models.threat_model_run import ThreatModelRun
from kresheen.models.trust_boundary import TrustBoundaryAssignment
from kresheen.models.user import User
from kresheen.plugins import get_registry
from kresheen.storage.migrate import upgrade_to_head

metadata = MetaData()

findings_table = Table(
    "findings",
    metadata,
    Column("id", String, primary_key=True),
    Column("domain", String, index=True),
    Column("status", String, index=True),
    Column("asset_id", String, index=True),
    Column("source_tool", String, index=True),
    # Mirrors of fields inside `data`, promoted to real columns so queries can
    # filter on them without fetching every finding's full JSON blob.
    Column("discovered_at", DateTime(timezone=True), index=True),
    # Set only for engine-produced findings -- lets the Application-run
    # detail page fetch just that run's findings without an in-memory filter.
    Column("run_id", String, index=True),
    Column("data", JSON),
)





users_table = Table(
    "users",
    metadata,
    Column("id", String, primary_key=True),
    Column("email", String, index=True, unique=True),
    Column("data", JSON),
)

sessions_table = Table(
    "sessions",
    metadata,
    Column("id", String, primary_key=True),
    # Promoted out of `data` so expired rows can be filtered/pruned without
    # deserializing every session -- same reasoning as findings_table's
    # promoted columns above.
    Column("expires_at", DateTime(timezone=True), index=True),
    Column("user_id", String, index=True),
    Column("data", JSON),
)

api_tokens_table = Table(
    "api_tokens",
    metadata,
    Column("id", String, primary_key=True),
    Column("token_hash", String, index=True, unique=True),
    Column("user_id", String, index=True),
    Column("data", JSON),
)

audit_events_table = Table(
    "audit_events",
    metadata,
    Column("id", String, primary_key=True),
    Column("at", DateTime(timezone=True), index=True),
    Column("user_id", String, index=True),
    Column("data", JSON),
)

threat_snapshots_table = Table(
    "threat_snapshots",
    metadata,
    Column("id", String, primary_key=True),
    Column("application_id", String, index=True),
    Column("day", String, index=True),
    Column("data", JSON),
)

assets_table = Table(
    "assets",
    metadata,
    Column("id", String, primary_key=True),
    Column("source", String, index=True),
    # Set only for source="threat_model_run" -- see models/asset.py.
    Column("run_id", String, index=True),
    Column("data", JSON),
)

asset_flows_table = Table(
    "asset_flows",
    metadata,
    Column("id", String, primary_key=True),
    Column("run_id", String, index=True),
    Column("data", JSON),
)

applications_table = Table(
    "applications",
    metadata,
    Column("id", String, primary_key=True),
    Column("owner_user_id", String, index=True),
    Column("status", String, index=True),
    Column("data", JSON),
)

data_sources_table = Table(
    "data_source_configs",
    metadata,
    Column("id", String, primary_key=True),
    Column("application_id", String, index=True),
    Column("data", JSON),
)

threat_model_runs_table = Table(
    "threat_model_runs",
    metadata,
    Column("id", String, primary_key=True),
    Column("application_id", String, index=True),
    Column("status", String, index=True),
    Column("data", JSON),
)

fact_nodes_table = Table(
    "fact_nodes",
    metadata,
    Column("id", String, primary_key=True),
    Column("run_id", String, index=True),
    Column("data", JSON),
)

fact_edges_table = Table(
    "fact_edges",
    metadata,
    Column("id", String, primary_key=True),
    Column("run_id", String, index=True),
    Column("data", JSON),
)

kb_entries_table = Table(
    "threat_kb_entries",
    metadata,
    Column("id", String, primary_key=True),
    Column("source", String, index=True),
    Column("is_active", Boolean, index=True),
    Column("data", JSON),
)

application_groups_table = Table(
    "application_groups", metadata,
    Column("id", String, primary_key=True),
    Column("owner_user_id", String, index=True),
    Column("data", JSON),
)

trust_boundary_assignments_table = Table(
    "trust_boundary_assignments",
    metadata,
    Column("id", String, primary_key=True),
    Column("application_id", String, index=True),
    Column("component_name", String, index=True),
    Column("data", JSON),
)

# Legacy table, no longer read or written; it stays because the baseline migration creates it.
trust_boundary_layouts_table = Table(
    "trust_boundary_layouts", metadata,
    Column("id", String, primary_key=True),
    Column("application_id", String, index=True),
    Column("boundary_name", String, index=True),
    Column("data", JSON),
)

manual_flows_table = Table(
    "manual_flows",
    metadata,
    Column("id", String, primary_key=True),
    Column("application_id", String, index=True),
    Column("data", JSON),
)

threat_statuses_table = Table(
    "threat_statuses",
    metadata,
    Column("id", String, primary_key=True),
    Column("application_id", String, index=True),
    Column("threat_key", String, index=True),
    Column("data", JSON),
)

action_statuses_table = Table(
    "action_statuses",
    metadata,
    Column("id", String, primary_key=True),
    Column("application_id", String, index=True),
    Column("action_id", String, index=True),
    Column("data", JSON),
)

manual_threats_table = Table(
    "manual_threats",
    metadata,
    Column("id", String, primary_key=True),
    Column("application_id", String, index=True),
    Column("data", JSON),
)

element_properties_table = Table(
    "element_properties",
    metadata,
    Column("id", String, primary_key=True),
    Column("application_id", String, index=True),
    Column("data", JSON),
)

diagrams_table = Table(
    "diagrams",
    metadata,
    Column("id", String, primary_key=True),
    Column("application_id", String, index=True),
    Column("data", JSON),
)

diagram_element_layouts_table = Table(
    "diagram_element_layouts",
    metadata,
    Column("id", String, primary_key=True),
    Column("diagram_id", String, index=True),
    Column("data", JSON),
)

agent_configs_table = Table(
    "agent_configs",
    metadata,
    Column("id", String, primary_key=True),
    Column("scope", String, index=True),
    Column("scope_id", String, index=True),
    Column("data", JSON),
)

encrypted_secrets_table = Table(
    "encrypted_secrets",
    metadata,
    Column("id", String, primary_key=True),
    Column("owner_scope", String, index=True),
    Column("data", JSON),
)

instance_settings_table = Table(
    "instance_settings",
    metadata,
    Column("key", String, primary_key=True),
    Column("value", JSON),
    Column("updated_at", DateTime(timezone=True)),
    Column("updated_by", String, nullable=True),
)

_INSERT_FN = {
    "sqlite": sqlite_insert,
    "postgresql": postgresql_insert,
}


def _create_engine(url: str) -> Engine:
    """SQLite defaults fail under concurrent writers: a 5 s lock wait, then `database is locked` (a run failed that
    way in testing). Use WAL (readers do not block the writer) and a 30 s busy wait, so writers
    queue instead of failing. WAL keeps `-wal`/`-shm` files beside the database and needs a local filesystem."""
    if not url.startswith("sqlite"):
        return create_engine(url)
    engine = create_engine(url, connect_args={"timeout": 30})
    if ":memory:" in url or url in ("sqlite://", "sqlite:///"):
        return engine

    @event.listens_for(engine, "connect")
    def _tune(dbapi_conn, _record):  # pragma: no cover - exercised by the concurrency test
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()

    return engine


def _restrict_sqlite_file_mode(engine: Engine) -> None:
    """The database holds session hashes, audit rows and encrypted credentials, and is not encrypted at rest, so deploy it on an
    encrypted volume. Keep the SQLite file owner-only so other local users cannot read it.
    Best effort: a read-only or foreign-owned file is left alone."""
    db_path = engine.url.database
    if engine.dialect.name != "sqlite" or not db_path or db_path == ":memory:":
        return
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        pass


class SQLRepository:
    def __init__(self, url: str = "sqlite:///kresheen.db"):
        self.engine: Engine = _create_engine(url)
        upgrade_to_head(self.engine)  # builds, upgrades or refuses; see storage/migrate.py
        get_registry().init_storage(self.engine)  # a plugin adds its own tables; a failing one is logged and skipped
        _restrict_sqlite_file_mode(self.engine)
        # Both dialects' Insert subclasses support on_conflict_do_update/
        # .excluded identically, but only as a dialect-specific extension --
        # mypy only knows the dialect-agnostic base Insert type here.
        self._insert: Any = _INSERT_FN[self.engine.dialect.name]

    # -- Findings -------------------------------------------------------------

    @staticmethod
    def _finding_rows(findings: list[Finding]) -> list[dict]:
        return [
            {
                "id": f.id,
                "domain": f.domain.value,
                "status": f.status,
                "asset_id": f.asset_id,
                "source_tool": f.source_tool,
                "discovered_at": f.discovered_at,
                "run_id": f.run_id,
                "data": f.model_dump(mode="json"),
            }
            for f in findings
        ]

    def save_findings(self, findings: list[Finding]) -> None:
        if not findings:
            return
        stmt = self._insert(findings_table)
        stmt = stmt.on_conflict_do_update(
            index_elements=["id"],
            set_={
                "status": stmt.excluded.status,
                "data": stmt.excluded.data,
            },
        )
        with self.engine.begin() as conn:
            for row in self._finding_rows(findings):
                conn.execute(stmt, row)

    def list_findings(
        self,
        *,
        domain: Domain | None = None,
        status: str | None = None,
        asset_id: str | None = None,
        run_id: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Finding]:
        query = select(findings_table.c.data)
        if domain is not None:
            query = query.where(findings_table.c.domain == domain.value)
        if status is not None:
            query = query.where(findings_table.c.status == status)
        if asset_id is not None:
            query = query.where(findings_table.c.asset_id == asset_id)
        if run_id is not None:
            query = query.where(findings_table.c.run_id == run_id)
        query = query.order_by(findings_table.c.id)
        if limit is not None:
            query = query.limit(limit).offset(offset)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [Finding.model_validate(row[0]) for row in rows]

    def get_finding(self, finding_id: str) -> Finding | None:
        query = select(findings_table.c.data).where(findings_table.c.id == finding_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return Finding.model_validate(row[0]) if row else None

    # -- Users / sessions -------------------------------------------------------

    def save_user(self, user: User) -> None:
        stmt = self._insert(users_table)
        stmt = stmt.on_conflict_do_update(
            index_elements=["id"], set_={"email": stmt.excluded.email, "data": stmt.excluded.data}
        )
        with self.engine.begin() as conn:
            conn.execute(stmt, {"id": user.id, "email": user.email, "data": user.model_dump(mode="json")})

    def get_user(self, user_id: str) -> User | None:
        query = select(users_table.c.data).where(users_table.c.id == user_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return User.model_validate(row[0]) if row else None

    def get_user_by_email(self, email: str) -> User | None:
        # Case-insensitive (new accounts are stored lower-cased, see
        # models/user.py::normalize_email). An exact match wins; if older
        # accounts differ only by case and none matches exactly, the lookup
        # is ambiguous and returns None rather than picking one, so neither
        # a password login nor an SSO email match can land on the wrong one.
        with self.engine.connect() as conn:
            exact = conn.execute(select(users_table.c.data).where(users_table.c.email == email)).fetchone()
            if exact:
                return User.model_validate(exact[0])
            rows = conn.execute(
                select(users_table.c.data).where(func.lower(users_table.c.email) == email.strip().lower())
            ).fetchall()
        return User.model_validate(rows[0][0]) if len(rows) == 1 else None

    def list_users(self) -> list[User]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(users_table.c.data)).fetchall()
        return [User.model_validate(row[0]) for row in rows]

    # Session ids are bearer secrets (they are the cookie value), so only their SHA-256 is stored: a read of the database does not yield usable sessions. The id is high-entropy random, so a fast hash is
    # enough. Callers keep passing and receiving the raw id; the hashing stays inside these methods.
    @staticmethod
    def _session_key(session_id: str) -> str:
        return hashlib.sha256(session_id.encode()).hexdigest()

    def create_session(self, session: Session) -> None:
        stmt = self._insert(sessions_table)
        stored = session.model_copy(update={"id": self._session_key(session.id)})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": stored.id,
                    "expires_at": stored.expires_at,
                    "user_id": stored.user_id,
                    "data": stored.model_dump(mode="json"),
                },
            )

    def get_session(self, session_id: str) -> Session | None:
        query = select(sessions_table.c.data).where(sessions_table.c.id == self._session_key(session_id))
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        if row is None:
            return None
        session = Session.model_validate(row[0]).model_copy(update={"id": session_id})
        if session.expires_at < datetime.now(UTC):
            return None
        return session

    def touch_session(self, session_id: str, last_seen_at: datetime) -> None:
        key = self._session_key(session_id)
        with self.engine.begin() as conn:
            row = conn.execute(select(sessions_table.c.data).where(sessions_table.c.id == key)).fetchone()
            if row is None:
                return
            data = Session.model_validate(row[0]).model_copy(update={"last_seen_at": last_seen_at})
            conn.execute(sessions_table.update().where(sessions_table.c.id == key).values(data=data.model_dump(mode="json")))

    def delete_session(self, session_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(sessions_table.delete().where(sessions_table.c.id == self._session_key(session_id)))

    def delete_sessions_for_user(self, user_id: str, *, keep_session_id: str | None = None) -> None:
        # Used when an owner deactivates an account (`is_active` already
        # blocks the next request; this ends open sessions right away) and
        # after a password change, which keeps only the caller's session.
        condition = sessions_table.c.user_id == user_id
        if keep_session_id is not None:
            condition = condition & (sessions_table.c.id != self._session_key(keep_session_id))
        with self.engine.begin() as conn:
            conn.execute(sessions_table.delete().where(condition))

    def save_api_token(self, token: ApiToken) -> None:
        stmt = self._insert(api_tokens_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": token.id,
                    "token_hash": token.token_hash,
                    "user_id": token.user_id,
                    "data": token.model_dump(mode="json"),
                },
            )

    def get_api_token_by_hash(self, token_hash: str) -> ApiToken | None:
        query = select(api_tokens_table.c.data).where(api_tokens_table.c.token_hash == token_hash)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return ApiToken.model_validate(row[0]) if row else None

    def list_api_tokens_for_user(self, user_id: str) -> list[ApiToken]:
        query = select(api_tokens_table.c.data).where(api_tokens_table.c.user_id == user_id)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return sorted((ApiToken.model_validate(r[0]) for r in rows), key=lambda t: t.created_at)

    def delete_api_token(self, token_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(api_tokens_table.delete().where(api_tokens_table.c.id == token_id))

    def prune_audit_events(self, before: datetime) -> int:
        with self.engine.begin() as conn:
            return conn.execute(audit_events_table.delete().where(audit_events_table.c.at < before)).rowcount

    def save_threat_snapshot(self, snapshot: ThreatSnapshot) -> None:
        stmt = self._insert(threat_snapshots_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": snapshot.id,
                    "application_id": snapshot.application_id,
                    "day": snapshot.day,
                    "data": snapshot.model_dump(mode="json"),
                },
            )

    def list_threat_snapshots(self, since_day: str | None = None) -> list[ThreatSnapshot]:
        """Oldest first. `since_day` is inclusive."""
        query = select(threat_snapshots_table.c.data).order_by(threat_snapshots_table.c.day)
        if since_day is not None:
            query = query.where(threat_snapshots_table.c.day >= since_day)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [ThreatSnapshot.model_validate(r[0]) for r in rows]

    def count_audit_events(self) -> int:
        with self.engine.connect() as conn:
            return int(conn.execute(select(func.count()).select_from(audit_events_table)).scalar_one())

    def trim_audit_events(
        self, keep: int, *, security: bool | None = None, names: frozenset[str] = frozenset(), prefixes: tuple[str, ...] = ()
    ) -> int:
        """Delete the oldest rows beyond the newest `keep`; returns how many went.

        `security=True` considers only rows whose action is in `names` or starts with one of `prefixes`,
        `security=False` only the other rows, `None` all rows. Two separate pools means routine writes (which any
        member can generate in bulk) can never push security events out of the log."""
        action = audit_events_table.c.data["action"].as_string()
        is_security = or_(action.in_(sorted(names)) if names else false(), *(action.like(f"{p}%") for p in prefixes))
        scope = None if security is None else (is_security if security else not_(is_security))
        with self.engine.begin() as conn:
            query = select(audit_events_table.c.at).order_by(audit_events_table.c.at.desc()).offset(keep).limit(1)
            if scope is not None:
                query = query.where(scope)
            cutoff = conn.execute(query).scalar_one_or_none()
            if cutoff is None:
                return 0
            delete = audit_events_table.delete().where(audit_events_table.c.at <= cutoff)
            if scope is not None:
                delete = delete.where(scope)
            return conn.execute(delete).rowcount

    def trim_audit_events_for_action(self, action: str, keep: int) -> int:
        """Keep only the newest `keep` rows of one action. Used so a flood of failed sign-ins cannot push
        every other audit row out of the shared cap."""
        match = audit_events_table.c.data["action"].as_string() == action
        with self.engine.begin() as conn:
            cutoff = conn.execute(
                select(audit_events_table.c.at).where(match).order_by(audit_events_table.c.at.desc()).offset(keep).limit(1)
            ).scalar_one_or_none()
            if cutoff is None:
                return 0
            return conn.execute(audit_events_table.delete().where(match, audit_events_table.c.at <= cutoff)).rowcount

    def add_audit_event(self, event: AuditEvent) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                self._insert(audit_events_table),
                {"id": event.id, "at": event.at, "user_id": event.user_id, "data": event.model_dump(mode="json")},
            )

    def list_audit_events(
        self, *, limit: int = 100, before: datetime | None = None, user_id: str | None = None
    ) -> list[AuditEvent]:
        query = select(audit_events_table.c.data).order_by(audit_events_table.c.at.desc()).limit(limit)
        if before is not None:
            query = query.where(audit_events_table.c.at < before)
        if user_id is not None:
            query = query.where(audit_events_table.c.user_id == user_id)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [AuditEvent.model_validate(r[0]) for r in rows]

    # -- Assets / asset flows -----------------------------------------------

    def get_asset(self, asset_id: str) -> Asset | None:
        query = select(assets_table.c.data).where(assets_table.c.id == asset_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return Asset.model_validate(row[0]) if row else None

    def replace_assets_for_run(self, run_id: str, assets: list[Asset]) -> None:
        """Same regenerate-in-place shape as `replace_assets_for_source`,
        but keyed on `run_id` rather than `source` -- every engine-produced
        Asset shares `source="threat_model_run"`, so deleting by source
        alone would wipe out every other run's/Application's DFD too."""
        stmt = self._insert(assets_table)
        with self.engine.begin() as conn:
            conn.execute(assets_table.delete().where(assets_table.c.run_id == run_id))
            for asset in assets:
                conn.execute(
                    stmt,
                    {
                        "id": asset.id,
                        "source": asset.source,
                        "run_id": asset.run_id,
                        "data": asset.model_dump(mode="json"),
                    },
                )

    def list_assets_for_run(self, run_id: str) -> list[Asset]:
        query = select(assets_table.c.data).where(assets_table.c.run_id == run_id)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [Asset.model_validate(row[0]) for row in rows]

    def replace_asset_flows_for_run(self, run_id: str, flows: list[AssetFlow]) -> None:
        stmt = self._insert(asset_flows_table)
        with self.engine.begin() as conn:
            conn.execute(asset_flows_table.delete().where(asset_flows_table.c.run_id == run_id))
            for flow in flows:
                conn.execute(
                    stmt, {"id": flow.id, "run_id": flow.run_id, "data": flow.model_dump(mode="json")}
                )

    def list_asset_flows_for_run(self, run_id: str) -> list[AssetFlow]:
        query = select(asset_flows_table.c.data).where(asset_flows_table.c.run_id == run_id)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [AssetFlow.model_validate(row[0]) for row in rows]

    def save_asset(self, asset: Asset) -> None:
        """Single-row upsert -- unlike `replace_assets_for_run`'s
        regenerate-in-place shape, this never deletes sibling rows. Used
        for manual Assets (source="manual"), which are user-authored one
        at a time, not regenerated wholesale by a scan."""
        stmt = self._insert(assets_table)
        stmt = stmt.on_conflict_do_update(
            index_elements=["id"],
            set_={"source": stmt.excluded.source, "run_id": stmt.excluded.run_id, "data": stmt.excluded.data},
        )
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": asset.id,
                    "source": asset.source,
                    "run_id": asset.run_id,
                    "data": asset.model_dump(mode="json"),
                },
            )

    def delete_asset(self, asset_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(assets_table.delete().where(assets_table.c.id == asset_id))

    def list_manual_assets_for_application(self, application_id: str) -> list[Asset]:
        """`assets_table` has no indexed `application_id` column (adding
        one to an existing table needs a real migration -- see this file's
        module docstring), so this filters the manual-source rows in Python.
        Manual assets are user-authored one at a time and expected to be
        few per Application, so a full scan is fine at this scale."""
        query = select(assets_table.c.data).where(assets_table.c.source == "manual")
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [a for a in (Asset.model_validate(row[0]) for row in rows) if a.application_id == application_id]

    # -- Trust boundaries / manual DFD editing -------------------------------

    def save_trust_boundary_assignment(self, assignment: TrustBoundaryAssignment) -> None:
        stmt = self._insert(trust_boundary_assignments_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": assignment.id,
                    "application_id": assignment.application_id,
                    "component_name": assignment.component_name,
                    "data": assignment.model_dump(mode="json"),
                },
            )

    def list_trust_boundary_assignments(self, application_id: str) -> list[TrustBoundaryAssignment]:
        query = select(trust_boundary_assignments_table.c.data).where(
            trust_boundary_assignments_table.c.application_id == application_id
        )
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [TrustBoundaryAssignment.model_validate(row[0]) for row in rows]

    def delete_trust_boundary_assignment(self, assignment_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                trust_boundary_assignments_table.delete().where(
                    trust_boundary_assignments_table.c.id == assignment_id
                )
            )

    def save_manual_flow(self, flow: ManualFlow) -> None:
        stmt = self._insert(manual_flows_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {"id": flow.id, "application_id": flow.application_id, "data": flow.model_dump(mode="json")},
            )

    def list_manual_flows(self, application_id: str) -> list[ManualFlow]:
        query = select(manual_flows_table.c.data).where(manual_flows_table.c.application_id == application_id)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [ManualFlow.model_validate(row[0]) for row in rows]

    def get_manual_flow(self, flow_id: str) -> ManualFlow | None:
        query = select(manual_flows_table.c.data).where(manual_flows_table.c.id == flow_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return ManualFlow.model_validate(row[0]) if row else None

    def delete_manual_flow(self, flow_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(manual_flows_table.delete().where(manual_flows_table.c.id == flow_id))

    # -- Threat triage status ---------------------------------------------------

    def save_threat_status(self, record: ThreatStatusRecord) -> None:
        stmt = self._insert(threat_statuses_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": record.id,
                    "application_id": record.application_id,
                    "threat_key": record.threat_key,
                    "data": record.model_dump(mode="json"),
                },
            )

    def list_threat_statuses(self, application_id: str) -> list[ThreatStatusRecord]:
        query = select(threat_statuses_table.c.data).where(
            threat_statuses_table.c.application_id == application_id
        )
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [ThreatStatusRecord.model_validate(row[0]) for row in rows]

    def delete_threat_status(self, status_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(threat_statuses_table.delete().where(threat_statuses_table.c.id == status_id))

    # -- Action plan status -----------------------------------------------------

    def save_action_status(self, record: ActionStatusRecord) -> None:
        stmt = self._insert(action_statuses_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": record.id,
                    "application_id": record.application_id,
                    "action_id": record.action_id,
                    "data": record.model_dump(mode="json"),
                },
            )

    def list_action_statuses(self, application_id: str) -> list[ActionStatusRecord]:
        query = select(action_statuses_table.c.data).where(action_statuses_table.c.application_id == application_id)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [ActionStatusRecord.model_validate(row[0]) for row in rows]

    def delete_action_status(self, status_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(action_statuses_table.delete().where(action_statuses_table.c.id == status_id))

    def save_manual_threat(self, threat: ManualThreat) -> None:
        stmt = self._insert(manual_threats_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {"id": threat.id, "application_id": threat.application_id, "data": threat.model_dump(mode="json")},
            )

    def list_manual_threats(self, application_id: str) -> list[ManualThreat]:
        query = select(manual_threats_table.c.data).where(manual_threats_table.c.application_id == application_id)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [ManualThreat.model_validate(row[0]) for row in rows]

    def get_manual_threat(self, threat_id: str) -> ManualThreat | None:
        query = select(manual_threats_table.c.data).where(manual_threats_table.c.id == threat_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return ManualThreat.model_validate(row[0]) if row else None

    def delete_manual_threat(self, threat_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(manual_threats_table.delete().where(manual_threats_table.c.id == threat_id))

    def save_element_properties(self, record: ElementPropertiesRecord) -> None:
        stmt = self._insert(element_properties_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {"id": record.id, "application_id": record.application_id, "data": record.model_dump(mode="json")},
            )

    def list_element_properties(self, application_id: str) -> list[ElementPropertiesRecord]:
        query = select(element_properties_table.c.data).where(
            element_properties_table.c.application_id == application_id
        )
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [ElementPropertiesRecord.model_validate(row[0]) for row in rows]

    def delete_element_properties(self, record_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(element_properties_table.delete().where(element_properties_table.c.id == record_id))

    # -- Diagrams (multiple DFD views per Application) -----------------------

    def save_diagram(self, diagram: Diagram) -> None:
        stmt = self._insert(diagrams_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {"id": diagram.id, "application_id": diagram.application_id, "data": diagram.model_dump(mode="json")},
            )

    def get_diagram(self, diagram_id: str) -> Diagram | None:
        query = select(diagrams_table.c.data).where(diagrams_table.c.id == diagram_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return Diagram.model_validate(row[0]) if row else None

    def list_diagrams_for_application(self, application_id: str) -> list[Diagram]:
        query = select(diagrams_table.c.data).where(diagrams_table.c.application_id == application_id)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return sorted((Diagram.model_validate(row[0]) for row in rows), key=lambda d: d.created_at)

    def delete_diagram(self, diagram_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(diagrams_table.delete().where(diagrams_table.c.id == diagram_id))
            conn.execute(
                diagram_element_layouts_table.delete().where(
                    diagram_element_layouts_table.c.diagram_id == diagram_id
                )
            )

    def save_diagram_element_layout(self, layout: DiagramElementLayout) -> None:
        stmt = self._insert(diagram_element_layouts_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {"id": layout.id, "diagram_id": layout.diagram_id, "data": layout.model_dump(mode="json")},
            )

    def list_diagram_element_layouts(self, diagram_id: str) -> list[DiagramElementLayout]:
        query = select(diagram_element_layouts_table.c.data).where(
            diagram_element_layouts_table.c.diagram_id == diagram_id
        )
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [DiagramElementLayout.model_validate(row[0]) for row in rows]

    def delete_diagram_element_layout(self, layout_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                diagram_element_layouts_table.delete().where(diagram_element_layouts_table.c.id == layout_id)
            )

    # -- Applications / data sources / runs ----------------------------------

    def save_application(self, application: Application) -> None:
        stmt = self._insert(applications_table)
        stmt = stmt.on_conflict_do_update(
            index_elements=["id"],
            set_={"status": stmt.excluded.status, "data": stmt.excluded.data},
        )
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": application.id,
                    "owner_user_id": application.owner_user_id,
                    "status": application.status,
                    "data": application.model_dump(mode="json"),
                },
            )

    def get_application(self, application_id: str) -> Application | None:
        query = select(applications_table.c.data).where(applications_table.c.id == application_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return Application.model_validate(row[0]) if row else None

    def list_applications(self) -> list[Application]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(applications_table.c.data)).fetchall()
        return [Application.model_validate(row[0]) for row in rows]

    def save_group(self, group: ApplicationGroup) -> None:
        stmt = self._insert(application_groups_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(stmt, {"id": group.id, "owner_user_id": group.owner_user_id,
                "data": group.model_dump(mode="json")})

    def get_group(self, group_id: str) -> ApplicationGroup | None:
        query = select(application_groups_table.c.data).where(application_groups_table.c.id == group_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return ApplicationGroup.model_validate(row[0]) if row else None

    def list_groups(self) -> list[ApplicationGroup]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(application_groups_table.c.data)).fetchall()
        return [ApplicationGroup.model_validate(row[0]) for row in rows]

    def delete_group(self, group_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(application_groups_table.delete().where(application_groups_table.c.id == group_id))

    def delete_application(self, application_id: str) -> None:
        with self.engine.begin() as conn:
            # Everything a run produced is keyed by run id, so collect the ids before the runs go. Without this the
            # facts, derived assets/flows and trend snapshots of a deleted application stayed in the database
            # forever: wasted space, "deleted" data that was not, and more rows in the
            # id space.
            run_ids = [
                row[0]
                for row in conn.execute(
                    select(threat_model_runs_table.c.id).where(threat_model_runs_table.c.application_id == application_id)
                ).fetchall()
            ]
            for chunk_start in range(0, len(run_ids), 500):
                chunk = run_ids[chunk_start : chunk_start + 500]
                conn.execute(fact_nodes_table.delete().where(fact_nodes_table.c.run_id.in_(chunk)))
                conn.execute(fact_edges_table.delete().where(fact_edges_table.c.run_id.in_(chunk)))
                conn.execute(assets_table.delete().where(assets_table.c.run_id.in_(chunk)))
                conn.execute(asset_flows_table.delete().where(asset_flows_table.c.run_id.in_(chunk)))
            conn.execute(  # the application's hand-drawn components (run_id is NULL; the owner is in the JSON)
                assets_table.delete().where(assets_table.c.data["application_id"].as_string() == application_id)
            )
            conn.execute(threat_snapshots_table.delete().where(threat_snapshots_table.c.application_id == application_id))
            conn.execute(applications_table.delete().where(applications_table.c.id == application_id))
            conn.execute(
                data_sources_table.delete().where(data_sources_table.c.application_id == application_id)
            )
            conn.execute(
                threat_model_runs_table.delete().where(
                    threat_model_runs_table.c.application_id == application_id
                )
            )
            conn.execute(
                threat_statuses_table.delete().where(threat_statuses_table.c.application_id == application_id)
            )
            conn.execute(
                action_statuses_table.delete().where(action_statuses_table.c.application_id == application_id)
            )
            conn.execute(
                manual_threats_table.delete().where(manual_threats_table.c.application_id == application_id)
            )
            conn.execute(
                element_properties_table.delete().where(
                    element_properties_table.c.application_id == application_id
                )
            )
            diagram_ids = [
                row[0]
                for row in conn.execute(
                    select(diagrams_table.c.id).where(diagrams_table.c.application_id == application_id)
                ).fetchall()
            ]
            conn.execute(diagrams_table.delete().where(diagrams_table.c.application_id == application_id))
            if diagram_ids:
                conn.execute(
                    diagram_element_layouts_table.delete().where(
                        diagram_element_layouts_table.c.diagram_id.in_(diagram_ids)
                    )
                )

    def save_data_source(self, data_source: DataSourceConfig) -> None:
        stmt = self._insert(data_sources_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": data_source.id,
                    "application_id": data_source.application_id,
                    "data": data_source.model_dump(mode="json"),
                },
            )

    def get_data_source(self, data_source_id: str) -> DataSourceConfig | None:
        query = select(data_sources_table.c.data).where(data_sources_table.c.id == data_source_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return DataSourceConfig.model_validate(row[0]) if row else None

    def list_data_source_digests(self, application_id: str) -> list[tuple[str, str | None]]:
        """(id, stored digest or None) per data source without deserialising `connection_details`."""
        query = select(data_sources_table.c.id, data_sources_table.c.data["digest"].as_string()).where(
            data_sources_table.c.application_id == application_id
        )
        with self.engine.connect() as conn:
            return [(row[0], row[1]) for row in conn.execute(query).fetchall()]

    def list_data_sources_for_application(self, application_id: str) -> list[DataSourceConfig]:
        query = select(data_sources_table.c.data).where(
            data_sources_table.c.application_id == application_id
        )
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [DataSourceConfig.model_validate(row[0]) for row in rows]

    def delete_data_source(self, data_source_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(data_sources_table.delete().where(data_sources_table.c.id == data_source_id))

    def save_run(self, run: ThreatModelRun) -> None:
        stmt = self._insert(threat_model_runs_table)
        stmt = stmt.on_conflict_do_update(
            index_elements=["id"], set_={"status": stmt.excluded.status, "data": stmt.excluded.data}
        )
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": run.id,
                    "application_id": run.application_id,
                    "status": run.status,
                    "data": run.model_dump(mode="json"),
                },
            )

    def get_run(self, run_id: str) -> ThreatModelRun | None:
        query = select(threat_model_runs_table.c.data).where(threat_model_runs_table.c.id == run_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return ThreatModelRun.model_validate(row[0]) if row else None

    def list_runs_with_status(self, statuses: tuple[str, ...]) -> list[ThreatModelRun]:
        query = select(threat_model_runs_table.c.data).where(threat_model_runs_table.c.status.in_(statuses))
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [ThreatModelRun.model_validate(r[0]) for r in rows]

    def list_runs_for_application(self, application_id: str) -> list[ThreatModelRun]:
        query = select(threat_model_runs_table.c.data).where(
            threat_model_runs_table.c.application_id == application_id
        )
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        # started_at lives in the JSON blob, not a promoted/indexed column, so
        # chronological order isn't guaranteed by the query -- sort here. Run
        # history and the diff endpoint's "immediately preceding run" lookup
        # both depend on this.
        runs = [ThreatModelRun.model_validate(row[0]) for row in rows]
        return sorted(runs, key=lambda r: r.started_at)

    # -- Facts ------------------------------------------------------------------

    def save_fact_nodes(self, nodes: list[FactNode]) -> None:
        if not nodes:
            return
        stmt = self._insert(fact_nodes_table)
        with self.engine.begin() as conn:
            for node in nodes:
                conn.execute(
                    stmt, {"id": node.id, "run_id": node.run_id, "data": node.model_dump(mode="json")}
                )

    def save_fact_edges(self, edges: list[FactEdge]) -> None:
        if not edges:
            return
        stmt = self._insert(fact_edges_table)
        with self.engine.begin() as conn:
            for edge in edges:
                conn.execute(
                    stmt, {"id": edge.id, "run_id": edge.run_id, "data": edge.model_dump(mode="json")}
                )

    def list_fact_nodes_for_run(self, run_id: str) -> list[FactNode]:
        query = select(fact_nodes_table.c.data).where(fact_nodes_table.c.run_id == run_id)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [FactNode.model_validate(row[0]) for row in rows]

    def list_fact_edges_for_run(self, run_id: str) -> list[FactEdge]:
        query = select(fact_edges_table.c.data).where(fact_edges_table.c.run_id == run_id)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [FactEdge.model_validate(row[0]) for row in rows]

    # -- Threat knowledge base ----------------------------------------------

    def save_kb_entries(self, entries: list[ThreatKBEntry]) -> None:
        if not entries:
            return
        stmt = self._insert(kb_entries_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            for entry in entries:
                conn.execute(
                    stmt,
                    {
                        "id": entry.id,
                        "source": entry.source,
                        "is_active": entry.is_active,
                        "data": entry.model_dump(mode="json"),
                    },
                )

    def list_kb_entries(self, *, source: str | None = None) -> list[ThreatKBEntry]:
        query = select(kb_entries_table.c.data)
        if source is not None:
            query = query.where(kb_entries_table.c.source == source)
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [ThreatKBEntry.model_validate(row[0]) for row in rows]

    def get_kb_entry(self, entry_id: str) -> ThreatKBEntry | None:
        query = select(kb_entries_table.c.data).where(kb_entries_table.c.id == entry_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return ThreatKBEntry.model_validate(row[0]) if row else None

    def delete_kb_entry(self, entry_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(kb_entries_table.delete().where(kb_entries_table.c.id == entry_id))

    # -- AI assist config ------------------------------

    def save_agent_config(self, agent_config: AgentConfig) -> None:
        stmt = self._insert(agent_configs_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": agent_config.id,
                    "scope": agent_config.scope,
                    "scope_id": agent_config.scope_id,
                    "data": agent_config.model_dump(mode="json"),
                },
            )

    def get_agent_config(self, scope: str, scope_id: str) -> AgentConfig | None:
        query = select(agent_configs_table.c.data).where(
            agent_configs_table.c.scope == scope, agent_configs_table.c.scope_id == scope_id
        )
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return AgentConfig.model_validate(row[0]) if row else None

    # -- Secrets ------------------------------------------------------------

    def save_secret_blob(self, ref: str, ciphertext: bytes, owner_scope: str) -> None:
        stmt = self._insert(encrypted_secrets_table)
        stmt = stmt.on_conflict_do_update(index_elements=["id"], set_={"data": stmt.excluded.data})
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                {
                    "id": ref,
                    "owner_scope": owner_scope,
                    "data": {"ciphertext": ciphertext.decode("ascii")},
                },
            )

    def get_secret_blob(self, ref: str) -> bytes | None:
        query = select(encrypted_secrets_table.c.data).where(encrypted_secrets_table.c.id == ref)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        if row is None:
            return None
        return row[0]["ciphertext"].encode("ascii")

    def delete_secret_blob(self, ref: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(encrypted_secrets_table.delete().where(encrypted_secrets_table.c.id == ref))

    # -- Instance settings ------------------------------------------------------

    def get_instance_setting(self, key: str) -> Any | None:
        query = select(instance_settings_table.c.value).where(instance_settings_table.c.key == key)
        with self.engine.connect() as conn:
            row = conn.execute(query).fetchone()
        return row[0] if row else None

    def set_instance_setting(self, key: str, value: Any, updated_by: str | None) -> None:
        stmt = self._insert(instance_settings_table)
        stmt = stmt.on_conflict_do_update(
            index_elements=["key"],
            set_={"value": stmt.excluded.value, "updated_at": stmt.excluded.updated_at, "updated_by": stmt.excluded.updated_by},
        )
        with self.engine.begin() as conn:
            conn.execute(stmt, {"key": key, "value": value, "updated_at": datetime.now(UTC), "updated_by": updated_by})
