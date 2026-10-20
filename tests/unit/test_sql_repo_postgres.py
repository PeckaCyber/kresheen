"""Postgres-backed SQLRepository tests -- same behavior as the SQLite path
(test_sql_repo.py), run against a real ephemeral Postgres via
testcontainers so the dialect-specific upsert path
(`sqlalchemy.dialects.postgresql.insert`) is actually exercised, not just
assumed to behave like SQLite's. Skipped if Docker isn't reachable, so
contributors without Docker aren't broken.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kresheen.models.finding import Domain, Evidence, Finding, Severity
from kresheen.storage.sql_repo import (
    SQLRepository,
    findings_table,
)

try:
    import docker as _docker

    _docker.from_env().ping()
    _DOCKER_AVAILABLE = True
except Exception:  # noqa: BLE001 -- any failure here just means "skip these tests"
    _DOCKER_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="Docker is not reachable")


@pytest.fixture(scope="module")
def postgres_repo():
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer("postgres:16-alpine", driver="psycopg") as postgres:
        yield SQLRepository(postgres.get_connection_url())


@pytest.fixture(autouse=True)
def _clean_tables(postgres_repo: SQLRepository):
    yield
    with postgres_repo.engine.begin() as conn:
        conn.execute(findings_table.delete())


def _finding() -> Finding:
    return Finding.create(
        domain=Domain.VULNERABILITY,
        source_tool="grype",
        title="t",
        description="d",
        severity=Severity.HIGH,
        asset_id="asset-1",
        evidence=Evidence(cve_refs=["CVE-2021-1"]),
        discovered_at=datetime.now(UTC),
    )


def test_save_and_list_roundtrips(postgres_repo: SQLRepository):
    assert postgres_repo.engine.dialect.name == "postgresql"

    finding = _finding()
    postgres_repo.save_findings([finding])

    loaded = postgres_repo.list_findings()

    assert len(loaded) == 1
    assert loaded[0].id == finding.id
    assert loaded[0].evidence.cve_refs == ["CVE-2021-1"]


def test_upsert_updates_status(postgres_repo: SQLRepository):
    finding = _finding()
    postgres_repo.save_findings([finding])

    resolved = finding.model_copy(update={"status": "resolved"})
    postgres_repo.save_findings([resolved])

    loaded = postgres_repo.get_finding(finding.id)
    assert loaded is not None
    assert loaded.status == "resolved"


def test_filter_by_domain_and_status(postgres_repo: SQLRepository):
    open_finding = _finding()
    resolved_finding = _finding().model_copy(update={"status": "resolved"})
    postgres_repo.save_findings([open_finding, resolved_finding])

    open_only = postgres_repo.list_findings(status="open")
    assert {f.id for f in open_only} == {open_finding.id}
