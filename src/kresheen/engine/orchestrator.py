"""Runs one ThreatModelRun end to end: ingest each of the Application's
DataSourceConfigs -> assemble the facts graph -> rule-based reasoning
(`engine.reasoning.generate_findings`) -> save Findings -> derive and save
the DFD -> mark the run completed.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from kresheen.engine.dfd.derive import derive_dfd
from kresheen.engine.facts.graph import FactGraph
from kresheen.engine.facts.naming import qualify_colliding_names
from kresheen.engine.ingest.architecture_diagram_ingestor import ArchitectureDiagramIngestor
from kresheen.engine.ingest.base import SourceIngestor
from kresheen.engine.ingest.documentation_ingestor import DocumentationIngestor
from kresheen.engine.ingest.github_repository_ingestor import GithubRepositoryIngestor
from kresheen.engine.ingest.manifest_ingestor import ManifestUploadIngestor
from kresheen.engine.provenance import engine_version, input_digest, rule_catalog_version
from kresheen.engine.reasoning import generate_findings
from kresheen.engine.run_safety import (
    data_source_label,
    safe_run_error,
    save_run_reliably,
    source_run_error,
)
from kresheen.engine.source_status import classify_source
from kresheen.engine.trend import record_snapshot
from kresheen.models.facts import FactEdge, FactNode
from kresheen.secrets.github_token import resolve_token, secure_legacy_token, strip_token_keys
from kresheen.storage.repository import Repository

logger = logging.getLogger(__name__)

_INGESTORS: dict[str, type[SourceIngestor]] = {
    "manifest_upload": ManifestUploadIngestor,
    "github_repository": GithubRepositoryIngestor,
    "architecture_diagram": ArchitectureDiagramIngestor,
    "documentation": DocumentationIngestor,
}

SUPPORTED_DATA_SOURCE_TYPES: frozenset[str] = frozenset(_INGESTORS)
"""The single source of truth for which `DataSourceConfig.type` values can
actually be ingested right now. `dashboard/routes/api_applications.py`'s
`create_data_source` validates against this instead of its own hardcoded
list, so the two cannot drift apart."""


def execute_run(repo: Repository, run_id: str) -> None:
    run = repo.get_run(run_id)
    if run is None:
        raise ValueError(f"Unknown run: {run_id}")

    run.status = "ingesting"
    repo.save_run(run)

    reading_source: str | None = None  # label of the data source being read, for the failure message
    try:
        all_nodes: list[FactNode] = []
        all_edges: list[FactEdge] = []
        for data_source_id in run.data_source_config_ids:
            data_source = repo.get_data_source(data_source_id)
            if data_source is None:
                logger.warning("Run %s references unknown data source %s", run.id, data_source_id)
                continue
            ingestor_cls = _INGESTORS.get(data_source.type)
            if ingestor_cls is None:
                logger.warning("No ingestor registered for data source type %s", data_source.type)
                continue
            reading_source = data_source_label(data_source.type, data_source.connection_details)
            if data_source.type == "github_repository":
                secure_legacy_token(repo, data_source)
            connection_details = data_source.connection_details
            if data_source.type == "github_repository":
                # The ingestor takes the token as a plain detail; it is resolved here, in memory only, and the
                # stored row keeps just the reference.
                connection_details = strip_token_keys(connection_details)
                token = resolve_token(repo, data_source)
                if token:
                    connection_details["github_token"] = token
            if run.source_ref and data_source.type == "github_repository":
                # Per-run override (CI scanning a PR's commit); never written back to the data source.
                connection_details = {**connection_details, "ref": run.source_ref}
            nodes, edges = ingestor_cls().run(
                run_id=run.id,
                application_id=run.application_id,
                connection_details=connection_details,
            )
            all_nodes.extend(nodes)
            all_edges.extend(edges)
            data_source.last_ingested_at = datetime.now(UTC)
            repo.save_data_source(data_source)
            run.input_digests[data_source_id] = input_digest(data_source)
            run.source_results.append(classify_source(data_source_id, data_source.type, nodes))
            reading_source = None

        qualify_colliding_names(all_nodes)
        repo.save_fact_nodes(all_nodes)
        repo.save_fact_edges(all_edges)

        run.status = "reasoning"
        repo.save_run(run)

        graph = FactGraph.build(all_nodes, all_edges)
        kb_entries = repo.list_kb_entries()
        findings = generate_findings(graph, kb_entries, run_id=run.id)
        repo.save_findings(findings)

        assets, flows = derive_dfd(all_nodes, all_edges)
        repo.replace_assets_for_run(run.id, assets)
        repo.replace_asset_flows_for_run(run.id, flows)

        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1

        run.finding_counts_by_severity = counts
        run.engine_version = engine_version()
        run.rule_catalog_version = rule_catalog_version()
        run.status = "completed"
        run.completed_at = datetime.now(UTC)
        repo.save_run(run)
        record_snapshot(repo, run.application_id)  # D3: never fails the run (record_snapshot logs and swallows)
    except Exception as exc:
        logger.exception("Threat model run %s failed", run.id)
        run.status = "failed"
        run.error_message = (
            source_run_error(reading_source, exc) if reading_source else safe_run_error(exc)
        )  # never the raw text: SQL, parameters and server paths stay in the log
        run.completed_at = datetime.now(UTC)
        save_run_reliably(repo, run)
        raise
