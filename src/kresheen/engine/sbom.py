"""The SBOM summary for one run, shared by the SBOM route and the report."""

from __future__ import annotations

from typing import Any

from kresheen.storage.repository import Repository


def build_sbom_summary(repo: Repository, run_id: str) -> dict[str, Any] | None:
    """Not every run has one -- only a `github_repository` source with Grype
    installed produces a `sbom_document` fact (see
    engine/ingest/github_repository_ingestor.py). None is a normal state."""
    nodes = repo.list_fact_nodes_for_run(run_id)
    sbom_node = next((node for node in nodes if node.node_type == "sbom_document"), None)
    if sbom_node is None:
        return None
    attrs = sbom_node.attributes
    return {
        "format": attrs.get("format", "cyclonedx-json"),
        "component_count": attrs.get("component_count", 0),
        "vulnerability_count": attrs.get("vulnerability_count", 0),
        "components": attrs.get("components", []),
        "vulnerabilities": attrs.get("vulnerabilities", []),
        "no_lockfile_detected": attrs.get("no_lockfile_detected", False),
        "manifest_files_found": attrs.get("manifest_files_found", []),
    }
