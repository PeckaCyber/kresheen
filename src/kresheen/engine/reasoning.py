"""Rule-based reasoning stage: facts graph -> findings, with no LLM call.

Each check below is an independent function over one FactNode's *live*
attributes: policy-as-code, one function per concern. Checks read the current
facts on every run and never a stored association, so they cannot go stale
when the inputs change (see models/facts.py's docstring). The knowledge base
(engine/kb/retrieve.py)
only ever *enriches* a finding a check already decided to raise (extra
citations) -- it never independently decides to raise one. That boundary
matters: a check that raised findings *because* the KB matched would drift
back toward a type-keyed lookup table.
"""

from __future__ import annotations

from kresheen.engine.facts.graph import FactGraph
from kresheen.engine.kb.retrieve import score_kb_entries
from kresheen.models.facts import FactNode
from kresheen.models.finding import Domain, Evidence, Finding, Severity
from kresheen.models.threat_kb import ThreatKBEntry

# `Finding.source_tool` for every finding the rule-based engine produces itself (scanner findings carry the scanner's name).
SOURCE_TOOL = "kresheen"

_SEVERITY_BY_NAME = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

_GRYPE_SEVERITY_BY_NAME = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.INFO,
    "unknown": Severity.INFO,
}

_PURL_SCHEME_TO_LANGUAGE = {
    "npm": "node",
    "pypi": "python",
    "golang": "go",
    "maven": "java",
    "gem": "ruby",
    "composer": "php",
}
"""Maps a CycloneDX purl scheme to the same `language` strings
`github_repository_ingestor.py`'s `_NOTABLE_FILES` already uses on its
`dependency_manifest`/`dependency_lockfile` code_artifact facts, so a
vulnerability can be matched back to the manifest/lockfile responsible for
its ecosystem."""


def _language_from_purl(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    scheme = purl[len("pkg:") :].split("/", 1)[0]
    return _PURL_SCHEME_TO_LANGUAGE.get(scheme)


def _dependency_asset_id_for(node: FactNode, graph: FactGraph) -> str:
    """A vulnerability fact is excluded from the DFD entirely (see
    engine/dfd/derive.py's `_DIAGRAM_WORTHY_NODE_TYPES`) -- attaching its
    Finding to its own id, like every other check in this file does, would
    make the finding unreachable from the diagram. Instead, attach it to
    the dependency-manifest/lockfile code_artifact fact responsible for its
    ecosystem (e.g. a Go CVE attaches to `go.sum`), preferring a lockfile
    over a bare manifest when both exist -- the lockfile is where the exact
    vulnerable version is actually pinned. Two vulnerabilities in the same
    ecosystem both resolve to the same asset_id, so they show up as one
    node with a "(2)" count, not two.

    Falls back to the run's hub `external_entity` node (see
    github_repository_ingestor.py's hub-and-spoke fix) if no matching
    manifest/lockfile fact exists -- shouldn't happen in practice, since
    that ingestor only creates a hub whenever it produces a `vulnerability`
    fact at all, but a defensive fallback beats a silently-orphaned
    finding. If even that's somehow missing (e.g. a hand-built test graph),
    falls back to the vulnerability fact's own id as a last resort -- the
    finding would exist but not be reachable from the diagram, same as
    before this fix, rather than raising.
    """
    language = _language_from_purl(node.attributes.get("purl"))
    lockfile_match: FactNode | None = None
    manifest_match: FactNode | None = None
    hub_match: FactNode | None = None
    for other in graph.nodes_by_id.values():
        if hub_match is None and other.node_type == "external_entity" and other.source_ref == "github_repository":
            hub_match = other
        if language is None or other.node_type != "code_artifact":
            continue
        if other.attributes.get("language") != language:
            continue
        kind = other.attributes.get("kind")
        if kind == "dependency_lockfile":
            lockfile_match = other
        elif kind == "dependency_manifest" and manifest_match is None:
            manifest_match = other
    resolved = lockfile_match or manifest_match or hub_match
    return resolved.id if resolved is not None else node.id


def _host_network_finding(node: FactNode, run_id: str) -> Finding | None:
    if not node.attributes.get("host_network"):
        return None
    return Finding.create(
        domain=Domain.THREAT_MODEL,
        source_tool=SOURCE_TOOL,
        title=f"{node.name} shares the host network namespace",
        description=(
            f"{node.name} runs with hostNetwork enabled, giving it direct access to the "
            "host's network interfaces and removing the network-level isolation other "
            "workloads on the same node rely on."
        ),
        severity=Severity.HIGH,
        asset_id=node.id,
        run_id=run_id,
        evidence=Evidence(stride_category="ElevationOfPrivilege", attack_path=[node.id]),
    )


def _unpinned_image_finding(node: FactNode, run_id: str) -> Finding | None:
    images: list[str] = node.attributes.get("container_images", [])
    unpinned = [img for img in images if img and (img.endswith(":latest") or ":" not in img)]
    if not unpinned:
        return None
    return Finding.create(
        domain=Domain.THREAT_MODEL,
        source_tool=SOURCE_TOOL,
        title=f"{node.name} runs an unpinned container image",
        description=(
            f"{node.name} references {', '.join(unpinned)} without a fixed version tag, so "
            "the exact code running today isn't reproducible or auditable."
        ),
        severity=Severity.MEDIUM,
        asset_id=node.id,
        run_id=run_id,
        evidence=Evidence(stride_category="Tampering", attack_path=[node.id]),
    )


_MANIFEST_CHECKS = (_host_network_finding, _unpinned_image_finding)


def _grype_vulnerability_finding(node: FactNode, graph: FactGraph, run_id: str) -> Finding:
    """Every grype-sourced "vulnerability" FactNode already represents one
    real CVE/GHSA match from a live SBOM scan
    (engine/ingest/github_repository_ingestor.py) -- already-classified
    severity from Grype itself, so this converts directly rather than
    running it through a heuristic check, the same "already classified"
    pattern the other direct converters use. Not KB-enriched for the same
    reason: a real CVE citation is already more
    precise than a heuristic tag-overlap match would add.

    `asset_id` is resolved via `_dependency_asset_id_for` to the real
    dependency-manifest/lockfile fact this vulnerability affects, not the
    vulnerability fact's own id -- see that function's docstring."""
    attrs = node.attributes
    cve_id = attrs.get("cve_id", node.name)
    package = attrs.get("package", "unknown package")
    version = attrs.get("version", "")
    title = f"{cve_id} in {package}@{version}" if version else f"{cve_id} in {package}"
    return Finding.create(
        domain=Domain.VULNERABILITY,
        source_tool=SOURCE_TOOL,
        title=title,
        description=str(attrs.get("description") or title),
        severity=_GRYPE_SEVERITY_BY_NAME.get(str(attrs.get("severity", "unknown")).lower(), Severity.INFO),
        asset_id=_dependency_asset_id_for(node, graph),
        run_id=run_id,
        evidence=Evidence(
            cve_refs=[cve_id] if cve_id else [],
            attack_path=[node.id],
            known_exploited=bool(attrs.get("known_exploited", False)),
            fixed_versions=list(attrs.get("fixed_versions", []) or []),
            fix_state=attrs.get("fix_state"),
            epss_score=attrs.get("epss_score"),
            epss_percentile=attrs.get("epss_percentile"),
        ),
    )


def _enrich_with_kb(finding: Finding, node: FactNode, kb_entries: list[ThreatKBEntry]) -> Finding:
    matches = score_kb_entries(node, kb_entries, top_n=3)
    if not matches:
        return finding
    return finding.model_copy(
        update={
            "evidence": finding.evidence.model_copy(
                update={
                    "mitre_technique_ids": [
                        m.external_id for m in matches if m.source == "mitre_attack" and m.external_id
                    ],
                    "cwe_refs": [m.external_id for m in matches if m.source == "cwe" and m.external_id],
                }
            )
        }
    )


def generate_findings(
    graph: FactGraph,
    kb_entries: list[ThreatKBEntry],
    *,
    run_id: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for node in graph.nodes_by_id.values():
        if node.source_ref == "grype":
            if node.node_type == "vulnerability":
                findings.append(_grype_vulnerability_finding(node, graph, run_id))
            # "sbom_document" nodes carry data for the SBOM view only --
            # they never produce a Finding themselves.
            continue
        for check in _MANIFEST_CHECKS:
            finding = check(node, run_id)
            if finding is not None:
                findings.append(_enrich_with_kb(finding, node, kb_entries))
    return findings
