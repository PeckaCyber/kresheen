"""A run's threats with the owner's triage status joined on, and the summary
counts. Shared by the threats route and the report exporters (reporting/)."""

from __future__ import annotations

from kresheen.engine.threats.cache import cache_for
from kresheen.engine.threats.coverage import check_coverage
from kresheen.engine.threats.doc_conflicts import check_doc_conflicts
from kresheen.engine.threats.methodology import unavailable_methodologies
from kresheen.engine.threats.service import generate_run_threats
from kresheen.models.threat import (
    CoverageGapOut,
    DocConflictOut,
    ThreatOut,
    ThreatsOut,
    ThreatSummary,
)
from kresheen.storage.repository import Repository

SEVERITIES = ("critical", "high", "medium", "low")
STATUSES = ("open", "mitigated", "accepted", "not_applicable")


def build_threats_out(application_id: str, run_id: str, repo: Repository, *, use_cache: bool = True) -> ThreatsOut:
    """Raises UnknownRunError (engine/threats/service.py) for a run that isn't
    this application's.

    `use_cache=False` is for code that reads right after writing in the same request (the cache is invalidated
    only when the request ends), e.g. recording a trend snapshot after a status change."""
    if not use_cache:
        return _build_threats_out(application_id, run_id, repo)
    return cache_for(repo).get_or_compute(
        (application_id, run_id),
        application_id,
        lambda: _build_threats_out(application_id, run_id, repo),
        lambda result: len(result.threats) + 1,  # treated as read-only by every caller
    )


def _build_threats_out(application_id: str, run_id: str, repo: Repository) -> ThreatsOut:
    generated = generate_run_threats(application_id, run_id, repo)
    statuses = {record.threat_key: record for record in repo.list_threat_statuses(application_id)}

    threats: list[ThreatOut] = []
    for threat in generated:
        record = statuses.get(threat.key)
        threats.append(
            ThreatOut(
                **threat.model_dump(),
                status=record.status if record else "open",
                note=record.note if record else "",
                dread=record.dread if record else None,
                status_updated_at=record.updated_at if record else None,
            )
        )

    by_status = {status: 0 for status in STATUSES}
    open_by_severity = {severity: 0 for severity in SEVERITIES}
    open_by_risk = {severity: 0 for severity in SEVERITIES}
    for threat in threats:
        by_status[threat.status] += 1
        if threat.status == "open":
            open_by_severity[threat.severity] += 1
            open_by_risk[threat.risk] += 1
    fact_nodes = repo.list_fact_nodes_for_run(run_id)
    gaps = check_coverage(fact_nodes, repo.list_fact_edges_for_run(run_id))
    conflicts = check_doc_conflicts(fact_nodes)
    application = repo.get_application(application_id)
    return ThreatsOut(
        threats=threats,
        summary=ThreatSummary(
            total=len(threats), by_status=by_status, open_by_severity=open_by_severity, open_by_risk=open_by_risk
        ),
        coverage_gaps=[CoverageGapOut(kind=g.kind, name=g.name, reason=g.reason) for g in gaps],
        doc_conflicts=[DocConflictOut(kind=c.kind, name=c.name, reason=c.reason) for c in conflicts],
        unavailable_methodologies=unavailable_methodologies(application.methodologies) if application else [],
    )
