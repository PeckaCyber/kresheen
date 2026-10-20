"""Landing-page data: an executive summary of every visible application --
portfolio totals, trend and recent activity -- before drilling into any one
application. A plugin may add sections (`Plugin.dashboard_sections`).

Loading this also records today's `ThreatSnapshot` for each application (see
models/snapshot.py), which is what gives the trend its history (also written
on run completion and threat status changes, see `engine/trend.py::record_snapshot`).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from kresheen.dashboard.access import can_view_group
from kresheen.dashboard.auth import get_current_session, get_current_user
from kresheen.dashboard.deps import get_repo
from kresheen.engine.action_plan import build_action_plan
from kresheen.engine.completeness import assess_completeness
from kresheen.engine.portfolio import (
    ApplicationPortfolioData,
    PortfolioSummary,
    build_portfolio_summary,
)
from kresheen.engine.provenance import compute_staleness
from kresheen.engine.source_status import has_unanalysed
from kresheen.engine.threats.cache import cache_for
from kresheen.engine.threats.service import UnknownRunError, load_derived_dfd_model
from kresheen.engine.threats.view import build_threats_out
from kresheen.engine.trend import TrendPoint, compute_trend, make_snapshot
from kresheen.models.audit import AuditEvent
from kresheen.models.threat import ThreatOut
from kresheen.models.user import User
from kresheen.plugins import get_registry
from kresheen.storage.repository import Repository

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"], dependencies=[Depends(get_current_session)])

_SESSION_ACTIONS = ("auth.login", "auth.logout", "POST /api/auth/login", "POST /api/auth/logout")
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_ADDRESSED_STATUSES = ("mitigated", "accepted", "not_applicable")


class DashboardApplication(BaseModel):
    id: str
    name: str
    group_id: str | None = None
    group_name: str | None = None
    latest_run_id: str | None = None
    worst_severity: str | None = None
    finding_count: int = 0
    open_threat_count: int = 0
    worst_threat_risk: str | None = None
    not_analysed: bool = False
    stale: bool = False
    # Whole days since the latest run completed; None when it never has.
    days_since_run: int | None = None
    # -- Executive summary additions ------------------------------------
    # mitigated + accepted + not_applicable, vs every threat this run generates.
    addressed_count: int = 0
    total_threat_count: int = 0
    open_by_risk: dict[str, int] = Field(default_factory=dict)
    # Key is "<methodology>:<category>".
    open_by_category: dict[str, int] = Field(default_factory=dict)
    # 0-100 (engine/completeness.py); None if there is no run to assess.
    completeness_score: int | None = None
    reviewed_at: datetime | None = None
    # Open (todo/in_progress) action-plan items (engine/action_plan.py); None if there is no run.
    open_action_count: int | None = None


class RecentActivityItem(BaseModel):
    at: datetime
    actor: str | None = None
    action: str
    target: str


class DashboardOut(BaseModel):
    applications: list[DashboardApplication]
    trend: list[TrendPoint]
    summary: PortfolioSummary = Field(default_factory=PortfolioSummary)
    recent_activity: list[RecentActivityItem] = Field(default_factory=list)
    # Extra data from plugins, keyed by plugin name (`Plugin.dashboard_sections`); empty in the core.
    extensions: dict[str, Any] = Field(default_factory=dict)


def _worst(current: str | None, candidate: str) -> str:
    if current is None or _SEVERITY_RANK.get(candidate, 9) < _SEVERITY_RANK.get(current, 9):
        return candidate
    return current


def _open_by_category(threats: list[ThreatOut]) -> dict[str, int]:
    result: dict[str, int] = {}
    for threat in threats:
        if threat.status != "open":
            continue
        key = f"{threat.methodology}:{threat.category or 'Uncategorized'}"
        result[key] = result.get(key, 0) + 1
    return result


def _recent_activity(user: User, repo: Repository) -> list[RecentActivityItem]:
    """Owner only (audit visibility mirrors `api_audit.py`); members see none.
    Never includes request bodies -- audit rows never carry them (models/audit.py)."""
    if user.role != "owner":
        return []
    # Sign-ins and sign-outs would crowd out the changes an executive cares
    # about, so they are left to the full audit log page.
    events: list[AuditEvent] = [
        event for event in repo.list_audit_events(limit=100) if not event.action.startswith(_SESSION_ACTIONS)
    ][:10]
    return [
        RecentActivityItem(
            at=event.at,
            actor=event.user_email or event.user_id,
            action=event.action,
            target=", ".join(f"{k}={v}" for k, v in event.subject.items()),
        )
        for event in events
    ]


def _completeness_and_plan(application_id, run, out, repo):
    """The per-model pieces of a dashboard row that are not the threat list itself. Cached with the same
    invalidation as the threats (action statuses are written under `/api/applications/{id}/...`), so a cold
    dashboard no longer rebuilds every model's DFD and action plan on each load."""

    def compute():
        try:
            elements, flows = load_derived_dfd_model(application_id, run.id, repo)
            score = assess_completeness(elements, flows, run.source_results).score
        except UnknownRunError:
            score = None
        statuses = {r.action_id: r for r in repo.list_action_statuses(application_id)}
        return score, build_action_plan(out.threats, statuses)

    return cache_for(repo).get_or_compute(
        ("dashboard", application_id, run.id),
        application_id,
        compute,
        lambda value: len(value[1].actions) + 1,
    )


@router.get("", response_model=DashboardOut)
def dashboard(
    days: int = Query(90, ge=7, le=365),
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> DashboardOut:
    groups = {g.id: g for g in repo.list_groups()}
    now = datetime.now(UTC)
    rows: list[DashboardApplication] = []
    portfolio_rows: list[ApplicationPortfolioData] = []
    for application in repo.list_applications():
        group = groups.get(application.group_id) if application.group_id else None
        if not can_view_group(user, group, repo):
            continue
        row = DashboardApplication(
            id=application.id,
            name=application.name,
            group_id=application.group_id,
            group_name=group.name if group else None,
            latest_run_id=application.latest_run_id,
            stale=compute_staleness(application, repo).stale,
            reviewed_at=application.reviewed_at,
        )
        portfolio_row = ApplicationPortfolioData(
            application_id=application.id, stale=row.stale, reviewed_at=application.reviewed_at
        )
        run = repo.get_run(application.latest_run_id) if application.latest_run_id else None
        if run is not None:
            row.not_analysed = has_unanalysed(run.source_results)
            if run.completed_at is not None:
                completed = run.completed_at if run.completed_at.tzinfo else run.completed_at.replace(tzinfo=UTC)
                row.days_since_run = max(0, (now - completed).days)
            for severity, count in run.finding_counts_by_severity.items():
                if count:
                    row.finding_count += count
                    row.worst_severity = _worst(row.worst_severity, severity)
            try:
                out = build_threats_out(application.id, run.id, repo)
            except UnknownRunError:
                out = None
            if out is not None:
                open_threats = [t for t in out.threats if t.status == "open"]
                open_keys = [t.key for t in open_threats]
                row.open_threat_count = len(open_keys)
                row.total_threat_count = out.summary.total
                row.addressed_count = sum(out.summary.by_status.get(s, 0) for s in _ADDRESSED_STATUSES)
                row.open_by_risk = dict(out.summary.open_by_risk)
                row.open_by_category = _open_by_category(out.threats)
                for risk, count in out.summary.open_by_risk.items():
                    if count:
                        row.worst_threat_risk = _worst(row.worst_threat_risk, risk)
                repo.save_threat_snapshot(make_snapshot(application.id, open_keys, out.summary.open_by_risk))

                completeness_score, plan = _completeness_and_plan(application.id, run, out, repo)
                row.completeness_score = completeness_score
                closed = plan.summary.by_status.get("done", 0) + plan.summary.by_status.get("wont_do", 0)
                row.open_action_count = plan.summary.total - closed

                portfolio_row = portfolio_row.model_copy(
                    update={
                        "total_threat_count": row.total_threat_count,
                        "addressed_count": row.addressed_count,
                        "open_by_risk": row.open_by_risk,
                        "open_by_category": row.open_by_category,
                        "completeness_score": row.completeness_score,
                        "open_action_count": row.open_action_count,
                    }
                )
        rows.append(row)
        portfolio_rows.append(portfolio_row)

    visible = {r.id for r in rows}
    since = (now - timedelta(days=days)).date().isoformat()
    snapshots = [s for s in repo.list_threat_snapshots(since_day=since) if s.application_id in visible]
    trend = compute_trend(snapshots)
    summary = build_portfolio_summary(portfolio_rows, now)

    result = DashboardOut(
        applications=rows,
        trend=trend,
        summary=summary,
        recent_activity=_recent_activity(user, repo),
    )
    result.extensions = get_registry().dashboard_extensions(repo, user, result)
    return result
