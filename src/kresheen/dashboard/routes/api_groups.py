"""Groups (teams) that own several Applications. See models/application_group.py."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from kresheen.dashboard.access import can_view_group, effective_role, require_group_role
from kresheen.dashboard.auth import get_current_session, get_current_user, require_csrf
from kresheen.dashboard.deps import get_repo
from kresheen.engine.provenance import compute_staleness
from kresheen.engine.source_status import has_unanalysed
from kresheen.engine.threats.service import UnknownRunError
from kresheen.engine.threats.view import build_threats_out
from kresheen.models.application import Application
from kresheen.models.application_group import ApplicationGroup, new_group_id
from kresheen.models.user import User
from kresheen.plugins import get_registry
from kresheen.storage.repository import Repository

router = APIRouter(prefix="/api/groups", tags=["groups"], dependencies=[Depends(get_current_session)])

# Mirrors reporting/model.py's _SEVERITY_RANK (module-private there, so
# defined again here rather than reached into across modules).
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class GroupBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)


class RollupOut(BaseModel):
    """Aggregated across a set of Applications' latest runs -- see
    `_compute_rollup`. `finding_count` is every finding the latest run
    produced (the engine has no run-scoped open/resolved distinction), not
    filtered to any particular status."""

    application_count: int
    worst_severity: str | None = None
    finding_count: int = 0
    stale_count: int = 0
    # Threats are derived per run, not stored, so these are computed live from
    # each application's latest run. Without them a
    # hand-drawn model with dozens of open threats read as "no findings".
    open_threat_count: int = 0
    worst_threat_risk: str | None = None
    # Applications whose latest run stored an input it could not analyse.
    not_analysed_count: int = 0


class GroupOut(BaseModel):
    id: str
    name: str
    description: str
    created_at: datetime
    rollup: RollupOut
    # The caller's role in this group: what the UI uses to show/hide controls.
    my_role: str | None = None


class GroupListOut(BaseModel):
    groups: list[GroupOut]
    # Applications with no group_id -- the virtual "Ungrouped" bucket has no
    # row, so its rollup travels alongside the real groups.
    ungrouped: RollupOut
    # Every application regardless of group -- derived by combining the
    # per-group and ungrouped rollups already computed, not a second pass.
    overall: RollupOut


def _get_group_or_404(group_id: str, repo: Repository) -> ApplicationGroup:
    group = repo.get_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Unknown group")
    return group


def _clean_name(body: GroupBody, repo: Repository, *, except_id: str | None = None) -> str:
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Group name cannot be blank")
    # Two groups differing only by case would be indistinguishable in the UI.
    if any(g.name.casefold() == name.casefold() and g.id != except_id for g in repo.list_groups()):
        raise HTTPException(status_code=409, detail="A group with that name already exists")
    return name


def _compute_rollup(applications: list[Application], repo: Repository) -> RollupOut:
    worst: str | None = None
    finding_count = 0
    stale_count = 0
    open_threats = 0
    worst_risk: str | None = None
    not_analysed = 0
    for application in applications:
        run = repo.get_run(application.latest_run_id) if application.latest_run_id else None
        if run is not None:
            if has_unanalysed(run.source_results):
                not_analysed += 1
            try:
                summary = build_threats_out(application.id, run.id, repo).summary
            except UnknownRunError:
                summary = None
            if summary is not None:
                open_threats += summary.by_status.get("open", 0)
                for risk, count in summary.open_by_risk.items():
                    if count and (worst_risk is None or _SEVERITY_RANK.get(risk, 9) < _SEVERITY_RANK.get(worst_risk, 9)):
                        worst_risk = risk
            for severity, count in run.finding_counts_by_severity.items():
                if not count:
                    continue
                finding_count += count
                if worst is None or _SEVERITY_RANK.get(severity, 9) < _SEVERITY_RANK.get(worst, 9):
                    worst = severity
        if compute_staleness(application, repo).stale:
            stale_count += 1
    return RollupOut(
        application_count=len(applications),
        worst_severity=worst,
        finding_count=finding_count,
        stale_count=stale_count,
        open_threat_count=open_threats,
        worst_threat_risk=worst_risk,
        not_analysed_count=not_analysed,
    )


def _combine_rollups(rollups: list[RollupOut]) -> RollupOut:
    worst: str | None = None
    worst_risk: str | None = None
    for rollup in rollups:
        if rollup.worst_severity is not None and (
            worst is None or _SEVERITY_RANK.get(rollup.worst_severity, 9) < _SEVERITY_RANK.get(worst, 9)
        ):
            worst = rollup.worst_severity
        if rollup.worst_threat_risk is not None and (
            worst_risk is None or _SEVERITY_RANK.get(rollup.worst_threat_risk, 9) < _SEVERITY_RANK.get(worst_risk, 9)
        ):
            worst_risk = rollup.worst_threat_risk
    return RollupOut(
        application_count=sum(r.application_count for r in rollups),
        worst_severity=worst,
        finding_count=sum(r.finding_count for r in rollups),
        stale_count=sum(r.stale_count for r in rollups),
        open_threat_count=sum(r.open_threat_count for r in rollups),
        worst_threat_risk=worst_risk,
        not_analysed_count=sum(r.not_analysed_count for r in rollups),
    )


def _applications_by_group(repo: Repository) -> dict[str | None, list[Application]]:
    by_group: dict[str | None, list[Application]] = {}
    for application in repo.list_applications():
        by_group.setdefault(application.group_id, []).append(application)
    return by_group


def _to_out(
    group: ApplicationGroup, by_group: dict[str | None, list[Application]], repo: Repository, user: User
) -> GroupOut:
    return GroupOut(
        my_role=effective_role(user, group, repo),
        id=group.id,
        name=group.name,
        description=group.description,
        created_at=group.created_at,
        rollup=_compute_rollup(by_group.get(group.id, []), repo),
    )


@router.get("", response_model=GroupListOut)
def list_groups(user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)) -> GroupListOut:
    by_group = _applications_by_group(repo)
    groups = sorted(
        (g for g in repo.list_groups() if can_view_group(user, g, repo)), key=lambda g: g.name.casefold()
    )
    group_outs = [_to_out(g, by_group, repo, user) for g in groups]
    ungrouped = _compute_rollup(by_group.get(None, []), repo)
    return GroupListOut(
        groups=group_outs,
        ungrouped=ungrouped,
        overall=_combine_rollups([g.rollup for g in group_outs] + [ungrouped]),
    )


@router.get("/{group_id}", response_model=GroupOut)
def get_group(group_id: str, user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)) -> GroupOut:
    group = _get_group_or_404(group_id, repo)
    require_group_role(user, group_id, "viewer", repo, what="group")
    return _to_out(group, _applications_by_group(repo), repo, user)


@router.post("", response_model=GroupOut, dependencies=[Depends(require_csrf)])
def create_group(
    body: GroupBody, user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)
) -> GroupOut:
    now = datetime.now(UTC)
    group = ApplicationGroup(
        id=new_group_id(),
        name=_clean_name(body, repo),
        description=body.description.strip(),
        owner_user_id=user.id,
        created_at=now,
        updated_at=now,
    )
    repo.save_group(group)
    return _to_out(group, {}, repo, user)


@router.put("/{group_id}", response_model=GroupOut, dependencies=[Depends(require_csrf)])
def update_group(
    group_id: str, body: GroupBody, user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)
) -> GroupOut:
    group = _get_group_or_404(group_id, repo)
    require_group_role(user, group_id, "admin", repo, what="group")
    group = group.model_copy(
        update={
            "name": _clean_name(body, repo, except_id=group_id),
            "description": body.description.strip(),
            "updated_at": datetime.now(UTC),
        }
    )
    repo.save_group(group)
    return _to_out(group, _applications_by_group(repo), repo, user)


@router.delete("/{group_id}", status_code=204, dependencies=[Depends(require_csrf)])
def delete_group(
    group_id: str, user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)
) -> None:
    """Deleting a group never deletes its applications -- they move to the
    virtual Ungrouped bucket."""
    _get_group_or_404(group_id, repo)
    require_group_role(user, group_id, "admin", repo, what="group")
    for application in repo.list_applications():
        if application.group_id == group_id:
            repo.save_application(application.model_copy(update={"group_id": None}))
    repo.delete_group(group_id)
    get_registry().group_deleted(group_id)
