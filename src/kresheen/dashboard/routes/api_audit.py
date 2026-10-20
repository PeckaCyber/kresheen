"""Read-only audit log (owner only). See dashboard/audit.py and models/audit.py."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from kresheen.dashboard.audit import max_entries
from kresheen.dashboard.auth import get_current_session, require_owner
from kresheen.dashboard.deps import get_repo
from kresheen.models.audit import AuditEvent
from kresheen.storage.repository import Repository

router = APIRouter(
    prefix="/api/audit-log",
    tags=["audit"],
    dependencies=[Depends(get_current_session), Depends(require_owner)],
)


@router.get("", response_model=list[AuditEvent])
def list_audit_events(
    limit: int = Query(100, ge=1, le=500),
    before: datetime | None = None,
    user_id: str | None = None,
    repo: Repository = Depends(get_repo),
) -> list[AuditEvent]:
    """Newest first. Page backwards by passing the last row's `at` as `before`."""
    return repo.list_audit_events(limit=limit, before=before, user_id=user_id)


class AuditSummary(BaseModel):
    count: int
    max_entries: int


@router.get("/summary", response_model=AuditSummary)
def audit_summary(repo: Repository = Depends(get_repo)) -> AuditSummary:
    """Rows held versus the local cap (`KRESHEEN_AUDIT_MAX_ENTRIES`, default 2000)."""
    return AuditSummary(count=repo.count_audit_events(), max_entries=max_entries())
