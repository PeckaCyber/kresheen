"""Action plan: the same open threats pivoted to the fixes that address them
Actions are derived, never stored; only the user's
decision about an action persists (`ActionStatusRecord`)."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

ActionStatusValue = Literal["todo", "in_progress", "done", "wont_do"]
ACTION_STATUSES: tuple[ActionStatusValue, ...] = ("todo", "in_progress", "done", "wont_do")


def action_status_id(application_id: str, action_id: str) -> str:
    digest = hashlib.sha256(f"{application_id}\0{action_id}".encode()).hexdigest()[:16]
    return f"AS-{digest}"


class ActionStatusRecord(BaseModel):
    id: str
    application_id: str
    action_id: str
    status: ActionStatusValue
    # Required when status is wont_do: a declined fix needs a stated reason.
    note: str = ""
    updated_by_user_id: str | None = None
    updated_at: datetime


class ActionOut(BaseModel):
    id: str
    # The fix, worded for a reader. Names the element when only one is affected.
    text: str
    # Sum over the open threats it addresses of risk_score x a tier weight
    # (observed 3, specific 2, generic 1); see engine/action_plan.py. Actions rank by tier first.
    score: int
    max_risk: Literal["critical", "high", "medium", "low"]
    # The strongest tier among its threats: observed = fixes a config-derived (SC-*) finding;
    # specific = fixes a threat backed by a finding or a stated fact; generic = hardening advice.
    basis: Literal["observed", "specific", "generic"]
    threat_count: int
    element_count: int
    elements: list[str]  # capped; element_count is the full number
    cwe_refs: list[str] = Field(default_factory=list)
    # How to check the fix worked and an example fix, gathered from the threats it addresses
    # (from a plugin; empty in the core). Capped; empty when no rule supplies any.
    verification: list[str] = Field(default_factory=list)
    fix_examples: list[str] = Field(default_factory=list)
    threat_keys: list[str]
    status: ActionStatusValue = "todo"
    note: str = ""
    status_updated_at: datetime | None = None


class ActionPlanSummary(BaseModel):
    total: int
    by_status: dict[str, int]
    open_threats_covered: int


class ActionPlanOut(BaseModel):
    actions: list[ActionOut]
    summary: ActionPlanSummary
