"""TrustBoundaryAssignment: a user-authored trust-boundary label for one
named component, persisted per Application (not per run) so it survives
re-execution.

Facts (and the Assets derived from them) get fresh ids every run by
design. The rule engine computes from the live facts on every run and
never stores a catalog, so it cannot go stale when the inputs change. That
means this assignment can't reference a specific run's
ephemeral asset id; it's keyed by the component's stable `name` instead,
and re-applied to whichever run is currently being viewed by
`dashboard/routes/api_applications.py`'s `get_run_dfd` (matching by name,
not id). One row per (application_id, component_name) pair -- reassigning
a component's boundary updates the existing row rather than accumulating
duplicates (see api_applications.py's save route for the upsert-by-key
lookup).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


def new_trust_boundary_assignment_id() -> str:
    return f"TB-{uuid.uuid4().hex[:16]}"


class TrustBoundaryAssignment(BaseModel):
    id: str
    application_id: str
    component_name: str
    trust_boundary: str
    created_at: datetime
    updated_at: datetime
