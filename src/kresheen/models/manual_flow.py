"""ManualFlow: a user-drawn connection between two DFD components,
overlaid on top of whichever run is currently being viewed.

`source_ref`/`target_ref` use a small tagged-string convention rather than
referencing a specific run's Asset id directly (which would silently
break the moment the Application is re-scanned, since facts/Assets get
fresh ids every run by design -- see models/trust_boundary.py's docstring
for the same reasoning):

- `"asset:<id>"` -- a specific *manual* Asset (source="manual"), whose id
  is stable forever: manual Assets are never touched by a run's
  regenerate-in-place delete (see storage/sql_repo.py's
  `replace_assets_for_run`, which only deletes rows matching that exact
  `run_id`; a manual Asset's `run_id` is always `None`).
- `"name:<component name>"` -- resolved fresh against whichever run's
  live Assets are being viewed, by exact `name` match. If no asset in
  that run has that name (e.g. a later re-scan renamed or dropped the
  component), the edge is simply omitted from that run's DFD response,
  not an error -- see dashboard/routes/api_applications.py's
  `get_run_dfd`.

Persisted per Application (not per run), for the same reason
TrustBoundaryAssignment is.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


def new_manual_flow_id() -> str:
    return f"MFLOW-{uuid.uuid4().hex[:16]}"


def name_ref(name: str) -> str:
    return f"name:{name}"


class ManualFlow(BaseModel):
    id: str
    application_id: str
    source_ref: str
    target_ref: str
    label: str | None = None
    created_at: datetime
    updated_at: datetime
