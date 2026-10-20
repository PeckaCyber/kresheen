"""DiagramElementLayout: one diagram's visual state for one DFD element --
whether it's hidden on that diagram's canvas, and (for manual components and
trust-boundary groups) where it's positioned there.

Keyed by `element_key`, the same name-based convention
`ElementPropertiesRecord` already uses (`<type>:<name>` for a component,
`flow:<source name>-><target name>` for a flow), plus a new `boundary:<name>`
form for a trust-boundary group's canvas position. Name-based, not asset-id
based, for the same reason every other Application-scoped overlay is
(models/manual_flow.py's docstring): a run's auto-generated Assets get a
fresh id every execution, so only the name is stable across diagrams and
re-scans.

One row per `(diagram_id, element_key)`, upserted -- same deterministic-id
pattern as `models/element_properties.py`'s `element_properties_id`.
A missing row means "visible, default position" -- absence is never itself
meaningful data, matching `ElementPropertiesRecord`'s "not present = unknown"
convention.
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from pydantic import BaseModel


def boundary_element_key(boundary_name: str) -> str:
    return f"boundary:{boundary_name}"


def diagram_element_layout_id(diagram_id: str, element_key: str) -> str:
    """Deterministic, so saving for the same (diagram, element) upserts."""
    digest = hashlib.sha256(f"{diagram_id}\0{element_key}".encode()).hexdigest()[:16]
    return f"DEL-{digest}"


class DiagramElementLayout(BaseModel):
    id: str
    diagram_id: str
    element_key: str
    hidden: bool = False
    position_x: float | None = None
    position_y: float | None = None
    updated_at: datetime
