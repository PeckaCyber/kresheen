"""Diagram: a named, independently-arranged view of one Application's DFD.

All diagrams of an Application share the same underlying facts, run and
threat list (see `engine/dfd/merge.py`'s optional `diagram_id` -- threat
generation always calls it with `diagram_id=None`, i.e. unfiltered).
A diagram only changes what the canvas shows and where things sit on it,
via `DiagramElementLayout` (models/diagram_layout.py). Every Application
has at least one diagram; see `Repository.get_or_create_default_diagram`.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

DEFAULT_DIAGRAM_NAME = "Main"


def new_diagram_id() -> str:
    return f"DIAG-{uuid.uuid4().hex[:16]}"


class Diagram(BaseModel):
    id: str
    application_id: str
    name: str
    created_at: datetime
    updated_at: datetime
