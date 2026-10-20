"""Owner-stated properties of one DFD element ("this store is encrypted", "this
flow crosses a public network", "this component is out of scope, because...").

Application-scoped and keyed by the element's *name*-based key (`<type>:<name>`
for a component, `flow:<source>-><target>` for a flow), the same key manual
threats and threat statuses use, never by a run's ephemeral asset id. So the
properties survive re-scans, apply to scanned and hand-drawn elements alike, and
reattach if a deleted element is re-created under the same name.

A property that is not present is *unknown* and changes nothing; only an
explicit value affects the generated threats (engine/threats/properties.py
defines which keys exist per element type).
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from pydantic import BaseModel, Field

PropertyValue = bool | str


def element_properties_id(application_id: str, element_key: str) -> str:
    """Deterministic, so saving for the same (application, element) upserts."""
    digest = hashlib.sha256(f"{application_id}\0{element_key}".encode()).hexdigest()[:16]
    return f"EP-{digest}"


class ElementPropertiesRecord(BaseModel):
    id: str
    application_id: str
    element_key: str
    properties: dict[str, PropertyValue] = Field(default_factory=dict)
    updated_by_user_id: str | None = None
    updated_at: datetime
