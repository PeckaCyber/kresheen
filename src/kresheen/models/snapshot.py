"""ThreatSnapshot: one application's open threats on one calendar day.

Threats are derived, never stored, so the trend on the dashboard has to be
recorded as it is observed. One row per (application, day), overwritten if
taken again the same day; `open_keys` lets the dashboard say which threats are
new or resolved between two snapshots rather than only how many.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ThreatSnapshot(BaseModel):
    id: str  # f"{application_id}:{day}"
    application_id: str
    day: str  # ISO date, UTC
    taken_at: datetime
    open_keys: list[str] = Field(default_factory=list)
    open_by_risk: dict[str, int] = Field(default_factory=dict)
