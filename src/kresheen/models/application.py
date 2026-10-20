"""Application: one system under threat modeling.

Deliberately no cached DFD/report field -- both are always derived fresh
from `latest_run_id`'s facts (see models/facts.py, engine/dfd/derive.py).
Caching a rendered diagram or report blob directly here would create a
persisted "this system's diagram" that can go stale when the facts change.
Keeping it a pointer to a run that gets recomputed from that run's facts
avoids that.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from kresheen.models.threat import Methodology

DEFAULT_METHODOLOGY: Methodology = "STRIDE"


def new_application_id() -> str:
    return f"APP-{uuid.uuid4().hex[:16]}"


class Application(BaseModel):
    id: str
    name: str
    description: str = ""
    owner_user_id: str
    # None = the virtual "Ungrouped" bucket (see models/application_group.py).
    group_id: str | None = None
    status: Literal["draft", "active", "archived"] = "draft"
    latest_run_id: str | None = None
    # Model metadata (Threat Dragon parity): free text, not tied to a platform user account -- a
    # reviewer or contributor need not have (or ever get) a login here.
    # Distinct from owner_user_id, which is attribution (who created this
    # record in this tool), not the system's real-world owner.
    owner: str = ""
    reviewer: str = ""
    contributors: list[str] = Field(default_factory=list)
    # Which threat-generation methodologies are active. Multi-select, STRIDE default-on: STRIDE
    # (and its config-derived SC-Txx rules) is the validated core, so it
    # stays on unless a user explicitly turns it off; a plugin's methodologies
    # are additive lenses. A name the installation no longer offers stays stored and generates nothing.
    # See engine/threats/generate.py's `methodologies` filter.
    methodologies: list[Methodology] = Field(default_factory=lambda: [DEFAULT_METHODOLOGY])
    # "Reviewed" stamp: who last signed off the model and when. A
    # display string (the reviewer's email at the time), so it survives the user being removed.
    reviewed_at: datetime | None = None
    reviewed_by: str = ""
    created_at: datetime
    updated_at: datetime
