"""ThreatKBEntry: reference threat/weakness knowledge (MITRE ATT&CK, CWE),
plus user-authored custom entries and a Pro-only curated feed.

Storing this reference material is not the concern. What matters is *how the
rule engine retrieves from it*: retrieval must be a relevance query over
a fact's live `attributes`/text (keyword/tag overlap scoring, see
engine/kb/retrieve.py), never a static `node_type`-keyed join. See models/facts.py's docstring for the fuller explanation.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from kresheen.models.threat import Methodology, ThreatElementType, ThreatSeverity


def new_kb_entry_id() -> str:
    return f"KB-{uuid.uuid4().hex[:16]}"


class ThreatKBEntry(BaseModel):
    id: str
    source: Literal["mitre_attack", "cwe", "custom", "kresheen_curated"]
    external_id: str | None = None  # e.g. "T1190", "CWE-79"
    name: str
    description: str
    tags: list[str] = Field(default_factory=list)
    url: str | None = None
    created_by_user_id: str | None = None  # set only for source="custom"
    is_active: bool = True
    # Optional threat-generation fields. Leave `applies_to` unset and the entry
    # is reference-only (still attachable to an element by hand); set it and
    # engine/threats/custom.py turns the entry into a rule that generates a
    # threat on every matching element of every run. `severity`, `category` and
    # `mitigations` shape the generated threat.
    methodology: Methodology = "STRIDE"
    category: str | None = None
    severity: ThreatSeverity = "medium"
    mitigations: list[str] = Field(default_factory=list)
    applies_to: ThreatElementType | None = None
    boundary_hint: str | None = None  # only where the trust boundary label contains this (case-insensitive)
    created_at: datetime
    updated_at: datetime
