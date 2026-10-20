"""FactNode/FactEdge: the per-run property graph.

Two properties matter here, deliberately:

1. `node_type`/`edge_type` are descriptive vocabulary only -- the same role
   `AssetType` (models/asset.py) already plays. They are never a foreign
   key into a stored threats table, and nothing in this codebase should
   ever branch `if node_type == X: return threats_for[X]` -- that shape is
   a stored generic component-type<->threat-type association, retrieved by
   lookup, which this design avoids. Threat
   knowledge base retrieval (engine/kb/retrieve.py) must instead score
   `ThreatKBEntry` rows against a fact's *live* `attributes`, not its type.

2. Facts are scoped by `run_id` and immutable once written -- re-extracted
   fresh on every "Execute Threat Model," never a durable, incrementally-
   patched "asset catalog" that later gets matched against. Raw ingested
   payloads are cached separately (see `DataSourceConfig.last_ingested_at`)
   so re-ingestion cost doesn't force this to become a persisted, evolving
   store either.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


def new_fact_node_id() -> str:
    return f"FACT-N-{uuid.uuid4().hex[:16]}"


def new_fact_edge_id() -> str:
    return f"FACT-E-{uuid.uuid4().hex[:16]}"


class FactNode(BaseModel):
    id: str
    run_id: str
    application_id: str
    node_type: str
    name: str
    attributes: dict = Field(default_factory=dict)
    source_ref: str
    discovered_at: datetime


class FactEdge(BaseModel):
    id: str
    run_id: str
    application_id: str
    source_node_id: str
    target_node_id: str
    edge_type: str
    attributes: dict = Field(default_factory=dict)
    label: str | None = None
