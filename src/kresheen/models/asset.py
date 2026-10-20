"""Asset: a first-class record backing the map/browse views.

`Finding.asset_id` points at an Asset: the record carries the component's
name, type and trust boundary.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel


class AssetType(str, Enum):
    PROCESS = "process"  # "Booking Website", "Practice Management App"
    DATA_STORE = "data_store"  # "Patient Records DB", "Backup Storage"
    EXTERNAL_ENTITY = "external_entity"  # "Card Processor", "IT Vendor"


def new_manual_asset_id() -> str:
    """Manual Assets (source="manual") need a stable id independent of any
    canonical-asset-id derivation, since they're user-authored, not tool-
    discovered -- see models/trust_boundary.py and models/manual_flow.py for
    why that stability matters (referenced by name/id from persistent,
    Application-scoped overlays that must survive a run's regenerate-in-
    place delete)."""
    return f"MANUAL-{uuid.uuid4().hex[:16]}"


class Asset(BaseModel):
    """`id` reuses the existing canonical asset_id (see
    `AssetAliasResolver.resolve()`) -- no new indirection layer, and no
    stored risk/severity field. Map node color is a query-time rollup over
    `Finding`/`Risk` records sharing that `asset_id`, the same "derive,
    don't duplicate" convention `FindingSummary`'s docstring already
    establishes -- this is what keeps a rendered map honest as "live":
    nothing about risk state is cached or can go stale.
    """

    id: str
    name: str
    type: AssetType
    trust_boundary: str | None = None  # coarse v1 label: "internal" | "internet_facing" | "third_party"
    source: Literal["manual", "threat_model_run"] = "manual"
    org_id: str | None = None  # reserved for multi-tenant; unused/unset in v1
    # Set only for source="threat_model_run": which Application/run this DFD
    # node was derived from. A run's DFD is a mechanical re-projection of
    # that run's FactNode/FactEdge graph (see engine/dfd/derive.py) --
    # scoping by run_id is what lets the Map page render one run's diagram
    # without mixing in another run's or another Application's nodes.
    application_id: str | None = None
    run_id: str | None = None
    # Manual-asset canvas position, set only when a user drags
    # a component onto the DFD at a specific spot. Only meaningful for
    # source="manual" -- those ids are stable across runs, so a saved
    # position keeps meaning on the next scan. Auto-generated
    # (source="threat_model_run") assets get a fresh id every run, so a
    # per-asset position would be silently orphaned each time -- persisting
    # a *stable* layout for auto-generated nodes would need the same
    # name-keyed-override pattern trust_boundary.py already uses, not this
    # field; deliberately out of scope here.
    position_x: float | None = None
    position_y: float | None = None
    created_at: datetime


class AssetFlow(BaseModel):
    """Populated only by DFD-capable sources (Threat Dragon import, or a
    threat-model-engine run, or drawn by hand)."""

    id: str
    source_asset_id: str
    target_asset_id: str
    label: str | None = None
    application_id: str | None = None
    run_id: str | None = None
