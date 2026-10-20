"""Diagram lifecycle: every Application always has at least one diagram.

Kept separate from `storage.repository.Repository` (a pure storage
Protocol) since creating the default diagram is a one-time, cross-table
operation: the first time an Application with no `Diagram` rows is asked
for one, this creates a "Main" diagram and backfills its
`DiagramElementLayout` rows from whatever this Application's pre-diagram
state already had saved (manual `Asset.position_x/y`) -- see models/diagram.py and models/diagram_layout.py
docstrings for why that data doesn't just move into the new table outright
(no ALTER TABLE / real migration in this codebase yet)."""

from __future__ import annotations

from datetime import UTC, datetime

from kresheen.models.diagram import DEFAULT_DIAGRAM_NAME, Diagram, new_diagram_id
from kresheen.models.diagram_layout import (
    DiagramElementLayout,
    diagram_element_layout_id,
)
from kresheen.storage.repository import Repository


def get_or_create_default_diagram(application_id: str, repo: Repository) -> Diagram:
    existing = repo.list_diagrams_for_application(application_id)
    if existing:
        return existing[0]
    now = datetime.now(UTC)
    diagram = Diagram(
        id=new_diagram_id(),
        application_id=application_id,
        name=DEFAULT_DIAGRAM_NAME,
        created_at=now,
        updated_at=now,
    )
    repo.save_diagram(diagram)
    _backfill_legacy_layout(application_id, diagram.id, repo)
    return diagram


def _backfill_legacy_layout(application_id: str, diagram_id: str, repo: Repository) -> None:
    now = datetime.now(UTC)

    def _save(key: str, position_x: float, position_y: float) -> None:
        repo.save_diagram_element_layout(
            DiagramElementLayout(
                id=diagram_element_layout_id(diagram_id, key),
                diagram_id=diagram_id,
                element_key=key,
                position_x=position_x,
                position_y=position_y,
                updated_at=now,
            )
        )

    for asset in repo.list_manual_assets_for_application(application_id):
        if asset.position_x is None or asset.position_y is None:
            continue
        _save(f"{asset.type.value}:{asset.name}", asset.position_x, asset.position_y)
