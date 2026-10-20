"""Connector contract: push findings/threats to an external system.

A connector pushes (never pulls) and is small: it receives typed
`ExportItem`s already built from a `ThreatModelReport` by the export route.

Push-only for now (see `ConnectorExportRecord`'s docstring) -- a connector
never reads ticket status back.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime
from typing import Literal, Protocol

from pydantic import BaseModel


class ExportResult(BaseModel):
    success: bool
    exported_count: int
    message: str = ""


class ConnectorExportRecord(BaseModel):
    """Tracks one finding/threat already pushed to an external system, so a
    repeat export updates the existing ticket instead of creating a
    duplicate. Push-only for now: `external_key`/`external_url` let the UI
    link out to the ticket, but nothing reads status back from it yet."""

    id: str
    connector_id: str
    application_id: str
    subject_type: Literal["finding", "threat"]
    subject_id: str
    external_key: str
    external_url: str = ""
    exported_at: datetime
    # Hash of the pushed title+description+severity, so a re-export only
    # calls the external API when the content actually changed.
    content_hash: str


class ExportItem(BaseModel):
    """One finding or threat, shaped for an external ticket -- independent of
    `Finding`/`Threat` so a connector never depends on the engine's internal
    models, only on what a ticket actually needs."""

    subject_type: Literal["finding", "threat"]
    subject_id: str
    title: str
    description: str
    severity: str  # critical | high | medium | low | info
    app_url: str = ""  # link back into Kresheen, included in the ticket body


def content_hash(item: ExportItem) -> str:
    """Hash of the fields that would change a pushed ticket's content, so a
    connector can skip re-pushing something unchanged since the last export."""
    return hashlib.sha256(f"{item.title}\n{item.description}\n{item.severity}".encode()).hexdigest()


class BaseConnector(Protocol):
    def push(
        self,
        items: Sequence[ExportItem],
        existing: Sequence[ConnectorExportRecord],
        *,
        connector_id: str,
        application_id: str,
    ) -> tuple[ExportResult, list[ConnectorExportRecord]]:
        """Creates or updates a ticket for each item. `existing` is this
        connector+application's already-pushed records (keyed by
        `subject_id`), used to update rather than duplicate and to skip
        anything whose `content_hash` is unchanged. Returns the push result
        and the full, updated set of export records to persist."""
        ...
