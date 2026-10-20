"""Ingests supplementary documentation (markdown/text) as a single reference
FactNode. Deliberately a thin pass-through, not NLP/parsing -- same honesty
principle as architecture_diagram_ingestor.py's unrecognized-format branch:
the content is stored so it's visible to a run, not deeply understood by
the rule-based analysis.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar

from kresheen.engine.ingest.base import SourceIngestor
from kresheen.models.facts import FactEdge, FactNode, new_fact_node_id

_CONTENT_PREVIEW_CHARS = 2000


class DocumentationIngestor(SourceIngestor):
    source_type: ClassVar[str] = "documentation"

    def fetch(self, *, connection_details: dict | None = None, **kwargs) -> dict:
        details = connection_details or {}
        return {"filename": details.get("filename", ""), "content": details.get("content", "")}

    def parse(self, raw: dict) -> list[dict]:
        return [raw]

    def normalize(
        self, records: list[dict], *, run_id: str, application_id: str
    ) -> tuple[list[FactNode], list[FactEdge]]:
        if not records:
            return [], []
        raw = records[0]
        filename = raw.get("filename", "")
        content = raw.get("content", "")
        node = FactNode(
            id=new_fact_node_id(),
            run_id=run_id,
            application_id=application_id,
            node_type="reference_document",
            name=filename or "uploaded documentation",
            attributes={
                "filename": filename,
                "content": content[:_CONTENT_PREVIEW_CHARS],
                "note": (
                    "supplementary documentation; stored for reference, not parsed by the "
                    "rule-based analysis"
                ),
            },
            source_ref="documentation",
            discovered_at=datetime.now(UTC),
        )
        return [node], []
