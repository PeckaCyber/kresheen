"""Ingests an uploaded architecture diagram file.

The format is sniffed from the content (engine/ingest/diagrams/): OWASP Threat Dragon JSON,
draw.io / diagrams.net XML (plain or compressed), a Mermaid flowchart, or a Threagile model.
Whatever the format, the parsed components and connections become FactNodes and FactEdges,
carrying the trust boundary each sits in and any facts the file states about it (as
`stated_properties`, which the DFD layers under what the owner states by hand).

Anything else (an image, a PDF, prose) doesn't fail: it becomes a single reference FactNode so the
upload stays visible to a run rather than being silently dropped, and the UI reports it as stored
but not analysed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import ClassVar

from kresheen.engine.ingest.base import SourceIngestor
from kresheen.engine.ingest.diagrams import parse_diagram
from kresheen.engine.ingest.diagrams.model import MAX_COMPONENTS, MAX_CONTENT_CHARS, MAX_FLOWS
from kresheen.models.facts import FactEdge, FactNode, new_fact_edge_id, new_fact_node_id


def _why_unreadable(content: object) -> str:
    """A specific reason when we can tell, so the user is not left guessing why a file was only stored."""
    if not isinstance(content, str):
        return ""
    if len(content) > MAX_CONTENT_CHARS:
        return f"The file is larger than the {MAX_CONTENT_CHARS // 1_000_000} MB limit for diagrams."
    if re.search(r"<!(?:DOCTYPE|ENTITY)", content[:20000], re.IGNORECASE):
        return "The file declares an XML DOCTYPE or entity, which is refused for safety (it can be used to attack the reader)."
    return ""


class ArchitectureDiagramIngestor(SourceIngestor):
    source_type: ClassVar[str] = "architecture_diagram"

    def fetch(self, *, connection_details: dict | None = None, **kwargs) -> dict:
        details = connection_details or {}
        return {"filename": details.get("filename", ""), "content": details.get("content", "")}

    def parse(self, raw: dict) -> list[dict]:
        filename = raw.get("filename", "")
        content = raw.get("content", "")
        diagram = parse_diagram(content)
        if diagram is None:
            return [{"_format": "unrecognized", "filename": filename, "reason": _why_unreadable(content)}]
        return [{"_format": diagram.format, "filename": filename, "diagram": diagram}]

    def normalize(
        self, records: list[dict], *, run_id: str, application_id: str
    ) -> tuple[list[FactNode], list[FactEdge]]:
        now = datetime.now(UTC)
        if not records or records[0]["_format"] == "unrecognized":
            filename = records[0]["filename"] if records else ""
            node = FactNode(
                id=new_fact_node_id(),
                run_id=run_id,
                application_id=application_id,
                node_type="reference_document",
                name=filename or "uploaded architecture diagram",
                attributes={
                    "filename": filename,
                    "note": (
                        "uploaded architecture diagram in a format this version cannot read; stored as a reference only"
                    ),
                    "reason": records[0].get("reason", "") if records else "",
                },
                source_ref="architecture_diagram",
                discovered_at=now,
            )
            return [node], []

        diagram = records[0]["diagram"]
        nodes: list[FactNode] = []
        if diagram.truncated:
            # The caps drop the rest silently otherwise, and a partly-read diagram looks like a complete one.
            nodes.append(
                FactNode(
                    id=new_fact_node_id(),
                    run_id=run_id,
                    application_id=application_id,
                    node_type="scan_note",
                    name="diagram size limit",
                    attributes={
                        "warnings": [
                            (
                                f"This diagram is larger than the limit ({MAX_COMPONENTS} components, {MAX_FLOWS} flows, "
                                "or the line limit for Mermaid). Only the first part was read, so the rest of the system "
                                "is not in the model."
                            )
                        ]
                    },
                    source_ref="architecture_diagram",
                    discovered_at=now,
                )
            )
        edges: list[FactEdge] = []
        node_id_by_key: dict[str, str] = {}
        for component in diagram.components:
            attributes: dict = {"source_format": diagram.format, "description": ""}
            if component.boundary:
                attributes["trust_boundary"] = component.boundary
            if component.properties:
                attributes["stated_properties"] = dict(component.properties)
            node = FactNode(
                id=new_fact_node_id(),
                run_id=run_id,
                application_id=application_id,
                node_type=component.type,
                name=component.name,
                attributes=attributes,
                source_ref="architecture_diagram",
                discovered_at=now,
            )
            nodes.append(node)
            node_id_by_key[component.key] = node.id
        for flow in diagram.flows:
            attributes = {"stated_properties": dict(flow.properties)} if flow.properties else {}
            edges.append(
                FactEdge(
                    id=new_fact_edge_id(),
                    run_id=run_id,
                    application_id=application_id,
                    source_node_id=node_id_by_key[flow.source],
                    target_node_id=node_id_by_key[flow.target],
                    edge_type="data_flow",
                    label=flow.label,
                    attributes=attributes,
                )
            )
        return nodes, edges
