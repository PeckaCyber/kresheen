"""Diagram formats the architecture-diagram source can read.

`parse_diagram` sniffs the format from the content, not the filename, and returns None for
anything it does not recognise (an image, a PDF, prose), which the ingestor then stores as a
reference only and the UI reports as not analysed.
"""

from __future__ import annotations

import json

from kresheen.engine.ingest.diagrams.drawio import looks_like_drawio, parse_drawio
from kresheen.engine.ingest.diagrams.mermaid import looks_like_mermaid, parse_mermaid
from kresheen.engine.ingest.diagrams.model import MAX_CONTENT_CHARS, ParsedDiagram
from kresheen.engine.ingest.diagrams.threagile import looks_like_threagile, parse_threagile
from kresheen.engine.ingest.diagrams.threat_dragon import (
    looks_like_threat_dragon,
    parse_threat_dragon,
)

SUPPORTED_FORMATS = ("Threat Dragon JSON", "draw.io / diagrams.net", "Mermaid flowchart", "Threagile YAML")


def parse_diagram(content: str) -> ParsedDiagram | None:
    if not isinstance(content, str) or not content.strip() or len(content) > MAX_CONTENT_CHARS:
        return None
    stripped = content.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(content)
        except (json.JSONDecodeError, RecursionError):
            return None
        return parse_threat_dragon(parsed) if looks_like_threat_dragon(parsed) else None
    if looks_like_drawio(content):
        return parse_drawio(content)
    if looks_like_mermaid(content):
        return parse_mermaid(content)
    if looks_like_threagile(content):
        return parse_threagile(content)
    return None
