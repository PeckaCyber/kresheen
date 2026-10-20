"""Mermaid flowcharts (`flowchart` / `graph`), as pasted from a README or saved as `.mmd`.

`A[Web] -->|HTTPS| B[(Database)]` becomes two components and a flow. Shapes give the type: a
cylinder `[( )]` is a data store and a circle `(( ))` an external entity; anything else is a
process. A `subgraph` is a trust boundary. Styling, click and class lines are ignored, and a
line that cannot be read is skipped rather than failing the file. Input is capped in size and
line length so a hostile file cannot make the scan expensive.
"""

from __future__ import annotations

import re

from kresheen.engine.ingest.diagrams.model import (
    MAX_CONTENT_CHARS,
    DiagramComponent,
    DiagramFlow,
    ParsedDiagram,
    clean_name,
    finish,
)

_MAX_LINES = 5000
_MAX_LINE_CHARS = 2000
_HEADER = re.compile(r"^\s*(flowchart|graph)\b", re.IGNORECASE)
_FENCE = re.compile(r"^\s*```")
_IGNORED = re.compile(r"^\s*(classDef|class|style|linkStyle|click|direction|accTitle|accDescr|%%)\b", re.IGNORECASE)
_LINK = re.compile(r"\s*(-->|---|-\.->|==>|--[ox])\s*(\|[^|\n]{0,200}\|)?\s*")
_TEXT_LINK = re.compile(r"--\s+([^\-<>|\n]{1,200}?)\s+-->")
_NODE = re.compile(r"^([A-Za-z0-9_]{1,80})\s*(.{0,300})$")


def _shape(rest: str) -> tuple[str, str]:
    """(type, label) from the bracket text after a node id."""
    rest = rest.strip()
    if not rest:
        return "process", ""
    kind = "process"
    if rest.startswith("[(") and rest.endswith(")]"):
        kind, inner = "data_store", rest[2:-2]
    elif rest.startswith("((") and rest.endswith("))"):
        kind, inner = "external_entity", rest[2:-2]
    else:
        inner = rest.strip("[](){}<>/\\")
    return kind, clean_name(inner.strip().strip('"').strip("'"))


def looks_like_mermaid(content: str) -> bool:
    for line in content.splitlines()[:40]:
        stripped = line.strip()
        if not stripped or stripped.startswith(("%%", "---")) or _FENCE.match(stripped):
            continue
        return bool(_HEADER.match(stripped))
    return False


def parse_mermaid(content: str) -> ParsedDiagram | None:
    if len(content) > MAX_CONTENT_CHARS:
        return None
    components: dict[str, DiagramComponent] = {}
    flows: list[DiagramFlow] = []
    zones: list[str] = []
    started = False
    cut = False  # more lines than _MAX_LINES: the rest was not read

    def node(token: str) -> str | None:
        match = _NODE.match(token.strip())
        if not match:
            return None
        key, rest = match.group(1), match.group(2).strip()
        # A node is an id alone or followed by a shape opener; an id followed by prose is a stray line.
        if rest and rest[0] not in "[({>":
            return None
        kind, label = _shape(rest)
        existing = components.get(key)
        if existing is None:
            components[key] = DiagramComponent(key=key, name=label or key, type=kind, boundary=zones[-1] if zones else None)
        elif label and existing.name == key:
            existing.name, existing.type = label, kind  # defined properly after first being referenced
        return key

    for number, raw in enumerate(content.splitlines()):
        if number >= _MAX_LINES:
            cut = True
            break
        line = raw.strip()[:_MAX_LINE_CHARS]
        if not line or line.startswith("%%") or _FENCE.match(line) or line == "---":
            continue
        if not started:
            started = bool(_HEADER.match(line))
            continue
        if _IGNORED.match(line):
            continue
        sub = re.match(r"^subgraph\s+(?:([A-Za-z0-9_]+)\s*)?(?:\[\s*\"?(.*?)\"?\s*\])?\s*$", line, re.IGNORECASE)
        if sub:
            zones.append(clean_name(sub.group(2) or sub.group(1) or "Boundary"))
            continue
        if line.lower() == "end":
            if zones:
                zones.pop()
            continue
        parts = _LINK.split(_TEXT_LINK.sub(r"-->|\1|", line))
        # split with two groups: [node, op, label, node, op, label, node, ...]
        tokens = parts[0::3]
        labels = parts[2::3]
        previous: list[str] = []
        for index, token in enumerate(tokens):
            keys = [k for k in (node(piece) for piece in token.split("&")) if k]
            if index > 0 and previous and keys:
                label = (labels[index - 1] or "").strip("|").strip()
                for source in previous:
                    for target in keys:
                        flows.append(DiagramFlow(source=source, target=target, label=clean_name(label) or None))
            previous = keys
    if not started:
        return None
    diagram = finish(ParsedDiagram(format="mermaid", components=list(components.values()), flows=flows))
    if diagram is not None and cut:
        diagram.truncated = True
    return diagram
