"""What every diagram format is parsed into, before it becomes facts.

A parser only describes what is drawn: components, the connections between them, which zone
each sits in, and any facts the file itself states. Turning that into FactNodes/FactEdges is the
ingestor's single job, so a new format is one parser and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Hard caps: a diagram is hand-drawn, so anything beyond these is a mistake or an attack, and the
# rest of the pipeline (layout, threat generation) is not built for thousands of nodes.
MAX_CONTENT_CHARS = 5_000_000
MAX_COMPONENTS = 500
MAX_FLOWS = 2000
MAX_NAME_CHARS = 200

PropertyValue = bool | str


@dataclass
class DiagramComponent:
    key: str  # unique within the file; how flows refer to it
    name: str
    type: str  # process | data_store | external_entity
    boundary: str | None = None
    # Facts the file states about it, already mapped to this platform's property keys. Only
    # explicit positive statements are carried: an unchecked box in another tool is "not
    # stated", not "no".
    properties: dict[str, PropertyValue] = field(default_factory=dict)


@dataclass
class DiagramFlow:
    source: str  # component keys
    target: str
    label: str | None = None
    properties: dict[str, PropertyValue] = field(default_factory=dict)


@dataclass
class ParsedDiagram:
    format: str  # threat_dragon | drawio | mermaid | threagile
    components: list[DiagramComponent] = field(default_factory=list)
    flows: list[DiagramFlow] = field(default_factory=list)
    # True when the file had more than the caps allow and the rest was dropped.
    truncated: bool = False


def clean_name(text: object) -> str:
    """One line, trimmed, capped: file text becomes a component name, so it must not carry markup or
    unbounded length into the rest of the app."""
    return " ".join(str(text).split())[:MAX_NAME_CHARS]


def finish(diagram: ParsedDiagram) -> ParsedDiagram | None:
    """Applies the caps and drops flows that lost an end. None when nothing usable was drawn."""
    if len(diagram.components) > MAX_COMPONENTS:
        diagram.components = diagram.components[:MAX_COMPONENTS]
        diagram.truncated = True
    keys = {c.key for c in diagram.components}
    flows = [f for f in diagram.flows if f.source in keys and f.target in keys]
    if len(flows) > MAX_FLOWS:
        flows = flows[:MAX_FLOWS]
        diagram.truncated = True
    diagram.flows = flows
    return diagram if diagram.components else None
