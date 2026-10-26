"""Doc-vs-code conflicts.

Narrow first pass: presence only. A
component named in an uploaded architecture diagram that has no matching
name among the run's other ingested infrastructure facts is flagged as
documentation drift. Property-level conflicts (the diagram says encrypted,
the manifest is plaintext) are NOT built here -- architecture_diagram_
ingestor.py doesn't yet capture that data from the diagram at all (see its
own module docstring: only a component's name/description survive parsing
today), so there is nothing to compare on that axis yet.

Deliberately one-directional. The reverse -- an infrastructure component
that isn't drawn in the diagram -- is not flagged: a diagram is normally a
simplified, higher-level view that omits plenty of real components on
purpose (a ConfigMap, an internal sidecar), so that direction would mostly
be noise, undoing the exact "generic rules regardless of context" noise
problem item #6 in this same section addresses. A diagram claiming
something that provably isn't there is the actionable direction: it means
the diagram is stale, or the component was renamed/removed and the design
record wasn't updated.

Matching is exact name (case-insensitive, trimmed) -- the same precision-
over-fuzzy-matching choice the rest of this codebase makes for cross-source
identity. A diagram
component intentionally named differently from its real counterpart will
read as drift here; that is a real limit of this narrow pass, not a bug.
"""

from __future__ import annotations

from dataclasses import dataclass

from kresheen.models.facts import FactNode

DIAGRAM_SOURCE = "architecture_diagram"
_NON_INFRA_SOURCES = frozenset({DIAGRAM_SOURCE, "documentation"})
_COMPONENT_NODE_TYPES = frozenset({"process", "data_store", "external_entity"})


@dataclass(frozen=True)
class DocConflict:
    kind: str  # "diagram_only"
    name: str
    reason: str


def _norm(name: str) -> str:
    return name.strip().lower()


def check_doc_conflicts(fact_nodes: list[FactNode]) -> list[DocConflict]:
    """Empty when there's nothing to compare: no diagram was uploaded, or no
    other infrastructure source was ingested alongside it in this run."""
    diagram_components = [
        n for n in fact_nodes if n.source_ref == DIAGRAM_SOURCE and n.node_type in _COMPONENT_NODE_TYPES
    ]
    infra_names = {
        _norm(n.name)
        for n in fact_nodes
        if n.source_ref not in _NON_INFRA_SOURCES and n.node_type in _COMPONENT_NODE_TYPES
    }
    if not diagram_components or not infra_names:
        return []

    seen: set[str] = set()
    conflicts: list[DocConflict] = []
    for node in diagram_components:
        norm = _norm(node.name)
        if norm in infra_names or norm in seen:
            continue
        seen.add(norm)
        conflicts.append(
            DocConflict(
                "diagram_only",
                node.name,
                "named in the architecture diagram, but no ingested infrastructure component matches it",
            )
        )
    return conflicts
