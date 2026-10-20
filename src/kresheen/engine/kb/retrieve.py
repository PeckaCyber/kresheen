"""Threat Knowledge Base retrieval: scores ThreatKBEntry rows against one
FactNode's *live* attributes, never against its `node_type`.

This is the one deliberately delicate seam flagged in models/facts.py and
models/threat_kb.py's docstrings: a `node_type`-keyed lookup here (`if
node_type == "process": return kb.filter(tags contains "process")`) would
be a stored component-type<->threat-type association, retrieved by match,
which this whole engine is designed to avoid. Keeping
retrieval driven by a node's specific discovered attribute values/keys
(container image names, exposed ports, IAM actions, ...) instead of its
type keeps it a live-facts query, not a catalog join.
"""

from __future__ import annotations

import re

from kresheen.models.facts import FactNode
from kresheen.models.threat_kb import ThreatKBEntry

_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower()))


def _keywords_from_node(node: FactNode) -> set[str]:
    words = _tokenize(node.name)
    for key, value in node.attributes.items():
        words |= _tokenize(str(key))
        if isinstance(value, (list, tuple)):
            for item in value:
                words |= _tokenize(str(item))
        elif isinstance(value, (str, int, float, bool)):
            words |= _tokenize(str(value))
    return words


def score_kb_entries(
    node: FactNode, entries: list[ThreatKBEntry], *, top_n: int = 5
) -> list[ThreatKBEntry]:
    """Keyword/tag-overlap scoring against `node`'s own live attributes --
    no vector DB, no embeddings, keeping the core
    light. Returns up to `top_n` entries, highest overlap first; ties keep
    the input's relative order (Python's sort is stable)."""
    node_words = _keywords_from_node(node)
    if not node_words:
        return []

    scored: list[tuple[int, ThreatKBEntry]] = []
    for entry in entries:
        if not entry.is_active:
            continue
        entry_words = _tokenize(" ".join([entry.name, entry.description, *entry.tags]))
        overlap = len(node_words & entry_words)
        if overlap > 0:
            scored.append((overlap, entry))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [entry for _, entry in scored[:top_n]]
