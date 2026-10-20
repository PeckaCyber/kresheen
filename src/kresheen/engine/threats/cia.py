"""Confidentiality/Integrity/Availability impact, auto-derived per threat from its (methodology, category) -- never
user-entered (CIA is a cross-cutting tag every threat carries, not its own selectable methodology).

The mapping lives on each `MethodologySpec` (engine/threats/methodology.py): STRIDE's in the core, a plugin
methodology's in the plugin. A category with no meaningful CIA angle is left with an empty mapping rather than
forced into one, and a threat of a methodology that is not available gets no tag.
"""

from __future__ import annotations

from kresheen.engine.threats.methodology import cia_for
from kresheen.models.threat import CIAImpact


def cia_impacts_for(methodology: str, category: str | None) -> list[CIAImpact]:
    return cia_for(methodology, category)
