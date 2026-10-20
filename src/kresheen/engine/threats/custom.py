"""Turns user-authored Threat Knowledge Base entries into threat rules.

An entry only becomes a rule when it opts in by setting `applies_to`; entries
without it stay reference-only. The rule then runs through the same generator
as the built-ins, so its threats get the same key, status, and mitigation
handling. The entry id doubles as the rule id, which keeps generated threat
keys (`<KB id>|<type>:<name>`) stable for as long as the entry exists.
"""

from __future__ import annotations

from kresheen.engine.threats.catalog import ThreatRule
from kresheen.models.threat_kb import ThreatKBEntry


def rule_from_kb_entry(entry: ThreatKBEntry) -> ThreatRule | None:
    if not entry.is_active or entry.applies_to is None:
        return None
    hint = (entry.boundary_hint or "").strip() or None
    return ThreatRule(
        id=entry.id,
        element_type=entry.applies_to,
        methodology=entry.methodology,
        category=entry.category,
        # Entry text is user data, and "{name}" is our own placeholder syntax;
        # the generator substitutes it, so a user can opt into it too.
        title=entry.name,
        description=entry.description,
        severity=entry.severity,
        mitigations=tuple(entry.mitigations),
        cwe=(entry.external_id,) if entry.external_id and entry.source == "cwe" else (),
        attack=(entry.external_id,) if entry.external_id and entry.source == "mitre_attack" else (),
        boundary_hint=hint,
        origin="custom_rule",
    )


def rules_from_kb_entries(entries: list[ThreatKBEntry]) -> list[ThreatRule]:
    return [rule for entry in entries if (rule := rule_from_kb_entry(entry)) is not None]
