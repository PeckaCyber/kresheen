"""Threat and finding CSVs for spreadsheets and ticketing.

Cells hold user-typed text (component names, notes, descriptions), so every cell
is guarded against spreadsheet formula injection: a value that would be read as
a formula (it starts with `=`, `+`, `-`, `@`, tab or carriage return) gets a
leading apostrophe, the OWASP-recommended neutralisation. The file starts with a
UTF-8 byte order mark so Excel reads non-ASCII text correctly.
"""

from __future__ import annotations

import csv
import io

from kresheen.reporting.model import ThreatModelReport
from kresheen.reporting.text import clean_text

_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")

THREAT_COLUMNS = (
    "element",
    "element_type",
    "methodology",
    "category",
    "title",
    "description",
    "impact",
    "likelihood",
    "risk",
    "status",
    "note",
    "mitigations",
    "how_to_verify",
    "cwe",
    "attack",
    "origin",
    "risk_factors",
    "evidence_count",
    "rule_id",
)

FINDING_COLUMNS = (
    "id",
    "element",
    "title",
    "severity",
    "status",
    "domain",
    "source_tool",
    "discovered_at",
    "description",
)


def safe_cell(value: object) -> str:
    text = clean_text(value)
    # Strip only spaces before looking: a leading tab or carriage return is
    # itself one of the formula triggers, not padding.
    return f"'{text}" if text.lstrip(" ").startswith(_FORMULA_STARTS) else text


def _write(columns: tuple[str, ...], rows: list[list[object]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(cell) for cell in row])
    return "\ufeff" + buffer.getvalue()


ACTION_COLUMNS = ("rank", "action", "risk", "basis", "threats", "elements", "cwe", "how_to_verify", "status", "note")


def actions_csv(report: ThreatModelReport) -> str:
    """The action plan as a checklist: open actions first, in rank order."""
    actions = report.action_plan.actions if report.action_plan else []
    return _write(
        ACTION_COLUMNS,
        [
            [
                rank,
                a.text,
                a.max_risk,
                a.basis,
                a.threat_count,
                ", ".join(a.elements) + (f" (+{a.element_count - len(a.elements)} more)" if a.element_count > len(a.elements) else ""),
                ", ".join(a.cwe_refs),
                " | ".join(a.verification),
                a.status.replace("_", " "),
                a.note,
            ]
            for rank, a in enumerate(actions, start=1)
        ],
    )


def threats_csv(report: ThreatModelReport) -> str:
    return _write(
        THREAT_COLUMNS,
        [
            [
                t.element_name,
                t.element_type,
                t.methodology,
                t.category or "",
                t.title,
                t.description,
                t.severity,
                t.likelihood,
                t.risk,
                t.status,
                t.note,
                " | ".join(t.mitigations),
                " | ".join(t.verification),
                ", ".join(t.cwe_refs),
                ", ".join(t.attack_refs),
                t.origin,
                " | ".join([*t.risk_factors, *t.likelihood_factors]),
                t.evidence_total,
                t.rule_id,
            ]
            for t in report.threats
        ],
    )


def findings_csv(report: ThreatModelReport) -> str:
    return _write(
        FINDING_COLUMNS,
        [
            [f.id, f.element, f.title, f.severity, f.status, f.domain, f.source_tool, f.discovered_at.isoformat(), f.description]
            for f in report.findings
        ],
    )
