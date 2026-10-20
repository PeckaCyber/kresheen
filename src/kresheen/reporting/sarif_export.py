"""Findings as a SARIF 2.1.0 log, for CI/CD and code-scanning consumers
(GitHub code scanning, Azure DevOps, generic SARIF viewers).

One `result` per finding. `ruleId` is the finding's `source_tool` (e.g.
"grype", "kresheen") rather than a specific rule/check id -- Finding
carries no separate rule identifier today, see `models/finding.py`. Findings
are not tied to a real repository file path (they attach to a DFD element,
not a line of source), so `physicalLocation.artifactLocation.uri` is a
best-effort placeholder built from the element name, not a real path --
known limitation, same spirit as `dfd_svg.py`'s "Known limit" note.
"""

from __future__ import annotations

from typing import Any

from kresheen.reporting.model import ReportFinding, ThreatModelReport
from kresheen.reporting.text import clean_text

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _result(finding: ReportFinding) -> dict[str, Any]:
    uri = clean_text(finding.element).replace(" ", "-") or "unknown-element"
    return {
        "ruleId": clean_text(finding.source_tool) or "unknown",
        "level": _LEVEL_BY_SEVERITY.get(finding.severity, "warning"),
        "message": {"text": clean_text(finding.description) or clean_text(finding.title)},
        "locations": [
            {
                "physicalLocation": {"artifactLocation": {"uri": uri}},
                "logicalLocations": [{"name": clean_text(finding.element), "kind": "element"}],
            }
        ],
        "properties": {
            "findingId": finding.id,
            "title": clean_text(finding.title),
            "severity": finding.severity,
            "status": finding.status,
            "domain": finding.domain,
        },
    }


def build_sarif(report: ThreatModelReport) -> dict[str, Any]:
    rule_ids = sorted({clean_text(f.source_tool) or "unknown" for f in report.findings})
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Kresheen",
                        "informationUri": "https://peckacyber.com",
                        "rules": [{"id": rule_id} for rule_id in rule_ids],
                    }
                },
                "results": [_result(f) for f in report.findings],
            }
        ],
    }
