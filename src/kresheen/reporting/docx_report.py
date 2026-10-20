"""The report as an editable Word document.

Same content as the HTML report (both render `ThreatModelReport`), laid out as
headings, tables and bullet lists so a consultant can edit and rebrand it. The
diagram is a components table and a flows table: an image would need an
SVG-to-PNG converter (cairo), which the runtime image doesn't carry.

python-docx raises on characters XML forbids, and every string here is
user-controlled, so all text goes through `clean_text` first.
"""

from __future__ import annotations

import io
from collections.abc import Sequence

from docx import Document
from docx.oxml import OxmlElement
from docx.shared import Cm, Pt
from docx.table import Table
from docx.text.paragraph import Paragraph

from kresheen.reporting.html_report import threat_groups
from kresheen.reporting.model import (
    PLAN_REPORT_LIMIT,
    ThreatModelReport,
    sbom_vulnerability_rows,
)
from kresheen.reporting.text import clean_text

_DATE = "%Y-%m-%d %H:%M UTC"


def _pretty(value: str) -> str:
    return value.replace("_", " ")


def _table(document, headers: list[str], rows: Sequence[Sequence[object]]) -> Table:
    # Create every row in one step: `table.add_row()` scans the existing rows each time, which made a table of
    # thousands of threats quadratic (354 s at 500 components).
    table = document.add_table(rows=1 + len(rows), cols=len(headers))
    table.style = "Table Grid"
    for cell, header in zip(table.rows[0].cells, headers, strict=True):
        cell.text = ""
        cell.paragraphs[0].add_run(clean_text(header)).bold = True
    for table_row, row in zip(list(table.rows)[1:], rows, strict=True):
        for cell, value in zip(table_row.cells, row, strict=True):
            cell.text = clean_text(value)
    return table


def _style_id(document, name: str) -> str:
    cache: dict[str, str] = document.__dict__.setdefault("_pc_style_ids", {})  # per document, dies with it
    if name not in cache:
        cache[name] = document.styles[name].style_id
    return cache[name]


def _new_paragraph(document, style: str | None = None) -> Paragraph:
    """Append a paragraph to the body in constant time. `document.add_paragraph` inserts before the section
    properties by scanning every existing child, so a report with tens of thousands of paragraphs (one block per
    threat) was quadratic: 354 s at 500 components."""
    body = document.element.body
    p = OxmlElement("w:p")
    # Look the section properties up once per document: `body.sectPr` searches from the start and `len(body)`
    # counts every child, so doing either per paragraph is the same quadratic cost again.
    cache = document.__dict__
    if "_pc_sect" not in cache:
        cache["_pc_sect"] = body.sectPr
    sect = cache["_pc_sect"]
    if sect is not None:
        sect.addprevious(p)
    else:
        body.append(p)
    if style:
        p.style = _style_id(document, style)
    return Paragraph(p, document._body)


def _heading(document, text: str, level: int) -> Paragraph:
    paragraph = _new_paragraph(document, "Title" if level == 0 else f"Heading {level}")
    paragraph.add_run(clean_text(text))
    return paragraph


def _bullet(document, text: str) -> Paragraph:
    paragraph = _new_paragraph(document, "List Bullet")
    paragraph.add_run(clean_text(text))
    return paragraph


def _para(document, text: str, *, bold: bool = False, italic: bool = False, size: int | None = None):
    paragraph = _new_paragraph(document)
    run = paragraph.add_run(clean_text(text))
    run.bold, run.italic = bold, italic
    if size:
        run.font.size = Pt(size)
    return paragraph


def render_docx(report: ThreatModelReport) -> bytes:
    document = Document()
    for section in document.sections:
        section.left_margin = section.right_margin = Cm(2)
        section.top_margin = section.bottom_margin = Cm(2)

    _heading(document, clean_text(report.application_name), level=0)
    subtitle = "Threat model report" + (f" · {report.group_name}" if report.group_name else "")
    _para(document, subtitle, italic=True)
    if report.application_description:
        _para(document, report.application_description)

    inputs = "; ".join(f"{s.type}: {s.label}" if s.label else s.type for s in report.sources) or (
        "None (a model drawn by hand)"
    )
    meta = [
        ["Run", f"{report.run_id} ({report.run_status})"],
        ["Started", report.run_started_at.strftime(_DATE)],
    ]
    if report.run_completed_at:
        meta.append(["Completed", report.run_completed_at.strftime(_DATE)])
    meta += [["Report generated", report.generated_at.strftime(_DATE)], ["Inputs", inputs]]
    if report.owner:
        meta.append(["Owner", report.owner])
    if report.reviewer:
        meta.append(["Reviewer", report.reviewer])
    if report.reviewed_at:
        meta.append(["Marked reviewed", report.reviewed_at.strftime("%Y-%m-%d") + (f" by {report.reviewed_by}" if report.reviewed_by else "")])
    if report.contributors:
        meta.append(["Contributors", ", ".join(report.contributors)])
    _table(document, ["Field", "Value"], meta)
    _para(
        document,
        "Generated by a rule-based threat modeling engine from the inputs above. Treat it as a starting "
        "point and review it before relying on it.",
        italic=True,
    )

    _heading(document, "Summary", level=1)
    by_status = report.summary.by_status
    _table(
        document,
        ["Threats", "Open", "Mitigated", "Accepted", "Not applicable", "Components", "Data flows"],
        [
            [
                report.summary.total,
                by_status.get("open", 0),
                by_status.get("mitigated", 0),
                by_status.get("accepted", 0),
                by_status.get("not_applicable", 0),
                len(report.components),
                len(report.data_flows),
            ]
        ],
    )
    _para(document, "Open threats by risk", bold=True)
    _table(
        document,
        ["Critical", "High", "Medium", "Low"],
        [[report.summary.open_by_risk.get(level, 0) for level in ("critical", "high", "medium", "low")]],
    )

    _heading(document, "Action plan", level=1)
    if report.open_actions:
        _para(
            document,
            "The open threats grouped by the fix that addresses them, ranked by risk, with fixes for things found "
            "in your configuration ahead of generic checklist items. Do these first.",
            italic=True,
        )
        _table(
            document,
            ["#", "Fix", "Risk", "Why listed", "Covers", "Status"],
            [
                [
                    rank,
                    a.text,
                    a.max_risk,
                    a.basis,
                    f"{a.threat_count} threat(s) on {', '.join(a.elements)}"
                    + (f" and {a.element_count - len(a.elements)} more" if a.element_count > len(a.elements) else ""),
                    a.status.replace("_", " "),
                ]
                for rank, a in enumerate(report.open_actions[:PLAN_REPORT_LIMIT], start=1)
            ],
        )
        if len(report.open_actions) > PLAN_REPORT_LIMIT:
            _para(document, f"{len(report.open_actions) - PLAN_REPORT_LIMIT} more actions are in the action plan CSV export.")
    else:
        _para(document, "No open actions: every threat is mitigated, accepted or not applicable.")
    if report.closed_action_count:
        _para(document, f"{report.closed_action_count} action(s) are marked done or declined and not shown.")

    _heading(document, "Data flow diagram", level=1)
    _para(
        document,
        "The diagram is listed as tables here. Open the HTML report to see it drawn.",
        italic=True,
    )
    _heading(document, "Components", level=2)
    _table(
        document,
        ["Name", "Type", "Trust boundary", "Open findings", "Source"],
        [
            [
                c.name + (" (out of scope)" if c.out_of_scope else ""),
                _pretty(c.type),
                c.trust_boundary or "",
                c.open_finding_count,
                "added by hand" if c.is_manual else "scanned",
            ]
            for c in report.components
        ],
    )
    _heading(document, "Data flows", level=2)
    _table(
        document,
        ["From", "To", "Label", "Source"],
        [[f.source_name, f.target_name, f.label or "", "added by hand" if f.is_manual else "scanned"] for f in report.data_flows],
    )

    _heading(document, "Assumptions and scope", level=1)
    _para(
        document,
        "Facts the owner stated that no scan confirmed, and elements excluded from the model. These shape "
        "the threats below, so a reviewer should check them.",
        italic=True,
    )
    if report.not_analysed:
        _para(
            document,
            f"{len(report.not_analysed)} input(s) were stored but not analysed. The threats below come only from "
            "what was analysed or drawn by hand, so a short list is not a clean result.",
        )
        for a in report.not_analysed:
            _para(document, f"{a.element}: {a.statement}")
    if report.partly_analysed:
        _para(
            document,
            f"{len(report.partly_analysed)} part(s) of the inputs were not analysed. The result is incomplete, so a "
            'short list, or "no vulnerabilities", does not mean nothing is there.',
        )
        for a in report.partly_analysed:
            _para(document, f"{a.element}: {a.statement}")
    if report.assumptions:
        _table(
            document,
            ["Element", "Type", "Owner states"],
            [[a.element, _pretty(a.element_type), a.statement] for a in report.assumptions],
        )
    else:
        _para(document, "No properties were stated by the owner.")
    if report.out_of_scope:
        _table(
            document,
            ["Out of scope", "Type", "Reason"],
            [[a.element, _pretty(a.element_type), a.statement] for a in report.out_of_scope],
        )
    if report.manual_threat_count:
        _para(document, f"{report.manual_threat_count} threat(s) were added by hand (marked Manual below).")

    _heading(document, f"Threats ({report.summary.total})", level=1)
    groups = threat_groups(report)
    if not groups:
        _para(document, "No threats were generated.", italic=True)
    for group in groups:
        _heading(document, f"{clean_text(group['name'])} ({_pretty(group['type'])})", level=2)
        for threat in group["threats"]:
            _para(document, threat.title, bold=True)
            facts = [
                f"Risk: {threat.risk}",
                f"Impact: {threat.severity}",
                f"Likelihood: {_pretty(threat.likelihood)}",
                f"Status: {_pretty(threat.status)}",
            ]
            if threat.category:
                facts.insert(3, f"{threat.methodology}: {threat.category}")
            if threat.origin == "manual":
                facts.append("Manual")
            elif threat.origin == "custom_rule":
                facts.append("Custom rule")
            _para(document, " | ".join(facts), size=9)
            if threat.note:
                _para(document, f"Note: {threat.note}", size=9)
            if threat.description:
                _para(document, threat.description)
            if threat.mitigations:
                _para(document, "Suggested mitigations", bold=True, size=9)
                for mitigation in threat.mitigations:
                    _bullet(document, mitigation)
            if threat.verification:
                _para(document, "How to verify", bold=True, size=9)
                for step in threat.verification:
                    _bullet(document, step)
            if threat.fix_example:
                _para(document, "Example fix", bold=True, size=9)
                _para(document, threat.fix_example, size=8)
            reasons = [*threat.risk_factors, *threat.likelihood_factors]
            if reasons:
                _para(document, "Why this likelihood: " + "; ".join(reasons), size=9)
            if threat.evidence:
                titles = ", ".join(f"{e.title} ({e.severity})" for e in threat.evidence)
                _para(document, f"Supporting findings ({threat.evidence_total}): {titles}", size=9)
            refs = [*threat.cwe_refs, *threat.attack_refs]
            if refs:
                _para(document, "References: " + ", ".join(refs), size=9)

    for extra in report.extra_sections:
        _heading(document, clean_text(extra.title), level=1)
        for text in extra.paragraphs:
            _para(document, clean_text(text))
        for extra_table in extra.tables:
            _table(document, [clean_text(h) for h in extra_table.headers], [[clean_text(c) for c in row] for row in extra_table.rows])

    _heading(document, f"Findings ({len(report.findings)})", level=1)
    if report.findings:
        _table(
            document,
            ["Severity", "Component", "Finding", "Status", "Source"],
            [[f.severity, f.element, f.title, _pretty(f.status), f.source_tool] for f in report.findings],
        )
    else:
        _para(document, "No findings.", italic=True)

    if report.sbom:
        _heading(document, "Software bill of materials", level=1)
        text = (
            f"{report.sbom.get('component_count', 0)} application dependencies, "
            f"{report.sbom.get('vulnerability_count', 0)} known vulnerabilities."
        )
        if report.sbom.get("no_lockfile_detected"):
            text += " No lockfile was found, so the vulnerability count may be understated."
        _para(document, text)
        rows = sbom_vulnerability_rows(report.sbom)
        if rows:
            _table(document, ["Vulnerability", "Severity", "Package"], [[r["id"], r["severity"], r["package"]] for r in rows])

    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()
