"""The report as a downloadable PDF, no browser required.

Same content and structure as `docx_report.py` (both render `ThreatModelReport`)
-- built with `reportlab` (pure Python, no native libraries), not an HTML-to-PDF
converter or a rasterized diagram image: `docx_report.py`'s docstring already
gives the reason a diagram image isn't embedded ("would need an SVG-to-PNG
converter (cairo), which the runtime image doesn't carry") and that reasoning
applies here too, so the diagram is component/flow tables here as well, same
as the DOCX report.

Every string is user-controlled, so everything goes through `clean_text` and
`xml.sax.saxutils.escape` before reaching a reportlab `Paragraph` (reportlab's
Paragraph markup is a small XML-like dialect, so raw `<`/`&` in a name would
otherwise be parsed as markup).
"""

from __future__ import annotations

import io
from contextvars import ContextVar
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.platypus.doctemplate import LayoutError

from kresheen.reporting.html_report import threat_groups
from kresheen.reporting.model import (
    PLAN_REPORT_LIMIT,
    ThreatModelReport,
    sbom_vulnerability_rows,
)
from kresheen.reporting.text import clean_text

_DATE = "%Y-%m-%d %H:%M UTC"

_STYLES = getSampleStyleSheet()
# wordWrap="CJK" lets a long unbroken token (a path, an id, a minified string) wrap anywhere, instead of
# forcing one enormous column/row that cannot fit on a page.
_STYLES["Normal"].wordWrap = "CJK"
_STYLES.add(ParagraphStyle("Small", parent=_STYLES["Normal"], fontSize=8, leading=10))
_STYLES.add(ParagraphStyle("SmallItalic", parent=_STYLES["Small"], fontName="Helvetica-Oblique"))
_STYLES.add(ParagraphStyle("SmallBold", parent=_STYLES["Small"], fontName="Helvetica-Bold"))


def _pretty(value: str) -> str:
    return value.replace("_", " ")


# A table cell longer than this is cut (with an ellipsis). The full text is in the HTML and DOCX reports and the
# app; a PDF row taller than a page cannot be laid out at all.
_MAX_CELL_CHARS = 1500
_FALLBACK_CELL_CHARS = 200
_FRAME_WIDTH = LETTER[0] - 4 * cm
_cell_limit: ContextVar[int] = ContextVar("pdf_cell_limit", default=_MAX_CELL_CHARS)  # per thread/request


def _p(text: object, style: str = "Normal") -> Paragraph:
    cleaned = clean_text(text)
    limit = _cell_limit.get()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1] + "…"
    return Paragraph(escape(cleaned), _STYLES[style])


def _col_widths(headers: list[str], rows: list[list[object]]) -> list[float]:
    """Proportional to typical content length, within the frame, so text wraps instead of widening a column."""
    weights = []
    for i, header in enumerate(headers):
        lengths = [len(clean_text(row[i])) for row in rows if i < len(row)] or [0]
        typical = sum(lengths) / len(lengths)
        weights.append(max(len(header), min(typical, 60), 6))
    total = sum(weights)
    return [max(_FRAME_WIDTH * w / total, 36.0) for w in weights]


def _table(headers: list[str], rows: list[list[object]]) -> Table:
    data = [[_p(h, "SmallBold") for h in headers]] + [[_p(cell, "Small") for cell in row] for row in rows]
    table = Table(data, repeatRows=1, hAlign="LEFT", colWidths=_col_widths(headers, rows), splitInRow=1)
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def render_pdf(report: ThreatModelReport) -> bytes:
    """Falls back to much shorter cells once rather than failing the whole export on a layout error."""
    for limit in (_MAX_CELL_CHARS, _FALLBACK_CELL_CHARS):
        token = _cell_limit.set(limit)
        try:
            return _render_pdf(report)
        except LayoutError:
            if limit == _FALLBACK_CELL_CHARS:
                raise
        finally:
            _cell_limit.reset(token)
    raise AssertionError("unreachable")


def _render_pdf(report: ThreatModelReport) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=clean_text(report.application_name) or "Threat model report",
    )
    story: list = [_p(report.application_name, "Title")]
    subtitle = "Threat model report" + (f" · {report.group_name}" if report.group_name else "")
    story.append(_p(subtitle, "SmallItalic"))
    if report.application_description:
        story.append(Spacer(1, 6))
        story.append(_p(report.application_description))
    story.append(Spacer(1, 10))

    inputs = "; ".join(f"{s.type}: {s.label}" if s.label else s.type for s in report.sources) or (
        "None (a model drawn by hand)"
    )
    meta: list[list[object]] = [
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
    story.append(_table(["Field", "Value"], meta))
    story.append(Spacer(1, 4))
    story.append(
        _p(
            "Generated by a rule-based threat modeling engine from the inputs above. Treat it as a starting "
            "point and review it before relying on it.",
            "SmallItalic",
        )
    )
    story.append(Spacer(1, 14))

    story.append(_p("Summary", "Heading1"))
    by_status = report.summary.by_status
    story.append(
        _table(
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
    )
    story.append(Spacer(1, 6))
    story.append(_p("Open threats by risk", "SmallBold"))
    story.append(
        _table(
            ["Critical", "High", "Medium", "Low"],
            [[report.summary.open_by_risk.get(level, 0) for level in ("critical", "high", "medium", "low")]],
        )
    )
    story.append(Spacer(1, 14))

    story.append(_p("Action plan", "Heading1"))
    if report.open_actions:
        story.append(
            _p(
                "The open threats grouped by the fix that addresses them, ranked by risk, with fixes for things found "
                "in your configuration ahead of generic checklist items. Do these first.",
                "SmallItalic",
            )
        )
        story.append(
            _table(
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
        )
        if len(report.open_actions) > PLAN_REPORT_LIMIT:
            story.append(_p(f"{len(report.open_actions) - PLAN_REPORT_LIMIT} more actions are in the action plan CSV export.", "Small"))
    else:
        story.append(_p("No open actions: every threat is mitigated, accepted or not applicable."))
    if report.closed_action_count:
        story.append(_p(f"{report.closed_action_count} action(s) are marked done or declined and not shown.", "Small"))
    story.append(Spacer(1, 14))

    story.append(_p("Data flow diagram", "Heading1"))
    story.append(_p("The diagram is listed as tables here. Open the HTML report to see it drawn.", "SmallItalic"))
    story.append(_p("Components", "Heading2"))
    story.append(
        _table(
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
    )
    story.append(Spacer(1, 6))
    story.append(_p("Data flows", "Heading2"))
    story.append(
        _table(
            ["From", "To", "Label", "Source"],
            [
                [f.source_name, f.target_name, f.label or "", "added by hand" if f.is_manual else "scanned"]
                for f in report.data_flows
            ],
        )
    )
    story.append(Spacer(1, 14))

    story.append(_p("Assumptions and scope", "Heading1"))
    story.append(
        _p(
            "Facts the owner stated that no scan confirmed, and elements excluded from the model. These shape "
            "the threats below, so a reviewer should check them.",
            "SmallItalic",
        )
    )
    if report.not_analysed:
        story.append(
            _p(
                f"{len(report.not_analysed)} input(s) were stored but not analysed. The threats below come only from "
                "what was analysed or drawn by hand, so a short list is not a clean result."
            )
        )
        for a in report.not_analysed:
            story.append(_p(f"{a.element}: {a.statement}", "SmallItalic"))
    if report.partly_analysed:
        story.append(
            _p(
                f"{len(report.partly_analysed)} part(s) of the inputs were not analysed. The result is incomplete, so "
                'a short list, or "no vulnerabilities", does not mean nothing is there.'
            )
        )
        for a in report.partly_analysed:
            story.append(_p(f"{a.element}: {a.statement}", "SmallItalic"))
    if report.assumptions:
        story.append(_table(["Element", "Type", "Owner states"], [[a.element, _pretty(a.element_type), a.statement] for a in report.assumptions]))
    else:
        story.append(_p("No properties were stated by the owner."))
    if report.out_of_scope:
        story.append(Spacer(1, 6))
        story.append(_table(["Out of scope", "Type", "Reason"], [[a.element, _pretty(a.element_type), a.statement] for a in report.out_of_scope]))
    if report.manual_threat_count:
        story.append(Spacer(1, 6))
        story.append(_p(f"{report.manual_threat_count} threat(s) were added by hand (marked Manual below)."))
    story.append(Spacer(1, 14))

    story.append(_p(f"Threats ({report.summary.total})", "Heading1"))
    groups = threat_groups(report)
    if not groups:
        story.append(_p("No threats were generated.", "SmallItalic"))
    for group in groups:
        story.append(_p(f"{clean_text(group['name'])} ({_pretty(group['type'])})", "Heading2"))
        for threat in group["threats"]:
            story.append(_p(threat.title, "SmallBold"))
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
            story.append(_p(" | ".join(facts), "Small"))
            if threat.note:
                story.append(_p(f"Note: {threat.note}", "Small"))
            if threat.description:
                story.append(_p(threat.description))
            if threat.mitigations:
                story.append(_p("Suggested mitigations", "SmallBold"))
                for mitigation in threat.mitigations:
                    story.append(_p(f"• {mitigation}", "Small"))
            if threat.verification:
                story.append(_p("How to verify", "SmallBold"))
                for step in threat.verification:
                    story.append(_p(f"• {step}", "Small"))
            if threat.fix_example:
                story.append(_p("Example fix", "SmallBold"))
                for line in threat.fix_example.splitlines():
                    story.append(_p(line or " ", "Small"))
            reasons = [*threat.risk_factors, *threat.likelihood_factors]
            if reasons:
                story.append(_p("Why this likelihood: " + "; ".join(reasons), "Small"))
            if threat.evidence:
                titles = ", ".join(f"{e.title} ({e.severity})" for e in threat.evidence)
                story.append(_p(f"Supporting findings ({threat.evidence_total}): {titles}", "Small"))
            refs = [*threat.cwe_refs, *threat.attack_refs]
            if refs:
                story.append(_p("References: " + ", ".join(refs), "Small"))
            story.append(Spacer(1, 6))

    for section in report.extra_sections:
        story.append(_p(section.title, "Heading1"))
        for text in section.paragraphs:
            story.append(_p(text))
        for extra_table in section.tables:
            story.append(_table(extra_table.headers, [list(r) for r in extra_table.rows]))

    story.append(_p(f"Findings ({len(report.findings)})", "Heading1"))
    if report.findings:
        story.append(
            _table(
                ["Severity", "Component", "Finding", "Status", "Source"],
                [[f.severity, f.element, f.title, _pretty(f.status), f.source_tool] for f in report.findings],
            )
        )
    else:
        story.append(_p("No findings.", "SmallItalic"))

    if report.sbom:
        story.append(Spacer(1, 14))
        story.append(_p("Software bill of materials", "Heading1"))
        text = (
            f"{report.sbom.get('component_count', 0)} application dependencies, "
            f"{report.sbom.get('vulnerability_count', 0)} known vulnerabilities."
        )
        if report.sbom.get("no_lockfile_detected"):
            text += " No lockfile was found, so the vulnerability count may be understated."
        story.append(_p(text))
        rows = sbom_vulnerability_rows(report.sbom)
        if rows:
            story.append(_table(["Vulnerability", "Severity", "Package"], [[r["id"], r["severity"], r["package"]] for r in rows]))

    doc.build(story)
    return buffer.getvalue()
