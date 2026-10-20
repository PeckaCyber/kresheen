"""The report as one self-contained HTML page (print it to get a PDF).

Jinja2 with autoescape on: every user-controlled string (names, notes,
descriptions) is escaped by default. The only `| safe` in the template is the
diagram, which is produced by dfd_svg.render_svg (it escapes its own text).
The page has no JavaScript and the route serves it with a restrictive
Content-Security-Policy, so an escaping mistake still can't run script.
"""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from kresheen.models.threat import ThreatOut
from kresheen.reporting.dfd_svg import render_svg
from kresheen.reporting.model import (
    PLAN_REPORT_LIMIT,
    ThreatModelReport,
    sbom_vulnerability_rows,
)

_ENV = Environment(
    loader=PackageLoader("kresheen.reporting", "templates"),
    autoescape=select_autoescape(["html", "j2"], default_for_string=True, default=True),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)

_RISK_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def threat_groups(report: ThreatModelReport) -> list[dict]:
    """Threats grouped by the element they attach to, worst element first."""
    groups: dict[tuple[str, str], list[ThreatOut]] = {}
    for threat in report.threats:
        groups.setdefault((threat.element_name, threat.element_type), []).append(threat)
    ordered = sorted(
        groups.items(),
        key=lambda item: (min(_RISK_RANK.get(t.risk, 9) for t in item[1]), item[0][0].lower()),
    )
    return [{"name": name, "type": element_type, "threats": threats} for (name, element_type), threats in ordered]


def render_html(report: ThreatModelReport) -> str:
    template = _ENV.get_template("report.html.j2")
    return template.render(
        r=report,
        diagram_svg=render_svg(report.components, report.flows, report.boundaries, standalone=False),
        threat_groups=threat_groups(report),
        sbom_vulnerabilities=sbom_vulnerability_rows(report.sbom),
        plan_limit=PLAN_REPORT_LIMIT,
    )
