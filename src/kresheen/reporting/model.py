"""One threat model report, built once and rendered three ways (HTML, DOCX, CSV).

Everything the renderers show comes from `ThreatModelReport`, so the formats
cannot drift apart. It is assembled from the same shared builders the API uses
(engine/dfd/view.py, engine/threats/view.py, engine/sbom.py), so a report always
matches what the user sees on screen.

Two things are deliberately kept out of it:
- data source `connection_details` wholesale (a GitHub source can hold a token):
  only the source type and a sanitised label are reported;
- raw finding evidence blobs.

Text in a report is user-controlled (component names, notes, descriptions).
Escaping is each renderer's job; this module only shapes data.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from kresheen.engine.action_plan import build_action_plan
from kresheen.engine.dfd.diagrams import get_or_create_default_diagram
from kresheen.engine.dfd.view import build_run_dfd
from kresheen.engine.sbom import build_sbom_summary
from kresheen.engine.threats.properties import is_out_of_scope, property_specs
from kresheen.engine.threats.service import NON_FLOW_LABELS, UnknownRunError
from kresheen.engine.threats.view import build_threats_out
from kresheen.models.action_plan import ActionOut, ActionPlanOut
from kresheen.models.element_properties import PropertyValue
from kresheen.models.threat import ThreatOut, ThreatSummary
from kresheen.plugins import ReportSection, get_registry
from kresheen.storage.repository import Repository

FINDING_DESCRIPTION_LIMIT = 500

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportSource(BaseModel):
    type: str
    label: str = ""


class ReportComponent(BaseModel):
    id: str
    name: str
    type: str
    trust_boundary: str | None
    worst_severity: str | None
    open_finding_count: int
    is_manual: bool
    statements: list[str] = Field(default_factory=list)
    out_of_scope: bool = False
    out_of_scope_reason: str = ""
    position_x: float | None = None
    position_y: float | None = None


class ReportFlow(BaseModel):
    id: str
    source_id: str
    target_id: str
    source_name: str
    target_name: str
    label: str | None
    is_manual: bool
    # False for the "mounts"/"config"/"discovered_in" edges: relationships drawn
    # on the diagram that are not network data flows and attract no flow threats.
    is_data_flow: bool = True
    statements: list[str] = Field(default_factory=list)
    out_of_scope: bool = False
    out_of_scope_reason: str = ""


class ReportBoundary(BaseModel):
    name: str
    position_x: float
    position_y: float


class ReportFinding(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    domain: str
    source_tool: str
    element: str
    description: str
    discovered_at: datetime


class Assumption(BaseModel):
    """Something the owner stated that no scan confirmed."""

    element: str
    element_type: str
    statement: str


PLAN_REPORT_LIMIT = 25


class ThreatModelReport(BaseModel):
    application_name: str
    application_description: str
    group_name: str | None
    owner: str = ""
    reviewer: str = ""
    reviewed_at: datetime | None = None
    reviewed_by: str = ""
    contributors: list[str] = Field(default_factory=list)
    run_id: str
    run_status: str
    run_started_at: datetime
    run_completed_at: datetime | None
    generated_at: datetime
    sources: list[ReportSource]
    components: list[ReportComponent]
    flows: list[ReportFlow]
    boundaries: list[ReportBoundary]
    threats: list[ThreatOut]
    summary: ThreatSummary
    findings: list[ReportFinding]
    sbom: dict | None
    assumptions: list[Assumption]
    out_of_scope: list[Assumption]
    manual_threat_count: int
    # Inputs that were stored but not analysed (engine/source_status.py):
    # element = source type, statement = why. Shown first in "Assumptions and
    # scope" so a short threat list is never mistaken for a clean result.
    not_analysed: list[Assumption] = Field(default_factory=list)
    # Inputs that were read but where a step did not run (e.g. the vulnerability scan): an incomplete result.
    partly_analysed: list[Assumption] = Field(default_factory=list)
    # Open threats pivoted to the fixes that address them (engine/action_plan.py).
    action_plan: ActionPlanOut | None = None
    # Sections added by plugins (`Plugin.report_sections`); empty in the core.
    extra_sections: list[ReportSection] = Field(default_factory=list)

    @property
    def open_actions(self) -> list[ActionOut]:
        return [
            a for a in (self.action_plan.actions if self.action_plan else []) if a.status in ("todo", "in_progress")
        ]

    @property
    def closed_action_count(self) -> int:
        return len(self.action_plan.actions) - len(self.open_actions) if self.action_plan else 0

    @property
    def data_flows(self) -> list[ReportFlow]:
        return [f for f in self.flows if f.is_data_flow]


def safe_repo_url(url: str) -> str:
    """A repository URL with any credentials, query string or fragment removed
    (a token can ride in `https://user:token@host/...` or `?token=`)."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return ""
    host = parts.netloc.rpartition("@")[2]
    if not parts.scheme or not host:
        return ""
    return f"{parts.scheme}://{host}{parts.path}".rstrip("/")


def _source_label(source_type: str, details: dict) -> str:
    if source_type == "github_repository":
        label = safe_repo_url(str(details.get("repo_url", ""))) or "repository"
        ref = str(details.get("ref") or "").strip()
        return f"{label} @ {ref}" if ref else label
    return str(details.get("filename") or "").strip()


def statements_for(element_type: str, properties: dict[str, PropertyValue]) -> list[str]:
    """Human-readable owner statements ("Encrypted at rest: No"), excluding the
    out-of-scope pair, which is reported separately."""
    lines = []
    for spec in property_specs().get(element_type, ()):
        if spec.key in ("out_of_scope", "out_of_scope_reason") or spec.key not in properties:
            continue
        value = properties[spec.key]
        text = ("Yes" if value else "No") if isinstance(value, bool) else str(value)
        lines.append(f"{spec.label}: {text}")
    return lines


def dfd_parts(
    nodes: list[dict], edges: list[dict], boundaries: list[dict]
) -> tuple[list[ReportComponent], list[ReportFlow], list[ReportBoundary]]:
    """The DFD from engine/dfd/view.py::build_run_dfd as report types. Shared by
    the report and the standalone `dfd.svg`, which doesn't need threats."""
    name_by_id = {n["id"]: n["name"] for n in nodes}
    components = [
        ReportComponent(
            id=n["id"],
            name=n["name"],
            type=n["type"],
            trust_boundary=n["trust_boundary"],
            worst_severity=n["worst_severity"],
            open_finding_count=n["open_finding_count"],
            is_manual=n["is_manual"],
            statements=statements_for(n["type"], n["properties"]),
            out_of_scope=is_out_of_scope(n["properties"]),
            out_of_scope_reason=str(n["properties"].get("out_of_scope_reason", "")),
            position_x=n["position_x"],
            position_y=n["position_y"],
        )
        for n in nodes
    ]
    flows = [
        ReportFlow(
            id=e["id"],
            source_id=e["source"],
            target_id=e["target"],
            source_name=name_by_id.get(e["source"], "?"),
            target_name=name_by_id.get(e["target"], "?"),
            label=e["label"],
            is_manual=e["is_manual"],
            is_data_flow=e["label"] not in NON_FLOW_LABELS,
            statements=statements_for("data_flow", e["properties"]),
            out_of_scope=is_out_of_scope(e["properties"]),
            out_of_scope_reason=str(e["properties"].get("out_of_scope_reason", "")),
        )
        for e in edges
    ]

    return components, flows, [ReportBoundary(**b) for b in boundaries]


def build_report(
    application_id: str, run_id: str, repo: Repository, *, diagram_id: str | None = None
) -> ThreatModelReport:
    """Raises UnknownRunError when the run isn't this application's, and
    LookupError when the application is unknown.

    `diagram_id` picks which diagram's DFD to include (threats/findings are
    always the full run-wide list regardless -- see engine/dfd/merge.py's
    docstring); omitted resolves to the Application's default diagram."""
    application = repo.get_application(application_id)
    if application is None:
        raise LookupError(application_id)
    run = repo.get_run(run_id)
    if run is None or run.application_id != application_id:
        raise UnknownRunError(run_id)

    if diagram_id is None:
        diagram_id = get_or_create_default_diagram(application_id, repo).id
    nodes, edges, boundaries = build_run_dfd(application_id, run_id, repo, diagram_id)
    threats_out = build_threats_out(application_id, run_id, repo)

    components, flows, report_boundaries = dfd_parts(nodes, edges, boundaries)
    name_by_id = {c.id: c.name for c in components}

    assumptions = [
        Assumption(element=c.name, element_type=c.type, statement=s) for c in components for s in c.statements
    ] + [
        Assumption(element=f"{f.source_name} -> {f.target_name}", element_type="data_flow", statement=s)
        for f in flows
        for s in f.statements
    ]
    out_of_scope = [
        Assumption(element=c.name, element_type=c.type, statement=c.out_of_scope_reason or "No reason given")
        for c in components
        if c.out_of_scope
    ] + [
        Assumption(
            element=f"{f.source_name} -> {f.target_name}",
            element_type="data_flow",
            statement=f.out_of_scope_reason or "No reason given",
        )
        for f in flows
        if f.out_of_scope
    ]

    sources = []
    for source_id in run.data_source_config_ids:
        source = repo.get_data_source(source_id)
        if source is not None:
            sources.append(ReportSource(type=source.type, label=_source_label(source.type, source.connection_details)))

    findings = sorted(
        (
            ReportFinding(
                id=f.id,
                title=f.title,
                severity=f.severity.value,
                status=f.status,
                domain=f.domain.value,
                source_tool=f.source_tool,
                element=name_by_id.get(f.asset_id, f.asset_id),
                description=f.description[:FINDING_DESCRIPTION_LIMIT],
                discovered_at=f.discovered_at,
            )
            for f in repo.list_findings(run_id=run_id)
        ),
        key=lambda f: (_SEVERITY_RANK.get(f.severity, 9), f.element.lower(), f.title),
    )

    group = repo.get_group(application.group_id) if application.group_id else None
    report = ThreatModelReport(
        application_name=application.name,
        application_description=application.description,
        group_name=group.name if group else None,
        owner=application.owner,
        reviewer=application.reviewer,
        reviewed_at=application.reviewed_at,
        reviewed_by=application.reviewed_by,
        contributors=application.contributors,
        run_id=run.id,
        run_status=run.status,
        run_started_at=run.started_at,
        run_completed_at=run.completed_at,
        generated_at=datetime.now(UTC),
        sources=sources,
        components=components,
        flows=flows,
        boundaries=report_boundaries,
        threats=threats_out.threats,
        summary=threats_out.summary,
        findings=findings,
        sbom=build_sbom_summary(repo, run_id),
        assumptions=assumptions,
        out_of_scope=out_of_scope,
        manual_threat_count=sum(1 for t in threats_out.threats if t.origin == "manual"),
        not_analysed=[
            Assumption(element=r.type.replace("_", " ").capitalize(), element_type=r.status, statement=r.message)
            for r in run.source_results
            if r.status != "analysed"
        ],
        partly_analysed=[
            Assumption(element=r.type.replace("_", " ").capitalize(), element_type="partly_analysed", statement=w)
            for r in run.source_results
            for w in r.warnings
        ]
        + [
            Assumption(
                element=f"Methodology {name}",
                element_type="partly_analysed",
                statement="Selected for this application but not available in this installation, so no threats were generated for it.",
            )
            for name in threats_out.unavailable_methodologies
        ],
        action_plan=build_action_plan(
            threats_out.threats, {r.action_id: r for r in repo.list_action_statuses(application_id)}
        ),
    )
    report.extra_sections = get_registry().report_sections(report)
    return report


SBOM_VULNERABILITY_LIMIT = 50


def sbom_vulnerability_rows(sbom: dict | None, limit: int = SBOM_VULNERABILITY_LIMIT) -> list[dict[str, str]]:
    """Flat (id, severity, package) rows from the stored CycloneDX vulnerability
    entries, worst first, capped so a large repository doesn't bury the report."""
    if not sbom:
        return []
    packages = {
        c.get("bom-ref"): f"{c.get('name', '?')}@{c['version']}" if c.get("version") else str(c.get("name", "?"))
        for c in sbom.get("components", [])
        if isinstance(c, dict)
    }
    rows = []
    for vuln in sbom.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        severity = next(
            (str(r["severity"]) for r in vuln.get("ratings", []) or [] if isinstance(r, dict) and r.get("severity")),
            "unknown",
        )
        refs = [a.get("ref") for a in vuln.get("affects", []) or [] if isinstance(a, dict)]
        rows.append(
            {
                "id": str(vuln.get("id", "?")),
                "severity": severity,
                "package": ", ".join(packages.get(ref, str(ref)) for ref in refs if ref) or "",
            }
        )
    rows.sort(key=lambda row: (_SEVERITY_RANK.get(row["severity"].lower(), 9), row["id"]))
    return rows[:limit]
