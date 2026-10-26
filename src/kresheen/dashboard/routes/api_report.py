"""Exports for one run: an HTML report (print it for a PDF), a DOCX report, threat
and finding CSVs, and the diagram as SVG.

GET-only, so a plain link or browser navigation works with the session cookie
(require_csrf only guards mutating methods), the same pattern as api_reporting.py.
The HTML is served inline so it can be viewed and printed; `?download=1` turns any
of them into an attachment.

The report holds user-typed text, and the HTML/SVG are same-origin, so they carry a
Content-Security-Policy that forbids script outright (defence in depth behind the
renderers' escaping). Nothing here is cacheable: it is the customer's own model.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from kresheen.dashboard.access import authorize_application
from kresheen.dashboard.auth import get_current_session
from kresheen.dashboard.deps import get_repo
from kresheen.engine.dfd.diagrams import get_or_create_default_diagram
from kresheen.engine.dfd.view import build_run_dfd
from kresheen.engine.threats.service import UnknownRunError
from kresheen.models.application import Application
from kresheen.reporting.csv_export import actions_csv, findings_csv, threats_csv
from kresheen.reporting.dfd_svg import render_svg
from kresheen.reporting.docx_report import render_docx
from kresheen.reporting.html_report import render_html
from kresheen.reporting.model import ThreatModelReport, build_report, dfd_parts
from kresheen.reporting.pdf_report import render_pdf
from kresheen.reporting.sarif_export import build_sarif
from kresheen.reporting.threat_dragon_export import build_threat_dragon_model
from kresheen.storage.repository import Repository

router = APIRouter(
    prefix="/api/applications",
    tags=["report"],
    dependencies=[Depends(get_current_session), Depends(authorize_application)],
)

_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _application_and_run(application_id: str, run_id: str, repo: Repository) -> Application:
    application = repo.get_application(application_id)
    if application is None:
        raise HTTPException(status_code=404, detail="Unknown application")
    run = repo.get_run(run_id)
    if run is None or run.application_id != application_id:
        raise HTTPException(status_code=404, detail="Unknown run")
    return application


def _resolve_diagram_id(application_id: str, diagram_id: str | None, repo: Repository) -> str:
    if diagram_id is None:
        return get_or_create_default_diagram(application_id, repo).id
    diagram = repo.get_diagram(diagram_id)
    if diagram is None or diagram.application_id != application_id:
        raise HTTPException(status_code=404, detail="Unknown diagram")
    return diagram.id


def _report(application_id: str, run_id: str, repo: Repository, diagram_id: str | None = None) -> ThreatModelReport:
    _application_and_run(application_id, run_id, repo)
    resolved_diagram_id = _resolve_diagram_id(application_id, diagram_id, repo)
    try:
        return build_report(application_id, run_id, repo, diagram_id=resolved_diagram_id)
    except (LookupError, UnknownRunError):
        raise HTTPException(status_code=404, detail="Unknown run") from None


def _slug(name: str) -> str:
    """ASCII-only, so it can go in a Content-Disposition header without escaping."""
    return re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")[:60] or "threat-model"


def _respond(
    content: str | bytes,
    media_type: str,
    *,
    application_name: str,
    suffix: str,
    attachment: bool,
    restrict_content: bool = False,
) -> Response:
    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    if restrict_content:
        headers["Content-Security-Policy"] = _CSP
    if attachment:
        stamp = datetime.now(UTC).strftime("%Y%m%d")
        headers["Content-Disposition"] = f'attachment; filename="{_slug(application_name)}-{stamp}{suffix}"'
    return Response(content=content, media_type=media_type, headers=headers)


@router.get("/{application_id}/runs/{run_id}/report.html")
def report_html(
    application_id: str,
    run_id: str,
    download: bool = False,
    diagram_id: str | None = None,
    repo: Repository = Depends(get_repo),
) -> Response:
    report = _report(application_id, run_id, repo, diagram_id)
    return _respond(
        render_html(report),
        "text/html; charset=utf-8",
        application_name=report.application_name,
        suffix="-threat-model.html",
        attachment=download,
        restrict_content=True,
    )


@router.get("/{application_id}/runs/{run_id}/report.docx")
def report_docx(
    application_id: str,
    run_id: str,
    diagram_id: str | None = None,
    repo: Repository = Depends(get_repo),
) -> Response:
    report = _report(application_id, run_id, repo, diagram_id)
    return _respond(
        render_docx(report),
        _DOCX,
        application_name=report.application_name,
        suffix="-threat-model.docx",
        attachment=True,
    )


@router.get("/{application_id}/runs/{run_id}/report.pdf")
def report_pdf(
    application_id: str,
    run_id: str,
    diagram_id: str | None = None,
    repo: Repository = Depends(get_repo),
) -> Response:
    report = _report(application_id, run_id, repo, diagram_id)
    return _respond(
        render_pdf(report),
        "application/pdf",
        application_name=report.application_name,
        suffix="-threat-model.pdf",
        attachment=True,
    )


@router.get("/{application_id}/runs/{run_id}/findings.sarif")
def export_findings_sarif(
    application_id: str,
    run_id: str,
    repo: Repository = Depends(get_repo),
) -> Response:
    report = _report(application_id, run_id, repo)
    return _respond(
        json.dumps(build_sarif(report), indent=2),
        "application/sarif+json",
        application_name=report.application_name,
        suffix="-findings.sarif",
        attachment=True,
    )


@router.get("/{application_id}/runs/{run_id}/threatdragon.json")
def export_threat_dragon(
    application_id: str,
    run_id: str,
    diagram_id: str | None = None,
    repo: Repository = Depends(get_repo),
) -> Response:
    application = _application_and_run(application_id, run_id, repo)
    resolved_diagram_id = _resolve_diagram_id(application_id, diagram_id, repo)
    nodes, edges, boundaries = build_run_dfd(application_id, run_id, repo, resolved_diagram_id)
    components, flows, report_boundaries = dfd_parts(nodes, edges, boundaries)
    model = build_threat_dragon_model(application, components, flows, report_boundaries)
    return _respond(
        json.dumps(model, indent=2),
        "application/json",
        application_name=application.name,
        suffix="-threatdragon.json",
        attachment=True,
    )


@router.get("/{application_id}/runs/{run_id}/threats.csv")
def export_threats_csv(
    application_id: str,
    run_id: str,
    repo: Repository = Depends(get_repo),
) -> Response:
    report = _report(application_id, run_id, repo)
    return _respond(
        threats_csv(report),
        "text/csv; charset=utf-8",
        application_name=report.application_name,
        suffix="-threats.csv",
        attachment=True,
    )


@router.get("/{application_id}/runs/{run_id}/action-plan.csv")
def export_action_plan_csv(
    application_id: str,
    run_id: str,
    repo: Repository = Depends(get_repo),
) -> Response:
    report = _report(application_id, run_id, repo)
    return _respond(
        actions_csv(report),
        "text/csv; charset=utf-8",
        application_name=report.application_name,
        suffix="-action-plan.csv",
        attachment=True,
    )


@router.get("/{application_id}/runs/{run_id}/findings.csv")
def export_findings_csv(
    application_id: str,
    run_id: str,
    repo: Repository = Depends(get_repo),
) -> Response:
    report = _report(application_id, run_id, repo)
    return _respond(
        findings_csv(report),
        "text/csv; charset=utf-8",
        application_name=report.application_name,
        suffix="-findings.csv",
        attachment=True,
    )


@router.get("/{application_id}/runs/{run_id}/dfd.svg")
def export_dfd_svg(
    application_id: str,
    run_id: str,
    download: bool = False,
    diagram_id: str | None = None,
    repo: Repository = Depends(get_repo),
) -> Response:
    application = _application_and_run(application_id, run_id, repo)
    resolved_diagram_id = _resolve_diagram_id(application_id, diagram_id, repo)
    nodes, edges, boundaries = build_run_dfd(application_id, run_id, repo, resolved_diagram_id)
    components, flows, report_boundaries = dfd_parts(nodes, edges, boundaries)
    return _respond(
        render_svg(components, flows, report_boundaries),
        "image/svg+xml",
        application_name=application.name,
        suffix="-diagram.svg",
        attachment=download,
        restrict_content=True,
    )
