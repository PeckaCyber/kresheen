"""POST a threat to the experimental AI assist for a plain-language explanation.

Reading rule, not writing rule: explaining changes nothing and stores nothing, so it needs the same
viewer access as listing the threats. Names, descriptions and property values are written by whoever
owns the system under review, so they only ever go into the content string; the instructions are fixed
(`engine/llm/policy.py`).
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from kresheen.dashboard.access import authorize_application_read
from kresheen.dashboard.ai_calls import AiCaller, require_ai_caller, run_ai_task
from kresheen.dashboard.auth import get_current_session, require_csrf
from kresheen.dashboard.deps import get_repo
from kresheen.dashboard.routes.api_applications import _get_application_or_404
from kresheen.engine.llm import limits
from kresheen.engine.llm.policy import THREAT_EXPLAIN_TASK
from kresheen.engine.threats.service import UnknownRunError, generate_run_threats, load_dfd_model
from kresheen.models.threat import Threat
from kresheen.storage.repository import Repository

router = APIRouter(
    prefix="/api/applications",
    tags=["threats"],
    dependencies=[Depends(get_current_session), Depends(authorize_application_read)],
)


class ExplainThreatRequest(BaseModel):
    threat_key: str


class ExplainWarning(BaseModel):
    pattern: str
    excerpt: str


class ExplainThreatOut(BaseModel):
    text: str
    warnings: list[ExplainWarning]
    trimmed: bool = False


@dataclass(frozen=True)
class ExplainContent:
    content: str  # what is sent
    full: str  # everything, untrimmed: what the injection scan reads
    trimmed: bool


_TRIMMED_MARK = " [trimmed]"


def _omitted_note(count: int) -> str:
    noun = "property was" if count == 1 else "properties were"
    return f"({count} {noun} left out to keep this short)"


def build_explain_content(
    threat: Threat,
    properties: dict,
    max_chars: int = limits.EXPLAIN_MAX_INPUT_CHARS,  # type: ignore[type-arg]
) -> ExplainContent:
    """The threat, rule text, mitigations and the component's name and type always go in full. Property
    values are shortened one by one, then whole properties are dropped, longest first, until it fits."""
    head = [
        f"Threat: {threat.title}",
        f"Methodology: {threat.methodology}",
        f"Category: {threat.category or 'none'}",
        f"Severity: {threat.severity}",
        f"Rule: {threat.rule_id}",
        f"Description: {threat.description}",
    ]
    if threat.risk_factors:
        head.append("Why it applies: " + "; ".join(threat.risk_factors))
    head.append("Mitigations:")
    head.extend(f"- {m}" for m in threat.mitigations or ["none recorded"])
    head.append("Affected element:")
    head.append(f"Name: {threat.element_name}")
    head.append(f"Type: {threat.element_type}")
    if not properties:
        text = "\n".join([*head, "Properties stated by the owner: none"])
        return ExplainContent(text, text, False)

    heading = "Properties stated by the owner:"
    full_lines = [f"- {key}: {value}" for key, value in sorted(properties.items())]
    full = "\n".join([*head, heading, *full_lines])

    cut = limits.EXPLAIN_MAX_PROPERTY_CHARS
    lines = []
    for key, value in sorted(properties.items()):
        shown = str(value)
        if len(shown) > cut:
            shown = shown[:cut] + _TRIMMED_MARK
        lines.append(f"- {key}: {shown}")
    trimmed = lines != full_lines

    def assemble(kept: list[str], omitted: int) -> str:
        tail = [_omitted_note(omitted)] if omitted else []
        return "\n".join([*head, heading, *kept, *tail])

    omitted = 0
    kept = list(lines)
    while kept and len(assemble(kept, omitted)) > max_chars:
        kept.remove(max(kept, key=len))
        omitted += 1
        trimmed = True
    if not kept:
        # Nothing left to say about properties; the cap check in the guardrail module decides if the
        # always-sent part alone is too long.
        return ExplainContent(assemble([], omitted), full, True)
    return ExplainContent(assemble(kept, omitted), full, trimmed)


@router.post(
    "/{application_id}/runs/{run_id}/threats/explain",
    response_model=ExplainThreatOut,
    dependencies=[Depends(require_csrf)],
)
def explain_threat(
    request: Request,
    application_id: str,
    run_id: str,
    body: ExplainThreatRequest,
    caller: AiCaller = Depends(require_ai_caller),
    repo: Repository = Depends(get_repo),
) -> ExplainThreatOut:
    _get_application_or_404(application_id, repo)
    try:
        threats = generate_run_threats(application_id, run_id, repo)
        elements, flows = load_dfd_model(application_id, run_id, repo)
    except UnknownRunError:
        raise HTTPException(status_code=404, detail="Unknown run") from None
    threat = next((t for t in threats if t.key == body.threat_key), None)
    if threat is None:
        raise HTTPException(status_code=404, detail="Unknown threat for this run")

    properties: dict = {}  # type: ignore[type-arg]
    if threat.element_kind == "component":
        element = next((e for e in elements if e.id == threat.element_id), None)
        properties = dict(element.properties) if element else {}
    elif threat.element_kind == "flow":
        flow = next((f for f in flows if f.id == threat.element_id), None)
        properties = dict(flow.properties) if flow else {}

    built = build_explain_content(threat, properties, THREAT_EXPLAIN_TASK.max_input_chars)
    result = run_ai_task(request, repo, caller, THREAT_EXPLAIN_TASK, built.content, scan_text=built.full)
    return ExplainThreatOut(
        text=result.value.text,
        warnings=[ExplainWarning(pattern=s.pattern, excerpt=s.excerpt) for s in result.signals],
        trimmed=built.trimmed,
    )
