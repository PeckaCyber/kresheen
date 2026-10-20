"""JSON API for design-level threats on a run's DFD: list the generated
threats (with suggested mitigations) and set the user's triage status.

Threats are recomputed from the merged DFD on every request (see
models/threat.py); only the status the user chose is persisted, keyed by
stable component names so it survives re-scans.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from kresheen.dashboard.access import authorize_application
from kresheen.dashboard.auth import get_current_session, get_current_user, require_csrf
from kresheen.dashboard.deps import get_repo
from kresheen.dashboard.methodology_checks import require_available_methodologies
from kresheen.dashboard.routes.api_applications import _get_application_or_404
from kresheen.engine.action_plan import build_action_plan
from kresheen.engine.completeness import assess_completeness
from kresheen.engine.threats.generate import (
    DfdElement,
    DfdFlow,
    component_element_key,
    flow_element_key,
)
from kresheen.engine.threats.properties import (
    InvalidPropertiesError,
    known_property_keys,
    validate_properties,
)
from kresheen.engine.threats.service import (
    UnknownRunError,
    generate_run_threats,
    load_derived_dfd_model,
    load_dfd_model,
)
from kresheen.engine.threats.view import build_threats_out
from kresheen.engine.trend import record_snapshot
from kresheen.models.action_plan import (
    ActionPlanOut,
    ActionStatusRecord,
    ActionStatusValue,
    action_status_id,
)
from kresheen.models.completeness import CompletenessOut
from kresheen.models.element_properties import (
    ElementPropertiesRecord,
    PropertyValue,
    element_properties_id,
)
from kresheen.models.threat import (
    DreadScore,
    ManualThreat,
    Methodology,
    Threat,
    ThreatElementType,
    ThreatOut,
    ThreatSeverity,
    ThreatsOut,
    ThreatStatusRecord,
    ThreatStatusValue,
    new_manual_threat_id,
    threat_status_id,
)
from kresheen.models.user import User
from kresheen.storage.repository import Repository

router = APIRouter(
    prefix="/api/applications", tags=["threats"], dependencies=[Depends(get_current_session), Depends(authorize_application)]
)

class SetThreatStatusRequest(BaseModel):
    threat_key: str
    status: ThreatStatusValue
    note: str = Field(default="", max_length=2000)
    # Optional DREAD score --
    # purely informational, never affects risk_score/ordering (see
    # DreadScore's docstring). `null` clears a previously-saved score.
    dread: DreadScore | None = None


class UpdateManualThreatRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    severity: ThreatSeverity = "medium"
    methodology: Methodology = "STRIDE"
    category: str | None = None
    mitigations: list[Annotated[str, Field(min_length=1, max_length=500)]] = Field(default_factory=list, max_length=20)


class SetElementPropertiesRequest(BaseModel):
    element_kind: Literal["component", "flow"]
    # This run's component (Asset) or flow id; resolved to a stable name-based key
    # server-side and never stored.
    element_id: str
    # The complete set of stated properties; anything absent is unknown. An empty
    # set removes the record.
    properties: dict[str, PropertyValue] = Field(default_factory=dict, max_length=20)


class ElementPropertiesOut(BaseModel):
    element_key: str
    properties: dict[str, PropertyValue]


class CreateManualThreatRequest(BaseModel):
    element_kind: Literal["component", "flow"]
    # This run's component (Asset) or flow id, as shown on the diagram. It is
    # resolved to a stable name-based key server-side and never stored.
    element_id: str
    kb_entry_id: str | None = None
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    severity: ThreatSeverity = "medium"
    methodology: Methodology = "STRIDE"
    category: str | None = None
    mitigations: list[Annotated[str, Field(min_length=1, max_length=500)]] = Field(default_factory=list, max_length=20)


def _load_model(application_id: str, run_id: str, repo: Repository) -> tuple[list[DfdElement], list[DfdFlow]]:
    try:
        return load_dfd_model(application_id, run_id, repo)
    except UnknownRunError:
        raise HTTPException(status_code=404, detail="Unknown run") from None


def _generate_for_run(application_id: str, run_id: str, repo: Repository) -> list[Threat]:
    try:
        return generate_run_threats(application_id, run_id, repo)
    except UnknownRunError:
        raise HTTPException(status_code=404, detail="Unknown run") from None


@router.get("/{application_id}/runs/{run_id}/threats", response_model=ThreatsOut)
def get_run_threats(
    application_id: str,
    run_id: str,
    repo: Repository = Depends(get_repo),
) -> ThreatsOut:
    _get_application_or_404(application_id, repo)
    try:
        return build_threats_out(application_id, run_id, repo)
    except UnknownRunError:
        raise HTTPException(status_code=404, detail="Unknown run") from None


_REASON_REQUIRED = ("accepted", "not_applicable")


def _require_reason(status: str, note: str) -> None:
    """Accepting a risk or calling it not applicable is a decision someone will need to justify
    later, so a reason is required."""
    if status in _REASON_REQUIRED and not note.strip():
        raise HTTPException(status_code=422, detail="Say why this threat is accepted or not applicable")


@router.put(
    "/{application_id}/runs/{run_id}/threats/status",
    response_model=ThreatOut,
    dependencies=[Depends(require_csrf)],
)
def set_threat_status(
    application_id: str,
    run_id: str,
    body: SetThreatStatusRequest,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> ThreatOut:
    _get_application_or_404(application_id, repo)
    # Only accept keys the current model actually generates, so a bad request
    # can't fill the table with rows that point at nothing.
    threat = next(
        (t for t in _generate_for_run(application_id, run_id, repo) if t.key == body.threat_key), None
    )
    if threat is None:
        raise HTTPException(status_code=404, detail="Unknown threat for this run")

    _require_reason(body.status, body.note)
    status_id = threat_status_id(application_id, body.threat_key)
    if body.status == "open" and not body.note and body.dread is None:
        # Back to the default: nothing left to say about this threat, so no
        # record is kept (a DREAD score or a note alone still keeps one --
        # see SetThreatStatusRequest's docstring).
        repo.delete_threat_status(status_id)
        record_snapshot(repo, application_id)  # Status changed, so today's trend point should too
        return ThreatOut(**threat.model_dump())

    record = ThreatStatusRecord(
        id=status_id,
        application_id=application_id,
        threat_key=body.threat_key,
        status=body.status,
        note=body.note,
        dread=body.dread,
        updated_by_user_id=user.id,
        updated_at=datetime.now(UTC),
    )
    repo.save_threat_status(record)
    record_snapshot(repo, application_id)  # Status changed, so today's trend point should too
    return ThreatOut(
        **threat.model_dump(),
        status=record.status,
        note=record.note,
        dread=record.dread,
        status_updated_at=record.updated_at,
    )


@router.post(
    "/{application_id}/runs/{run_id}/manual-threats",
    response_model=ThreatOut,
    dependencies=[Depends(require_csrf)],
)
def create_manual_threat(
    application_id: str,
    run_id: str,
    body: CreateManualThreatRequest,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> ThreatOut:
    """Attach a threat to one component or flow of this run's diagram. It is
    stored against the element's *name*, so it stays attached across re-scans."""
    _get_application_or_404(application_id, repo)
    require_available_methodologies([body.methodology])
    if body.kb_entry_id is not None and repo.get_kb_entry(body.kb_entry_id) is None:
        raise HTTPException(status_code=404, detail="Unknown threat knowledge base entry")

    elements, flows = _load_model(application_id, run_id, repo)
    by_id = {element.id: element for element in elements}
    element_key: str
    element_name: str
    element_type: ThreatElementType
    if body.element_kind == "component":
        element = by_id.get(body.element_id)
        if element is None:
            raise HTTPException(status_code=404, detail="Unknown component in this run")
        element_key, element_name = component_element_key(element), element.name
        element_type = cast(ThreatElementType, element.type)  # only ever process/data_store/external_entity
    else:
        flow = next((f for f in flows if f.id == body.element_id), None)
        source = by_id.get(flow.source_id) if flow else None
        target = by_id.get(flow.target_id) if flow else None
        if source is None or target is None:
            raise HTTPException(status_code=404, detail="Unknown data flow in this run")
        element_key, element_name = flow_element_key(source, target), f"{source.name} -> {target.name}"
        element_type = "data_flow"

    manual = ManualThreat(
        id=new_manual_threat_id(),
        application_id=application_id,
        element_kind=body.element_kind,
        element_type=element_type,
        element_key=element_key,
        element_name=element_name,
        kb_entry_id=body.kb_entry_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        methodology=body.methodology,
        category=body.category,
        mitigations=body.mitigations,
        created_by_user_id=user.id,
        created_at=datetime.now(UTC),
    )
    repo.save_manual_threat(manual)
    created = next(
        t for t in _generate_for_run(application_id, run_id, repo) if t.manual_threat_id == manual.id
    )
    return ThreatOut(**created.model_dump())


def _store_element_properties(
    application_id: str,
    run_id: str,
    element_kind: str,
    element_id: str,
    properties: dict[str, PropertyValue],
    user: User,
    repo: Repository,
    *,
    merge: bool = False,
) -> ElementPropertiesOut:
    """Validates and stores one element's owner-stated properties, keyed by *name* so they
    survive re-scans. `merge` layers `properties` over what is already stated instead of replacing
    it; a None-like value is not representable here, so clearing a key is done by replacing."""
    elements, flows = _load_model(application_id, run_id, repo)
    by_id = {element.id: element for element in elements}
    if element_kind == "component":
        element = by_id.get(element_id)
        if element is None:
            raise HTTPException(status_code=404, detail="Unknown component in this run")
        element_key, element_type, current = component_element_key(element), element.type, element.properties
    else:
        flow = next((f for f in flows if f.id == element_id), None)
        source = by_id.get(flow.source_id) if flow else None
        target = by_id.get(flow.target_id) if flow else None
        if flow is None or source is None or target is None:
            raise HTTPException(status_code=404, detail="Unknown data flow in this run")
        element_key, element_type, current = flow_element_key(source, target), "data_flow", flow.properties

    try:
        # A stated property no longer offered (a lapsed plugin's) is dropped when merging, not an error.
        known = known_property_keys(element_type)
        base = {key: value for key, value in current.items() if key in known}
        cleaned = validate_properties(element_type, {**base, **properties} if merge else properties)
    except InvalidPropertiesError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    record_id = element_properties_id(application_id, element_key)
    if not cleaned:
        repo.delete_element_properties(record_id)
    else:
        repo.save_element_properties(
            ElementPropertiesRecord(
                id=record_id,
                application_id=application_id,
                element_key=element_key,
                properties=cleaned,
                updated_by_user_id=user.id,
                updated_at=datetime.now(UTC),
            )
        )
    return ElementPropertiesOut(element_key=element_key, properties=cleaned)


@router.put(
    "/{application_id}/runs/{run_id}/element-properties",
    response_model=ElementPropertiesOut,
    dependencies=[Depends(require_csrf)],
)
def set_element_properties(
    application_id: str,
    run_id: str,
    body: SetElementPropertiesRequest,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> ElementPropertiesOut:
    """States properties of one component or flow of this run's diagram (scanned
    or hand-drawn), replacing what was stated before. Stored against the element's
    *name*, so they survive re-scans."""
    _get_application_or_404(application_id, repo)
    return _store_element_properties(
        application_id, run_id, body.element_kind, body.element_id, body.properties, user, repo
    )


class AnswerPropertyRequest(BaseModel):
    element_kind: Literal["component", "flow"]
    element_id: str
    properties: dict[str, PropertyValue] = Field(min_length=1, max_length=5)


@router.patch(
    "/{application_id}/runs/{run_id}/element-properties",
    response_model=ElementPropertiesOut,
    dependencies=[Depends(require_csrf)],
)
def answer_element_property(
    application_id: str,
    run_id: str,
    body: AnswerPropertyRequest,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> ElementPropertiesOut:
    """Adds or changes just these properties, leaving every other stated one alone. Used by the
    completeness panel's one-click answers, which must not clobber what else is stated."""
    _get_application_or_404(application_id, repo)
    return _store_element_properties(
        application_id, run_id, body.element_kind, body.element_id, body.properties, user, repo, merge=True
    )


@router.get("/{application_id}/runs/{run_id}/completeness", response_model=CompletenessOut)
def get_completeness(
    application_id: str,
    run_id: str,
    repo: Repository = Depends(get_repo),
) -> CompletenessOut:
    _get_application_or_404(application_id, repo)
    run = repo.get_run(run_id)
    if run is None or run.application_id != application_id:
        raise HTTPException(status_code=404, detail="Unknown run")
    try:
        elements, flows = load_derived_dfd_model(application_id, run_id, repo)
    except UnknownRunError:
        raise HTTPException(status_code=404, detail="Unknown run") from None
    return assess_completeness(elements, flows, run.source_results)


@router.patch(
    "/{application_id}/runs/{run_id}/manual-threats/{manual_threat_id}",
    response_model=ThreatOut,
    dependencies=[Depends(require_csrf)],
)
def update_manual_threat(
    application_id: str,
    run_id: str,
    manual_threat_id: str,
    body: UpdateManualThreatRequest,
    repo: Repository = Depends(get_repo),
) -> ThreatOut:
    """Edits the text of a manual threat. Its element and id (hence its threat
    key and triage status) never change; delete and re-add to move it."""
    _get_application_or_404(application_id, repo)
    manual = repo.get_manual_threat(manual_threat_id)
    if manual is None or manual.application_id != application_id:
        raise HTTPException(status_code=404, detail="Unknown manual threat")
    require_available_methodologies([body.methodology], keep=[manual.methodology])
    repo.save_manual_threat(manual.model_copy(update=body.model_dump()))

    generated = next(
        (t for t in _generate_for_run(application_id, run_id, repo) if t.manual_threat_id == manual.id),
        None,
    )
    if generated is None:
        # Its element isn't on this run's diagram (renamed or deleted).
        raise HTTPException(status_code=404, detail="This threat's component is not on this run's diagram")
    record = next((r for r in repo.list_threat_statuses(application_id) if r.threat_key == generated.key), None)
    return ThreatOut(
        **generated.model_dump(),
        status=record.status if record else "open",
        note=record.note if record else "",
        dread=record.dread if record else None,
        status_updated_at=record.updated_at if record else None,
    )


@router.delete(
    "/{application_id}/manual-threats/{manual_threat_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
def delete_manual_threat(
    application_id: str, manual_threat_id: str, repo: Repository = Depends(get_repo)
) -> None:
    _get_application_or_404(application_id, repo)
    manual = repo.get_manual_threat(manual_threat_id)
    if manual is None or manual.application_id != application_id:
        raise HTTPException(status_code=404, detail="Unknown manual threat")
    repo.delete_manual_threat(manual_threat_id)
    # Drop its triage status too, so a deleted threat leaves no orphan row.
    for record in repo.list_threat_statuses(application_id):
        if record.threat_key.startswith(f"{manual_threat_id}|"):
            repo.delete_threat_status(record.id)


class SetActionStatusRequest(BaseModel):
    status: ActionStatusValue
    note: str = Field(default="", max_length=2000)


def _plan_for(application_id: str, run_id: str, repo: Repository) -> ActionPlanOut:
    try:
        threats = build_threats_out(application_id, run_id, repo).threats
    except UnknownRunError:
        raise HTTPException(status_code=404, detail="Unknown run") from None
    statuses = {r.action_id: r for r in repo.list_action_statuses(application_id)}
    return build_action_plan(threats, statuses)


@router.get("/{application_id}/runs/{run_id}/action-plan", response_model=ActionPlanOut)
def get_action_plan(
    application_id: str,
    run_id: str,
    repo: Repository = Depends(get_repo),
) -> ActionPlanOut:
    _get_application_or_404(application_id, repo)
    return _plan_for(application_id, run_id, repo)


@router.put(
    "/{application_id}/runs/{run_id}/action-plan/{action_id}/status",
    response_model=ActionPlanOut,
    dependencies=[Depends(require_csrf)],
)
def set_action_status(
    application_id: str,
    run_id: str,
    action_id: str,
    body: SetActionStatusRequest,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> ActionPlanOut:
    """Returns the refreshed plan. Only ids the current plan contains are accepted, and a
    declined fix (wont_do) needs a stated reason."""
    _get_application_or_404(application_id, repo)
    plan = _plan_for(application_id, run_id, repo)
    if not any(action.id == action_id for action in plan.actions):
        raise HTTPException(status_code=404, detail="Unknown action for this run")
    note = body.note.strip()
    if body.status == "wont_do" and not note:
        raise HTTPException(status_code=422, detail="Say why this fix is not being done")

    status_id = action_status_id(application_id, action_id)
    if body.status == "todo" and not note:
        repo.delete_action_status(status_id)  # back to the default: keep no record
    else:
        repo.save_action_status(
            ActionStatusRecord(
                id=status_id,
                application_id=application_id,
                action_id=action_id,
                status=body.status,
                note=note,
                updated_by_user_id=user.id,
                updated_at=datetime.now(UTC),
            )
        )
    return _plan_for(application_id, run_id, repo)


class BulkThreatStatusRequest(BaseModel):
    threat_keys: list[str] = Field(min_length=1, max_length=500)
    status: ThreatStatusValue
    note: str = Field(default="", max_length=2000)


class BulkThreatStatusOut(BaseModel):
    updated: int


@router.put(
    "/{application_id}/runs/{run_id}/threats/status/bulk",
    response_model=BulkThreatStatusOut,
    dependencies=[Depends(require_csrf)],
)
def set_threat_status_bulk(
    application_id: str,
    run_id: str,
    body: BulkThreatStatusRequest,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> BulkThreatStatusOut:
    """Sets one status (and one shared reason) on several threats at once. All keys must belong to
    the current model or nothing is changed. A shared note replaces each threat's note only when given,
    and each threat keeps any DREAD score it already had."""
    _get_application_or_404(application_id, repo)
    _require_reason(body.status, body.note)
    keys = list(dict.fromkeys(body.threat_keys))
    known = {t.key for t in _generate_for_run(application_id, run_id, repo)}
    unknown = [key for key in keys if key not in known]
    if unknown:
        raise HTTPException(status_code=404, detail=f"{len(unknown)} of these threats are not in this run")

    existing = {r.threat_key: r for r in repo.list_threat_statuses(application_id)}
    note = body.note.strip()
    now = datetime.now(UTC)
    for key in keys:
        previous = existing.get(key)
        kept_note = note or (previous.note if previous else "")
        dread = previous.dread if previous else None
        status_id = threat_status_id(application_id, key)
        if body.status == "open" and not kept_note and dread is None:
            repo.delete_threat_status(status_id)
            continue
        repo.save_threat_status(
            ThreatStatusRecord(
                id=status_id,
                application_id=application_id,
                threat_key=key,
                status=body.status,
                note=kept_note,
                dread=dread,
                updated_by_user_id=user.id,
                updated_at=now,
            )
        )
    record_snapshot(repo, application_id)  # Statuses changed, so today's trend point should too
    return BulkThreatStatusOut(updated=len(keys))
