"""JSON API for the Applications tab: create/view/edit/delete an
Application, attach DataSourceConfigs, and execute a ThreatModelRun.

Application visibility is shared across every user in a deployment by
design (see models/user.py's docstring) -- `owner_user_id` is attribution
only, not an access filter.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from kresheen.dashboard.access import authorize_application, can_view_group, require_group_role
from kresheen.dashboard.auth import get_current_session, get_current_user, require_csrf
from kresheen.dashboard.deps import get_repo
from kresheen.dashboard.methodology_checks import require_available_methodologies
from kresheen.engine.attack_paths import find_attack_paths
from kresheen.engine.dfd.diagrams import get_or_create_default_diagram
from kresheen.engine.dfd.rename import rename_component_overlays
from kresheen.engine.dfd.view import build_run_dfd
from kresheen.engine.diff import build_run_diff
from kresheen.engine.ingest.github_repository_ingestor import validate_github_details
from kresheen.engine.orchestrator import SUPPORTED_DATA_SOURCE_TYPES, execute_run
from kresheen.engine.provenance import compute_staleness, input_digest
from kresheen.engine.run_safety import RunQueueFull, reconcile_run
from kresheen.engine.samples import DEFAULT_SAMPLE, SAMPLES, SampleKey
from kresheen.engine.sbom import build_sbom_summary
from kresheen.engine.threats.service import generate_run_threats, load_dfd_model
from kresheen.models.application import DEFAULT_METHODOLOGY, Application, new_application_id
from kresheen.models.asset import Asset, AssetType, new_manual_asset_id
from kresheen.models.attack_path import AttackPathHopOut, AttackPathOut, AttackPathsOut
from kresheen.models.data_source import DataSourceConfig, new_data_source_id
from kresheen.models.diagram import Diagram, new_diagram_id
from kresheen.models.diagram_layout import DiagramElementLayout, diagram_element_layout_id
from kresheen.models.finding import Finding
from kresheen.models.manual_flow import ManualFlow, new_manual_flow_id
from kresheen.models.run_diff import (
    BoundaryChangeOut,
    ComponentDiffOut,
    FindingDiffOut,
    FlowDiffOut,
    RunDiffOut,
    ThreatDiffOut,
)
from kresheen.models.threat import Methodology
from kresheen.models.threat_model_run import ThreatModelRun, new_run_id
from kresheen.models.trust_boundary import (
    TrustBoundaryAssignment,
    new_trust_boundary_assignment_id,
)
from kresheen.models.user import User
from kresheen.plugins import get_registry
from kresheen.secrets import github_token as gh_token
from kresheen.secrets.store import DbSecretStore, SecretKeyMissing
from kresheen.storage.repository import Repository

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/applications", tags=["applications"], dependencies=[Depends(get_current_session), Depends(authorize_application)]
)

UNGROUPED = "ungrouped"

class CreateApplicationRequest(BaseModel):
    name: str
    description: str = ""
    group_id: str | None = None
    owner: str = ""
    reviewer: str = ""
    contributors: list[str] = Field(default_factory=list)


class MoveApplicationRequest(BaseModel):
    # null moves the application to the virtual "Ungrouped" bucket.
    group_id: str | None


class UpdateApplicationMetadataRequest(BaseModel):
    """Full replace, not a partial update: the edit form always submits every
    field together (same as CreateApplicationRequest), so there's no
    unset-vs-explicitly-empty ambiguity to handle."""

    name: str
    description: str = ""
    owner: str = ""
    reviewer: str = ""
    contributors: list[str] = Field(default_factory=list)
    # Which threat-generation methodologies are active. See models/application.py's docstring.
    methodologies: list[Methodology] = Field(default_factory=lambda: [DEFAULT_METHODOLOGY])


class CreateRunRequest(BaseModel):
    # Scan this git ref (branch, tag or commit SHA) instead of each
    # github_repository data source's configured one, for this run only.
    source_ref: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9._/@-]+$")

    @field_validator("source_ref")
    @classmethod
    def _no_path_traversal(cls, value: str | None) -> str | None:
        # The ref is interpolated into a GitHub API URL path carrying the source's token.
        if value is not None and (".." in value or value.startswith("/")):
            raise ValueError("invalid ref")
        return value


def _has_lone_surrogate(value: object, depth: int = 0) -> bool:
    if depth > 20:
        return False
    if isinstance(value, str):
        return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)
    if isinstance(value, dict):
        return any(_has_lone_surrogate(k, depth + 1) or _has_lone_surrogate(v, depth + 1) for k, v in value.items())
    if isinstance(value, list):
        return any(_has_lone_surrogate(v, depth + 1) for v in value)
    return False


class CreateDataSourceRequest(BaseModel):
    type: str
    connection_details: dict = Field(default_factory=dict)

    @field_validator("connection_details")
    @classmethod
    def _text_must_be_valid_unicode(cls, value: dict) -> dict:
        # A lone surrogate (JSON "\\ud800") cannot be encoded as UTF-8, so hashing or storing it crashed with a 500.
        if _has_lone_surrogate(value):
            raise ValueError("Text contains invalid Unicode (an unpaired surrogate)")
        return value


class StalenessOut(BaseModel):
    """Whether the application's current data sources have changed since its
    latest run (see engine/provenance.py's input_digest) -- a signal for the
    UI to nudge a re-run, not a hard gate."""

    stale: bool
    new_data_source_ids: list[str] = Field(default_factory=list)
    changed_data_source_ids: list[str] = Field(default_factory=list)
    removed_data_source_ids: list[str] = Field(default_factory=list)


class RunDfdOut(BaseModel):
    nodes: list[dict]
    edges: list[dict]
    # Saved canvas origin per trust-boundary label (from the diagram's layout
    # rows); a boundary with no entry uses the auto-stacked layout.
    boundaries: list[dict] = Field(default_factory=list)


class SaveTrustBoundaryRequest(BaseModel):
    component_name: str
    trust_boundary: str


class CreateDiagramRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class UpdateDiagramRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class DiagramLayoutRequest(BaseModel):
    """Partial update -- an omitted field keeps its existing (or default)
    value. `hidden=False` and a `None` position are the defaults for an
    element with no saved layout row (see DiagramElementLayout's docstring:
    absence means "visible, default position", not itself meaningful)."""

    hidden: bool | None = None
    position_x: float | None = None
    position_y: float | None = None


# Client-supplied ids exist only so undo can restore a deleted component
# under its original id (manual flows reference it as "asset:<id>"). Locking
# them to the server-generated shape, plus the collision check in the create
# routes, keeps this from being a way to overwrite some other row.
_MANUAL_ASSET_ID_RE = re.compile(r"^MANUAL-[0-9a-f]{8,32}$")
_MANUAL_FLOW_ID_RE = re.compile(r"^MFLOW-[0-9a-f]{8,32}$")


class UpdateManualAssetRequest(BaseModel):
    """Move (both coordinates) and/or rename. The type is deliberately not
    editable: threat keys embed it, so changing it would orphan every status."""

    position_x: float | None = None
    position_y: float | None = None
    name: str | None = Field(default=None, max_length=200)


class UpdateManualFlowRequest(BaseModel):
    # Empty string clears the label.
    label: str = Field(max_length=200)


class CreateManualAssetRequest(BaseModel):
    id: str | None = Field(default=None, pattern=_MANUAL_ASSET_ID_RE.pattern)
    name: str
    type: str
    trust_boundary: str | None = None
    # Canvas drop position (drag-and-drop placement) -- see
    # Asset.position_x/y's docstring for why this only applies to manual
    # assets.
    position_x: float | None = None
    position_y: float | None = None


class CreateManualFlowRequest(BaseModel):
    id: str | None = Field(default=None, pattern=_MANUAL_FLOW_ID_RE.pattern)
    source_ref: str
    target_ref: str
    label: str | None = None


class SbomOut(BaseModel):
    """Frontend-friendly projection of the stored SBOM fact (drops the raw
    CycloneDX document's `$schema`/`bomFormat`/`serialNumber`/`metadata`
    boilerplate). `components`/`vulnerabilities`/the two counts are already
    filtered to real application dependencies by
    `engine/ingest/github_repository_ingestor.py`'s `_facts_from_cyclonedx`
    -- GitHub Actions usage and the scanned-directory pseudo-component are
    excluded there, not here, so there's one place that decides what
    counts as a real dependency. `no_lockfile_detected`/`manifest_files_found`
    let the frontend distinguish "found real dependencies with genuinely
    zero vulnerabilities" from "found nothing to report because no
    lockfile was present to resolve exact versions"."""

    format: str
    component_count: int
    vulnerability_count: int
    components: list[dict]
    vulnerabilities: list[dict]
    no_lockfile_detected: bool
    manifest_files_found: list[str]


def _get_application_or_404(application_id: str, repo: Repository) -> Application:
    application = repo.get_application(application_id)
    if application is None:
        raise HTTPException(status_code=404, detail="Unknown application")
    return application


def _get_diagram_or_404(application_id: str, diagram_id: str, repo: Repository) -> Diagram:
    diagram = repo.get_diagram(diagram_id)
    if diagram is None or diagram.application_id != application_id:
        raise HTTPException(status_code=404, detail="Unknown diagram")
    return diagram


@router.get("", response_model=list[Application])
def list_applications(
    group_id: str | None = None, user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)
) -> list[Application]:
    """`group_id` filters to one group; the literal "ungrouped" selects
    applications with no group. Omitted = every application."""
    groups = {g.id: g for g in repo.list_groups()}
    applications = [
        a for a in repo.list_applications() if can_view_group(user, groups.get(a.group_id) if a.group_id else None, repo)
    ]
    if group_id is None:
        return applications
    wanted = None if group_id == UNGROUPED else group_id
    return [a for a in applications if a.group_id == wanted]


@router.post("", response_model=Application, dependencies=[Depends(require_csrf)])
def create_application(
    body: CreateApplicationRequest,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> Application:
    if body.group_id is not None and repo.get_group(body.group_id) is None:
        raise HTTPException(status_code=422, detail="Unknown group")
    require_group_role(user, body.group_id, "editor", repo, what="group")
    now = datetime.now(UTC)
    application = Application(
        id=new_application_id(),
        name=body.name,
        description=body.description,
        group_id=body.group_id,
        owner_user_id=user.id,
        owner=body.owner,
        reviewer=body.reviewer,
        contributors=body.contributors,
        created_at=now,
        updated_at=now,
    )
    repo.save_application(application)
    return application


class SampleOut(BaseModel):
    application_id: str
    run_id: str


class SampleRequest(BaseModel):
    sample: SampleKey = DEFAULT_SAMPLE


@router.post("/sample", response_model=SampleOut, dependencies=[Depends(require_csrf)])
def create_sample_application(
    request: Request,
    body: SampleRequest | None = None,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> SampleOut:
    """Creates (ungrouped) and runs one bundled sample model (engine/samples) so a first-time user has
    something to explore. Each call makes a new copy; it is an ordinary application the user can edit or
    delete. No body means the online-shop sample."""
    require_group_role(user, None, "editor", repo, what="group")
    application = SAMPLES[(body or SampleRequest()).sample].build(repo, user.id)
    run = create_run(application.id, request, None, user, repo)
    return SampleOut(application_id=application.id, run_id=run.id)


@router.get("/{application_id}", response_model=Application)
def get_application(application_id: str, repo: Repository = Depends(get_repo)) -> Application:
    return _get_application_or_404(application_id, repo)


class ReviewRequest(BaseModel):
    reviewed: bool


@router.put("/{application_id}/review", response_model=Application, dependencies=[Depends(require_csrf)])
def set_reviewed(
    application_id: str,
    body: ReviewRequest,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> Application:
    """Marks the model as reviewed (now, by the caller) or clears the mark."""
    application = _get_application_or_404(application_id, repo)
    now = datetime.now(UTC)
    application.reviewed_at = now if body.reviewed else None
    application.reviewed_by = user.email if body.reviewed else ""
    application.updated_at = now
    repo.save_application(application)
    return application


@router.patch(
    "/{application_id}/metadata", response_model=Application, dependencies=[Depends(require_csrf)]
)
def update_application_metadata(
    application_id: str, body: UpdateApplicationMetadataRequest, repo: Repository = Depends(get_repo)
) -> Application:
    """Name, description and model metadata (owner, reviewer, contributors).
    Free text, not validated
    against real platform users -- see models/application.py's docstring."""
    application = _get_application_or_404(application_id, repo)
    # A methodology the application already holds may stay even if it has become unavailable (an expired licence);
    # adding one that is not offered is refused.
    require_available_methodologies(body.methodologies, allow_custom=False, keep=application.methodologies)
    application = application.model_copy(
        update={
            "name": body.name,
            "description": body.description,
            "owner": body.owner,
            "reviewer": body.reviewer,
            "contributors": body.contributors,
            "methodologies": body.methodologies,
            "updated_at": datetime.now(UTC),
        }
    )
    repo.save_application(application)
    return application


@router.patch("/{application_id}/group", response_model=Application, dependencies=[Depends(require_csrf)])
def move_application(
    application_id: str,
    body: MoveApplicationRequest,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> Application:
    application = _get_application_or_404(application_id, repo)
    if body.group_id is not None and repo.get_group(body.group_id) is None:
        raise HTTPException(status_code=422, detail="Unknown group")
    # The router dependency already required editor on the *current* group.
    require_group_role(user, body.group_id, "editor", repo, what="group")
    application = application.model_copy(update={"group_id": body.group_id, "updated_at": datetime.now(UTC)})
    repo.save_application(application)
    return application


@router.delete("/{application_id}", status_code=204, dependencies=[Depends(require_csrf)])
def delete_application(application_id: str, repo: Repository = Depends(get_repo)) -> None:
    """Confirmation of intent lives client-side (a modal, per the
    Applications tab's design) -- this route just performs the delete."""
    _get_application_or_404(application_id, repo)
    data_sources = repo.list_data_sources_for_application(application_id)
    repo.delete_application(application_id)
    gh_token.delete_stored_tokens(repo, data_sources)
    get_registry().application_deleted(application_id)


class DataSourceOut(BaseModel):
    """A data source as the API returns it: the GitHub token (and its stored reference) is never included, only
    whether one is saved and its last four characters."""

    id: str
    application_id: str
    type: str
    connection_details: dict
    digest: str | None = None
    created_at: datetime
    last_ingested_at: datetime | None = None
    has_token: bool = False
    token_hint: str | None = None


def _data_source_out(data_source: DataSourceConfig) -> DataSourceOut:
    return DataSourceOut(
        id=data_source.id,
        application_id=data_source.application_id,
        type=data_source.type,
        connection_details=gh_token.strip_token_keys(data_source.connection_details),
        digest=data_source.digest,
        created_at=data_source.created_at,
        last_ingested_at=data_source.last_ingested_at,
        has_token=gh_token.has_token(data_source),
        token_hint=gh_token.token_hint(data_source),
    )


class SetTokenRequest(BaseModel):
    token: str = Field(min_length=1, max_length=500)


def _require_secret_store(repo: Repository) -> None:
    try:
        DbSecretStore(repo)
    except SecretKeyMissing:
        raise HTTPException(
            status_code=400,
            detail="Cannot store a GitHub token: the server has no KRESHEEN_SECRET_KEY set. Ask the administrator.",
        ) from None


def _get_github_source_or_404(application_id: str, data_source_id: str, repo: Repository) -> DataSourceConfig:
    _get_application_or_404(application_id, repo)
    data_source = repo.get_data_source(data_source_id)
    if data_source is None or data_source.application_id != application_id:
        raise HTTPException(status_code=404, detail="Data source not found")
    if data_source.type != "github_repository":
        raise HTTPException(status_code=422, detail="Only a GitHub repository data source has a token")
    return data_source


@router.get("/{application_id}/data-sources", response_model=list[DataSourceOut])
def list_data_sources(application_id: str, repo: Repository = Depends(get_repo)) -> list[DataSourceOut]:
    _get_application_or_404(application_id, repo)
    data_sources = repo.list_data_sources_for_application(application_id)
    for data_source in data_sources:
        gh_token.secure_legacy_token(repo, data_source)  # a no-op unless an old row still holds a plaintext token
    return [_data_source_out(ds) for ds in data_sources]


@router.post(
    "/{application_id}/data-sources",
    response_model=DataSourceOut,
    dependencies=[Depends(require_csrf)],
)
def create_data_source(
    application_id: str, body: CreateDataSourceRequest, repo: Repository = Depends(get_repo)
) -> DataSourceOut:
    _get_application_or_404(application_id, repo)
    if body.type not in SUPPORTED_DATA_SOURCE_TYPES:
        raise HTTPException(status_code=422, detail=f"Unsupported data source type: {body.type}")
    details = body.connection_details or {}
    raw_token = details.get(gh_token.PLAINTEXT_KEY)
    if raw_token is not None and not isinstance(raw_token, str):
        raise HTTPException(status_code=422, detail="github_token must be a string")
    token = raw_token.strip() if raw_token else ""
    if token and body.type != "github_repository":
        raise HTTPException(status_code=422, detail="Only a GitHub repository data source has a token")
    if token:
        _require_secret_store(repo)  # before anything is stored
    details = gh_token.strip_token_keys(details)  # a client may not supply a ref or hint
    if body.type == "github_repository" and (details.get("repo_url") or details.get("ref")):
        try:  # a source with no URL yet is allowed to exist; the ingestor validates strictly again at run time
            validate_github_details(details)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    data_source = DataSourceConfig(
        id=new_data_source_id(),
        application_id=application_id,
        type=body.type,  # type: ignore[arg-type]
        connection_details=details,
        created_at=datetime.now(UTC),
    )
    if token:
        gh_token.set_token(repo, data_source, token)
    data_source.digest = input_digest(data_source)
    repo.save_data_source(data_source)
    return _data_source_out(data_source)


@router.put(
    "/{application_id}/data-sources/{data_source_id}/token",
    response_model=DataSourceOut,
    dependencies=[Depends(require_csrf)],
)
def replace_data_source_token(
    application_id: str, data_source_id: str, body: SetTokenRequest, repo: Repository = Depends(get_repo)
) -> DataSourceOut:
    data_source = _get_github_source_or_404(application_id, data_source_id, repo)
    token = body.token.strip()
    if not token:
        raise HTTPException(status_code=422, detail="Token must not be empty")
    _require_secret_store(repo)
    gh_token.set_token(repo, data_source, token)
    data_source.digest = input_digest(data_source)
    repo.save_data_source(data_source)
    return _data_source_out(data_source)


@router.delete(
    "/{application_id}/data-sources/{data_source_id}/token",
    response_model=DataSourceOut,
    dependencies=[Depends(require_csrf)],
)
def remove_data_source_token(
    application_id: str, data_source_id: str, repo: Repository = Depends(get_repo)
) -> DataSourceOut:
    data_source = _get_github_source_or_404(application_id, data_source_id, repo)
    gh_token.clear_token(repo, data_source)
    data_source.digest = input_digest(data_source)
    repo.save_data_source(data_source)
    return _data_source_out(data_source)


@router.delete(
    "/{application_id}/data-sources/{data_source_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
def delete_data_source(
    application_id: str, data_source_id: str, repo: Repository = Depends(get_repo)
) -> None:
    _get_application_or_404(application_id, repo)
    data_source = repo.get_data_source(data_source_id)
    repo.delete_data_source(data_source_id)
    if data_source is not None and data_source.application_id == application_id:
        gh_token.delete_stored_tokens(repo, [data_source])


@router.get("/{application_id}/staleness", response_model=StalenessOut)
def get_staleness(application_id: str, repo: Repository = Depends(get_repo)) -> StalenessOut:
    """Compares each current data source's live digest against the ones
    stamped on the application's latest run. No latest run, or a latest run
    with no provenance stamp (see
    ThreatModelRun.input_digests' docstring), is unconditionally stale --
    an unknown state is exactly the case a user should be nudged to re-run.
    The comparison itself lives in `engine/provenance.py::compute_staleness`,
    shared with the group rollup (`api_groups.py`)."""
    application = _get_application_or_404(application_id, repo)
    result = compute_staleness(application, repo)
    return StalenessOut(
        stale=result.stale,
        new_data_source_ids=result.new_data_source_ids,
        changed_data_source_ids=result.changed_data_source_ids,
        removed_data_source_ids=result.removed_data_source_ids,
    )


@router.post("/{application_id}/runs", response_model=ThreatModelRun, dependencies=[Depends(require_csrf)])
def create_run(
    application_id: str,
    request: Request,
    body: CreateRunRequest | None = None,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> ThreatModelRun:
    """Synchronous for v1: a run is a deliberate, infrequent user action, not a
    hot path, so no BackgroundTasks/queue.
    """
    application = _get_application_or_404(application_id, repo)
    # Bounded concurrency: a burst of runs used to fight over the CPU and the database (some failed with
    # `database is locked`); now a few run, a few wait, and the rest are told to retry.
    try:
        with request.app.state.run_gate.slot():
            return _create_and_execute_run(application, application_id, body, user, repo)
    except RunQueueFull:
        raise HTTPException(
            status_code=429, detail="Too many runs are in progress; try again shortly", headers={"Retry-After": "15"}
        ) from None


def _create_and_execute_run(
    application: Application,
    application_id: str,
    body: CreateRunRequest | None,
    user: User,
    repo: Repository,
) -> ThreatModelRun:
    # No data sources is allowed: a blank model the user builds by hand. The
    # run ingests nothing, and the Application-scoped manual components and
    # flows still merge into its DFD (see engine/dfd/merge.py).
    data_sources = repo.list_data_sources_for_application(application_id)

    run = ThreatModelRun(
        id=new_run_id(),
        application_id=application_id,
        triggered_by_user_id=user.id,
        data_source_config_ids=[ds.id for ds in data_sources],
        started_at=datetime.now(UTC),
        source_ref=body.source_ref if body else None,
    )
    repo.save_run(run)

    application.latest_run_id = run.id
    application.status = "active"
    application.updated_at = datetime.now(UTC)
    repo.save_application(application)

    try:
        execute_run(repo, run.id)
    except Exception:
        # status/error_message are already recorded on the run itself by
        # execute_run -- the route reports failure via the returned run
        # body (status="failed"), not a 500, so the frontend can render it
        # the same way it renders any other run status.
        logger.exception("Threat model run %s failed", run.id)
    return repo.get_run(run.id) or run


@router.get("/{application_id}/runs", response_model=list[ThreatModelRun])
def list_runs(application_id: str, repo: Repository = Depends(get_repo)) -> list[ThreatModelRun]:
    _get_application_or_404(application_id, repo)
    return [reconcile_run(repo, run) for run in repo.list_runs_for_application(application_id)]


@router.get("/{application_id}/runs/{run_id}", response_model=ThreatModelRun)
def get_run(application_id: str, run_id: str, repo: Repository = Depends(get_repo)) -> ThreatModelRun:
    _get_application_or_404(application_id, repo)
    run = repo.get_run(run_id)
    if run is None or run.application_id != application_id:
        raise HTTPException(status_code=404, detail="Unknown run")
    return reconcile_run(repo, run)


@router.get("/{application_id}/runs/{run_id}/dfd", response_model=RunDfdOut)
def get_run_dfd(
    application_id: str, run_id: str, diagram_id: str | None = None, repo: Repository = Depends(get_repo)
) -> RunDfdOut:
    """Same node/edge shape as api_map.py's `/api/map`, scoped to one run
    instead of the whole deployment -- lets the Application-run detail page
    reuse the Map page's existing React Flow rendering unchanged.

    Merges three things, all resolved fresh on every request, never
    persisted pre-joined: (1) this run's auto-generated Assets/AssetFlows,
    regenerated from scratch every execution; (2) this Application's
    manual Assets (source="manual", run_id=None -- never touched by a
    run's regenerate-in-place delete, so they appear on every run's
    diagram); (3) this Application's ManualFlows and
    TrustBoundaryAssignments, resolved by component *name* against
    whichever nodes ended up in (1)+(2) for this specific request -- see
    models/trust_boundary.py and models/manual_flow.py for why name-based
    resolution is required (Asset ids aren't stable across runs, by
    design).

    `diagram_id` selects which diagram's view to render (hidden elements
    dropped, its own saved positions used); omitted resolves to the
    Application's default diagram (`get_or_create_default_diagram`), so an
    Application always has one even on its very first DFD request."""
    _get_application_or_404(application_id, repo)
    diagram = (
        _get_diagram_or_404(application_id, diagram_id, repo)
        if diagram_id is not None
        else get_or_create_default_diagram(application_id, repo)
    )
    nodes, edges, boundaries = build_run_dfd(application_id, run_id, repo, diagram.id)
    return RunDfdOut(nodes=nodes, edges=edges, boundaries=boundaries)


@router.get("/{application_id}/diagrams", response_model=list[Diagram])
def list_diagrams(application_id: str, repo: Repository = Depends(get_repo)) -> list[Diagram]:
    _get_application_or_404(application_id, repo)
    get_or_create_default_diagram(application_id, repo)
    return repo.list_diagrams_for_application(application_id)


@router.post("/{application_id}/diagrams", response_model=Diagram, dependencies=[Depends(require_csrf)])
def create_diagram(
    application_id: str, body: CreateDiagramRequest, repo: Repository = Depends(get_repo)
) -> Diagram:
    _get_application_or_404(application_id, repo)
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="A diagram needs a name")
    now = datetime.now(UTC)
    diagram = Diagram(id=new_diagram_id(), application_id=application_id, name=name, created_at=now, updated_at=now)
    repo.save_diagram(diagram)
    return diagram


@router.patch(
    "/{application_id}/diagrams/{diagram_id}", response_model=Diagram, dependencies=[Depends(require_csrf)]
)
def rename_diagram(
    application_id: str, diagram_id: str, body: UpdateDiagramRequest, repo: Repository = Depends(get_repo)
) -> Diagram:
    _get_application_or_404(application_id, repo)
    diagram = _get_diagram_or_404(application_id, diagram_id, repo)
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="A diagram needs a name")
    diagram = diagram.model_copy(update={"name": name, "updated_at": datetime.now(UTC)})
    repo.save_diagram(diagram)
    return diagram


@router.delete(
    "/{application_id}/diagrams/{diagram_id}", status_code=204, dependencies=[Depends(require_csrf)]
)
def delete_diagram(application_id: str, diagram_id: str, repo: Repository = Depends(get_repo)) -> None:
    """Removes this diagram and its own visual state only -- the shared
    Assets/ManualFlows/TrustBoundaryAssignments/threats it displayed are
    untouched. Refuses to delete an Application's last diagram so it's
    never left without one to view."""
    _get_application_or_404(application_id, repo)
    _get_diagram_or_404(application_id, diagram_id, repo)
    if len(repo.list_diagrams_for_application(application_id)) <= 1:
        raise HTTPException(status_code=422, detail="Can't delete an Application's only diagram")
    repo.delete_diagram(diagram_id)


@router.get("/{application_id}/diagrams/{diagram_id}/layout", response_model=list[DiagramElementLayout])
def list_diagram_layout(
    application_id: str, diagram_id: str, repo: Repository = Depends(get_repo)
) -> list[DiagramElementLayout]:
    """Every saved layout row for this diagram, including hidden elements --
    unlike the DFD route, this doesn't filter anything out, so the frontend
    can offer "show" for something currently hidden."""
    _get_application_or_404(application_id, repo)
    _get_diagram_or_404(application_id, diagram_id, repo)
    return repo.list_diagram_element_layouts(diagram_id)


@router.put(
    "/{application_id}/diagrams/{diagram_id}/layout",
    response_model=DiagramElementLayout,
    dependencies=[Depends(require_csrf)],
)
def save_diagram_layout(
    application_id: str,
    diagram_id: str,
    element_key: str,
    body: DiagramLayoutRequest,
    repo: Repository = Depends(get_repo),
) -> DiagramElementLayout:
    """`element_key` is a query param, not a path segment -- a component
    name may contain `/` (see delete_trust_boundary's docstring for the
    same reason), and a flow key always contains `->`."""
    _get_application_or_404(application_id, repo)
    _get_diagram_or_404(application_id, diagram_id, repo)
    existing = next(
        (l for l in repo.list_diagram_element_layouts(diagram_id) if l.element_key == element_key), None
    )
    layout = DiagramElementLayout(
        id=diagram_element_layout_id(diagram_id, element_key),
        diagram_id=diagram_id,
        element_key=element_key,
        hidden=body.hidden if body.hidden is not None else (existing.hidden if existing else False),
        position_x=body.position_x if body.position_x is not None else (existing.position_x if existing else None),
        position_y=body.position_y if body.position_y is not None else (existing.position_y if existing else None),
        updated_at=datetime.now(UTC),
    )
    repo.save_diagram_element_layout(layout)
    return layout


@router.delete(
    "/{application_id}/diagrams/{diagram_id}/layout",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
def delete_diagram_layout(
    application_id: str, diagram_id: str, element_key: str, repo: Repository = Depends(get_repo)
) -> None:
    """Clears a saved layout row -- the element goes back to "visible,
    default position" rather than being deleted from the diagram."""
    _get_application_or_404(application_id, repo)
    _get_diagram_or_404(application_id, diagram_id, repo)
    existing = next(
        (l for l in repo.list_diagram_element_layouts(diagram_id) if l.element_key == element_key), None
    )
    if existing:
        repo.delete_diagram_element_layout(existing.id)


@router.get("/{application_id}/runs/{run_id}/diff", response_model=RunDiffOut)
def get_run_diff(
    application_id: str, run_id: str, against: str | None = None, repo: Repository = Depends(get_repo)
) -> RunDiffOut:
    """Diffs `run_id` against `against` if given, else the immediately
    preceding *completed* run for this application by start time (a failed
    re-run is skipped as a baseline, so it never gets picked as "what
    changed since"). `previous_run_id=None` (every list empty) if there's
    nothing completed to compare against yet."""
    _get_application_or_404(application_id, repo)
    current_run = repo.get_run(run_id)
    if current_run is None or current_run.application_id != application_id:
        raise HTTPException(status_code=404, detail="Unknown run")

    if against is not None:
        previous_run = repo.get_run(against)
        if previous_run is None or previous_run.application_id != application_id:
            raise HTTPException(status_code=404, detail="Unknown comparison run")
    else:
        completed_before = [
            r
            for r in repo.list_runs_for_application(application_id)
            if r.status == "completed" and r.started_at < current_run.started_at
        ]
        previous_run = completed_before[-1] if completed_before else None

    if previous_run is None:
        return RunDiffOut(current_run_id=run_id, previous_run_id=None)

    previous_threats = generate_run_threats(application_id, previous_run.id, repo)
    current_threats = generate_run_threats(application_id, run_id, repo)
    diff = build_run_diff(
        application_id,
        previous_run.id,
        run_id,
        repo,
        previous_threats=previous_threats,
        current_threats=current_threats,
    )
    return RunDiffOut(
        current_run_id=run_id,
        previous_run_id=previous_run.id,
        new_components=[ComponentDiffOut(key=e.key, type=e.type, name=e.name) for e in diff.new_components],
        removed_components=[ComponentDiffOut(key=e.key, type=e.type, name=e.name) for e in diff.removed_components],
        new_flows=[
            FlowDiffOut(
                key=e.key, source_name=e.source_name, target_name=e.target_name, crosses_boundary=e.crosses_boundary
            )
            for e in diff.new_flows
        ],
        removed_flows=[
            FlowDiffOut(key=e.key, source_name=e.source_name, target_name=e.target_name)
            for e in diff.removed_flows
        ],
        new_threats=[ThreatDiffOut(key=e.key, title=e.title, severity=e.severity) for e in diff.new_threats],
        resolved_threats=[
            ThreatDiffOut(key=e.key, title=e.title, severity=e.severity) for e in diff.resolved_threats
        ],
        new_findings=[
            FindingDiffOut(title=e.title, severity=e.severity, domain=e.domain) for e in diff.new_findings
        ],
        resolved_findings=[
            FindingDiffOut(title=e.title, severity=e.severity, domain=e.domain) for e in diff.resolved_findings
        ],
        boundary_changes=[
            BoundaryChangeOut(
                name=e.name, type=e.type, from_boundary=e.from_boundary, to_boundary=e.to_boundary
            )
            for e in diff.boundary_changes
        ],
    )


@router.get("/{application_id}/runs/{run_id}/attack-paths", response_model=AttackPathsOut)
def get_attack_paths(application_id: str, run_id: str, repo: Repository = Depends(get_repo)) -> AttackPathsOut:
    """Traces reachability from every external entity to a data store or
    crown-jewel asset over the run's merged DFD (engine/attack_paths.py).
    Empty `paths`, not a 404, when nothing is reachable -- that's a
    legitimate (reassuring) result, not an error state."""
    _get_application_or_404(application_id, repo)
    run = repo.get_run(run_id)
    if run is None or run.application_id != application_id:
        raise HTTPException(status_code=404, detail="Unknown run")

    elements, flows = load_dfd_model(application_id, run_id, repo)
    paths = find_attack_paths(elements, flows)
    return AttackPathsOut(
        paths=[
            AttackPathOut(
                source_name=p.source_name,
                target_name=p.target_name,
                target_type=p.target_type,
                is_crown_jewel=p.is_crown_jewel,
                risk=p.risk,
                risk_factors=p.risk_factors,
                boundary_crossings=p.boundary_crossings,
                hops=[
                    AttackPathHopOut(
                        from_name=h.from_name,
                        to_name=h.to_name,
                        flow_label=h.flow_label,
                        crosses_boundary=h.crosses_boundary,
                        authenticated=h.authenticated,
                        encrypted=h.encrypted,
                    )
                    for h in p.hops
                ],
            )
            for p in paths
        ]
    )


@router.put(
    "/{application_id}/trust-boundaries",
    response_model=TrustBoundaryAssignment,
    dependencies=[Depends(require_csrf)],
)
def save_trust_boundary(
    application_id: str, body: SaveTrustBoundaryRequest, repo: Repository = Depends(get_repo)
) -> TrustBoundaryAssignment:
    _get_application_or_404(application_id, repo)
    existing = next(
        (
            a
            for a in repo.list_trust_boundary_assignments(application_id)
            if a.component_name == body.component_name
        ),
        None,
    )
    now = datetime.now(UTC)
    assignment = TrustBoundaryAssignment(
        id=existing.id if existing else new_trust_boundary_assignment_id(),
        application_id=application_id,
        component_name=body.component_name,
        trust_boundary=body.trust_boundary,
        created_at=existing.created_at if existing else now,
        updated_at=now,
    )
    repo.save_trust_boundary_assignment(assignment)
    return assignment


@router.delete(
    "/{application_id}/trust-boundaries",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
def delete_trust_boundary(
    application_id: str, component_name: str, repo: Repository = Depends(get_repo)
) -> None:
    """Clears a component's boundary label. `component_name` is a query
    param, not a path segment -- a component name containing a `/` (e.g.
    "Deployment/web") breaks Starlette's default single-segment path
    converter (and %2F-encoding it doesn't reliably survive ASGI's own
    path decoding), so a query param sidesteps that entirely."""
    _get_application_or_404(application_id, repo)
    existing = next(
        (
            a
            for a in repo.list_trust_boundary_assignments(application_id)
            if a.component_name == component_name
        ),
        None,
    )
    if existing:
        repo.delete_trust_boundary_assignment(existing.id)


@router.post(
    "/{application_id}/manual-assets", response_model=Asset, dependencies=[Depends(require_csrf)]
)
def create_manual_asset(
    application_id: str, body: CreateManualAssetRequest, repo: Repository = Depends(get_repo)
) -> Asset:
    _get_application_or_404(application_id, repo)
    try:
        asset_type = AssetType(body.type)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Unknown asset type: {body.type}") from None
    if body.id is not None and repo.get_asset(body.id) is not None:
        raise HTTPException(status_code=409, detail="A component with that id already exists")
    asset = Asset(
        id=body.id or new_manual_asset_id(),
        name=body.name,
        type=asset_type,
        trust_boundary=body.trust_boundary,
        source="manual",
        application_id=application_id,
        run_id=None,
        position_x=body.position_x,
        position_y=body.position_y,
        created_at=datetime.now(UTC),
    )
    repo.save_asset(asset)
    return asset


@router.delete(
    "/{application_id}/manual-assets/{asset_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
def delete_manual_asset(application_id: str, asset_id: str, repo: Repository = Depends(get_repo)) -> None:
    _get_application_or_404(application_id, repo)
    asset = repo.get_asset(asset_id)
    if asset is None or asset.application_id != application_id or asset.source != "manual":
        raise HTTPException(status_code=404, detail="Unknown manual component")
    repo.delete_asset(asset_id)


@router.patch(
    "/{application_id}/manual-assets/{asset_id}",
    response_model=Asset,
    dependencies=[Depends(require_csrf)],
)
def update_manual_asset(
    application_id: str, asset_id: str, body: UpdateManualAssetRequest, repo: Repository = Depends(get_repo)
) -> Asset:
    """Moves and/or renames a manual component. Auto-generated components are
    rebuilt from their sources every run, so only manual ones are editable."""
    application = _get_application_or_404(application_id, repo)
    asset = repo.get_asset(asset_id)
    if asset is None or asset.application_id != application_id or asset.source != "manual":
        raise HTTPException(status_code=404, detail="Unknown manual component")
    if (body.position_x is None) != (body.position_y is None):
        raise HTTPException(status_code=422, detail="Provide both position_x and position_y, or neither")
    if body.name is None and body.position_x is None:
        raise HTTPException(status_code=422, detail="Nothing to update")

    updates: dict = {}
    if body.position_x is not None:
        updates["position_x"] = body.position_x
        updates["position_y"] = body.position_y

    old_name = asset.name
    new_name = body.name.strip() if body.name is not None else old_name
    if body.name is not None:
        if not new_name:
            raise HTTPException(status_code=422, detail="A component needs a name")
        if new_name != old_name:
            # merge_run_dfd resolves overlays by name, so two components sharing
            # one would silently merge their state.
            taken = {a.name for a in repo.list_manual_assets_for_application(application_id) if a.id != asset.id}
            if application.latest_run_id:
                taken |= {a.name for a in repo.list_assets_for_run(application.latest_run_id)}
            if new_name in taken:
                raise HTTPException(status_code=409, detail="Another component already has that name")
            updates["name"] = new_name

    asset = asset.model_copy(update=updates)
    repo.save_asset(asset)
    if new_name != old_name:
        rename_component_overlays(
            repo, application_id, element_type=asset.type.value, old=old_name, new=new_name
        )
    return asset


@router.post(
    "/{application_id}/manual-flows", response_model=ManualFlow, dependencies=[Depends(require_csrf)]
)
def create_manual_flow(
    application_id: str, body: CreateManualFlowRequest, repo: Repository = Depends(get_repo)
) -> ManualFlow:
    _get_application_or_404(application_id, repo)
    now = datetime.now(UTC)
    if body.id is not None and repo.get_manual_flow(body.id) is not None:
        raise HTTPException(status_code=409, detail="A connection with that id already exists")
    flow = ManualFlow(
        id=body.id or new_manual_flow_id(),
        application_id=application_id,
        source_ref=body.source_ref,
        target_ref=body.target_ref,
        label=body.label,
        created_at=now,
        updated_at=now,
    )
    repo.save_manual_flow(flow)
    return flow


@router.patch(
    "/{application_id}/manual-flows/{flow_id}",
    response_model=ManualFlow,
    dependencies=[Depends(require_csrf)],
)
def update_manual_flow(
    application_id: str, flow_id: str, body: UpdateManualFlowRequest, repo: Repository = Depends(get_repo)
) -> ManualFlow:
    """Edits a manual connection's label. Threat keys for a flow use its endpoint
    names, not its label, so nothing else needs to follow."""
    _get_application_or_404(application_id, repo)
    flow = repo.get_manual_flow(flow_id)
    if flow is None or flow.application_id != application_id:
        raise HTTPException(status_code=404, detail="Unknown connection")
    flow = flow.model_copy(update={"label": body.label.strip() or None, "updated_at": datetime.now(UTC)})
    repo.save_manual_flow(flow)
    return flow


@router.delete(
    "/{application_id}/manual-flows/{flow_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
def delete_manual_flow(application_id: str, flow_id: str, repo: Repository = Depends(get_repo)) -> None:
    _get_application_or_404(application_id, repo)
    repo.delete_manual_flow(flow_id)


@router.get("/{application_id}/runs/{run_id}/findings", response_model=list[Finding])
def get_run_findings(
    application_id: str, run_id: str, repo: Repository = Depends(get_repo)
) -> list[Finding]:
    _get_application_or_404(application_id, repo)
    return repo.list_findings(run_id=run_id)


@router.get("/{application_id}/runs/{run_id}/sbom", response_model=SbomOut | None)
def get_run_sbom(application_id: str, run_id: str, repo: Repository = Depends(get_repo)) -> SbomOut | None:
    """Not every run has one -- only a `github_repository` source with
    Grype installed produces a `sbom_document` fact (see
    engine/ingest/github_repository_ingestor.py). Absence is a normal,
    non-error state (`null`), not a 404."""
    _get_application_or_404(application_id, repo)
    summary = build_sbom_summary(repo, run_id)
    return SbomOut(**summary) if summary is not None else None
