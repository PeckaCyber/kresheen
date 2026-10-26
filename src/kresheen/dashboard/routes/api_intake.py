"""Guided intake: options for the wizard, and creating a starter
model from its answers. The logic is in engine/intake.py; this only wraps it."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from kresheen.dashboard.access import require_group_role
from kresheen.dashboard.ai_calls import AiCaller, require_ai_caller, run_ai_task
from kresheen.dashboard.auth import get_current_session, get_current_user, require_csrf
from kresheen.dashboard.deps import get_repo
from kresheen.dashboard.routes.api_applications import create_run
from kresheen.engine.intake import (
    AUTHENTICATION,
    DATA_KINDS,
    SYSTEM_TYPES,
    TEMPLATES,
    THIRD_PARTIES,
    USER_GROUPS,
    IntakeAnswers,
    Option,
    create_application_from_intake,
)
from kresheen.engine.llm.policy import INTAKE_DRAFT_TASK
from kresheen.models.user import User
from kresheen.storage.repository import Repository

router = APIRouter(prefix="/api/intake", tags=["intake"], dependencies=[Depends(get_current_session)])


class OptionOut(BaseModel):
    id: str
    label: str
    help: str = ""


class TemplateOut(BaseModel):
    id: str
    title: str
    description: str
    answers: dict[str, object]


class IntakeOptionsOut(BaseModel):
    system_types: list[OptionOut]
    users: list[OptionOut]
    authentication: list[OptionOut]
    data: list[OptionOut]
    third_parties: list[OptionOut]
    templates: list[TemplateOut]


class IntakeRequest(IntakeAnswers):
    group_id: str | None = None


class IntakeCreatedOut(BaseModel):
    application_id: str
    run_id: str


def _options(options: tuple[Option, ...]) -> list[OptionOut]:
    return [OptionOut(id=o.id, label=o.label, help=o.help) for o in options]


@router.get("/options", response_model=IntakeOptionsOut)
def get_options() -> IntakeOptionsOut:
    return IntakeOptionsOut(
        system_types=_options(SYSTEM_TYPES),
        users=_options(USER_GROUPS),
        authentication=_options(AUTHENTICATION),
        data=_options(DATA_KINDS),
        third_parties=_options(THIRD_PARTIES),
        templates=[
            TemplateOut(id=t.id, title=t.title, description=t.description, answers=t.answers) for t in TEMPLATES
        ],
    )


@router.post("", response_model=IntakeCreatedOut, dependencies=[Depends(require_csrf)])
def create_from_intake(
    body: IntakeRequest, request: Request, user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)
) -> IntakeCreatedOut:
    """Creates the application, draws its starter model from the answers and runs it."""
    if body.group_id is not None and repo.get_group(body.group_id) is None:
        raise HTTPException(status_code=422, detail="Unknown group")
    require_group_role(user, body.group_id, "editor", repo, what="group")
    answers = IntakeAnswers.model_validate(body.model_dump(exclude={"group_id"}))
    application = create_application_from_intake(repo, user.id, answers, body.group_id)
    run = create_run(application.id, request, None, user, repo)
    return IntakeCreatedOut(application_id=application.id, run_id=run.id)


_DRAFT_EXTENSIONS = (".txt", ".md")


class DraftRequest(BaseModel):
    """Pasted text, or the text of a file the browser has read. `filename` is only checked, never stored."""

    text: str = Field(min_length=1)
    filename: str | None = Field(default=None, max_length=255)


class DraftWarning(BaseModel):
    pattern: str
    excerpt: str


class DraftOut(BaseModel):
    answers: dict[str, object]
    filled: list[str]
    warnings: list[DraftWarning]


@router.post("/draft", response_model=DraftOut, dependencies=[Depends(require_csrf)])
def draft_from_description(
    body: DraftRequest,
    request: Request,
    caller: AiCaller = Depends(require_ai_caller),
    repo: Repository = Depends(get_repo),
) -> DraftOut:
    """Experimental AI assist: suggested intake answers from a prose description. A POST only because the text is
    large; it creates nothing. The user reviews the answers and submits the form as usual."""
    if body.filename is not None and not body.filename.lower().endswith(_DRAFT_EXTENSIONS):
        raise HTTPException(status_code=422, detail="Only .txt and .md files are supported.")
    if len(body.text) > INTAKE_DRAFT_TASK.max_input_chars:
        # Same answer run_ai_task would give, without spending a rate-limit slot or an audit row on it.
        raise HTTPException(
            status_code=413,
            detail=f"The text is too long. The limit is {INTAKE_DRAFT_TASK.max_input_chars} characters.",
        )
    result = run_ai_task(request, repo, caller, INTAKE_DRAFT_TASK, body.text)
    draft = result.value
    answers = draft.model_dump(exclude_none=True, exclude={"filled"})
    return DraftOut(
        answers=answers,
        filled=draft.filled,
        warnings=[DraftWarning(pattern=s.pattern, excerpt=s.excerpt) for s in result.signals],
    )
