"""Login/logout/session-check for the dashboard's JSON API.

Deliberately no self-serve signup -- bootstrap the first (owner) account via
`kresheen create-user`, or, in a desktop install (`kresheen desktop`), through the one-time setup link the launcher
opens: `POST /api/auth/setup` creates the owner while no account exists and the request carries the launcher's token.
"""

from __future__ import annotations

import ipaddress
import secrets
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from kresheen.dashboard.audit import record_event
from kresheen.dashboard.auth import (
    MIN_PASSWORD_LENGTH,
    SESSION_COOKIE_NAME,
    cookie_secure,
    generate_session,
    get_current_session,
    get_current_user,
    hash_password,
    require_cookie_session,
    require_csrf,
    session_lifetime,
    verify_against_dummy,
    verify_password,
)
from kresheen.dashboard.deps import get_repo
from kresheen.dashboard.login_throttle import LoginThrottle
from kresheen.models.auth import Session
from kresheen.models.user import User, new_user_id, normalize_email
from kresheen.plugins import get_registry
from kresheen.storage.repository import Repository

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


class SessionInfo(BaseModel):
    """What the SPA needs after login/on load: the CSRF token to echo back
    on every mutating request, when to expect the session to expire, and
    the account's role (so the SPA can show/hide owner-only surfaces like
    user management)."""

    csrf_token: str
    expires_at: datetime
    role: str
    # Shown in the SPA's user menu; the caller's own address only.
    email: str = ""


def set_session_cookie(response: Response, request: Request, session: Session) -> None:
    # `secure` must track the actual request scheme: a hardcoded `secure=True`
    # cookie is never sent back over plain HTTP (browsers *and* httpx's
    # TestClient both drop it), which breaks local `kresheen serve` (plain
    # HTTP by default) and every test. If this app ever sits behind a
    # TLS-terminating reverse proxy that forwards plain HTTP to it, the scheme
    # comes from a trusted X-Forwarded-Proto header, which needs
    # `KRESHEEN_FORWARDED_ALLOW_IPS`; `cookie_secure` (dashboard/auth.py) also
    # honours `KRESHEEN_COOKIE_SECURE`.
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session.id,
        httponly=True,
        samesite="lax",
        secure=cookie_secure(request),
        max_age=int(session_lifetime().total_seconds()),
    )


@router.post("/login", response_model=SessionInfo)
def login(
    body: LoginRequest, request: Request, response: Response, repo: Repository = Depends(get_repo)
) -> SessionInfo:
    ip = request.client.host if request.client else None
    throttle: LoginThrottle = request.app.state.login_throttle
    wait = throttle.retry_after(body.email, ip)
    if wait is not None:  # before any hashing: a blocked attempt costs almost nothing
        if throttle.note_block(body.email, ip):
            record_event(
                repo,
                action="auth.login_throttled",
                user_email=body.email[:200],
                status_code=429,
                client_ip=ip,
                subject={"retry_after_seconds": str(wait)},
            )
        raise HTTPException(
            status_code=429,
            detail="Too many failed sign-in attempts; try again later",
            headers={"Retry-After": str(wait)},
        )
    user = repo.get_user_by_email(body.email)
    if user is None or not user.is_active:
        verify_against_dummy(body.password)  # same work as a real check: no timing difference by account
        authenticated: User | None = None
    else:
        authenticated = user if verify_password(body.password, user.password_hash) else None
    if authenticated is None:
        throttle.record_failure(body.email, ip)
        record_event(repo, action="auth.login_failed", user_email=body.email[:200], status_code=401, client_ip=ip)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    user = authenticated
    # A plugin that bars password sign-in (SSO-only mode) is asked only after the password has been verified,
    # so the 403 reveals nothing to someone who does not already hold the password (an unknown address and a wrong
    # password both get a 401).
    if not get_registry().password_login_allowed(user):
        record_event(
            repo,
            action="auth.login_failed",
            user_id=user.id,
            user_email=user.email,
            subject={"reason": "password_login_disabled"},
            status_code=403,
            client_ip=ip,
        )
        raise HTTPException(status_code=403, detail="Password login is disabled; use single sign-on")
    throttle.record_success(body.email, ip)

    session = generate_session(user.id)
    repo.create_session(session)
    record_event(repo, action="auth.login", user_id=user.id, user_email=user.email, status_code=200, client_ip=ip)
    set_session_cookie(response, request, session)
    return SessionInfo(csrf_token=session.csrf_token, expires_at=session.expires_at, role=user.role, email=user.email)


@router.post("/logout")
def logout(request: Request, response: Response, repo: Repository = Depends(get_repo)) -> dict[str, bool | str | None]:
    """`redirect`: where the SPA should navigate after sign-out when a plugin asks for it (for example an identity
    provider's sign-out page); None otherwise."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    redirect: str | None = None
    if session_id is not None:
        session = repo.get_session(session_id)
        if session is not None:
            user = repo.get_user(session.user_id)
            redirect = get_registry().logout_redirect(session, user)
            record_event(
                repo,
                action="auth.logout",
                user_id=session.user_id,
                user_email=user.email if user else None,
                status_code=200,
                client_ip=request.client.host if request.client else None,
            )
        repo.delete_session(session_id)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"ok": True, "redirect": redirect}


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)


@router.post(
    "/change-password",
    dependencies=[Depends(require_csrf), Depends(require_cookie_session)],
)
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_current_session),
    repo: Repository = Depends(get_repo),
) -> dict[str, bool]:
    """Self-service rotation for the *current* account only -- an owner
    changing someone else's role/active status goes through
    `PATCH /api/users/{id}` instead, which never touches a password.
    Refused for SSO/SCIM-provisioned accounts (`auth_source != "password"`):
    their password is an unusable random value the IdP is authoritative
    over, so there's nothing meaningful to verify or rotate here."""
    ip = request.client.host if request.client else None
    if user.auth_source != "password":
        raise HTTPException(
            status_code=403, detail="This account signs in via single sign-on; there is no password to change"
        )
    if not verify_password(body.current_password, user.password_hash):
        record_event(
            repo,
            action="auth.change_password_failed",
            user_id=user.id,
            user_email=user.email,
            status_code=401,
            client_ip=ip,
        )
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    updated = user.model_copy(update={"password_hash": hash_password(body.new_password)})
    repo.save_user(updated)
    # Sign out every other session: a password change is often a response to
    # a suspected compromise, so a stolen session must not outlive it.
    repo.delete_sessions_for_user(user.id, keep_session_id=session.id)
    # API tokens are long-lived credentials too; a password change after a suspected compromise revokes them.
    revoked_tokens = repo.list_api_tokens_for_user(user.id)
    for api_token in revoked_tokens:
        repo.delete_api_token(api_token.id)
    record_event(
        repo,
        action="auth.change_password",
        user_id=user.id,
        user_email=user.email,
        status_code=200,
        client_ip=ip,
        subject={"api_tokens_revoked": str(len(revoked_tokens))},
    )
    return {"ok": True}


@router.get("/me", response_model=SessionInfo)
def me(session: Session = Depends(get_current_session), user: User = Depends(get_current_user)) -> SessionInfo:
    """Polled by the SPA on load to check "am I logged in" and pick up the
    CSRF token -- also doubles as the session-refresh/validity check."""
    return SessionInfo(csrf_token=session.csrf_token, expires_at=session.expires_at, role=user.role, email=user.email)


class SetupStatus(BaseModel):
    needed: bool


class SetupRequest(BaseModel):
    token: str = Field(max_length=200)
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)


def _is_loopback(request: Request) -> bool:
    try:
        return request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        return False


def _setup_open(request: Request, repo: Repository) -> bool:
    return getattr(request.app.state, "setup_token", None) is not None and not repo.list_users()


@router.get("/setup", response_model=SetupStatus)
def setup_status(request: Request, repo: Repository = Depends(get_repo)) -> SetupStatus:
    """Whether the first-run setup page applies: only in a desktop install that has no account yet."""
    return SetupStatus(needed=_setup_open(request, repo) and _is_loopback(request))


@router.post("/setup", status_code=201)
def setup(body: SetupRequest, request: Request, repo: Repository = Depends(get_repo)) -> dict[str, bool]:
    """Creates the first (owner) account of a desktop install. Refused unless all hold: the app was started with a
    setup token (`kresheen desktop` only; `serve` never sets one), no account exists yet, the request comes from this
    machine, and it carries that token. The token is then discarded, so the route is closed for good. The SPA signs
    in with the new password afterwards through the normal login."""
    ip = request.client.host if request.client else None
    with request.app.state.setup_lock:  # two requests racing must not both create an owner
        expected = getattr(request.app.state, "setup_token", None)
        if expected is None or repo.list_users():
            raise HTTPException(status_code=404, detail="Not found")
        if not _is_loopback(request) or not secrets.compare_digest(body.token.encode(), expected.encode()):
            record_event(repo, action="auth.setup_refused", status_code=403, client_ip=ip)
            raise HTTPException(status_code=403, detail="This setup link is not valid")
        email = normalize_email(body.email)
        user = User(
            id=new_user_id(),
            email=email,
            password_hash=hash_password(body.password),
            role="owner",
            created_at=datetime.now(UTC),
        )
        repo.save_user(user)
        request.app.state.setup_token = None
    record_event(repo, action="auth.setup_owner", user_id=user.id, user_email=email, status_code=201, client_ip=ip)
    return {"ok": True}
