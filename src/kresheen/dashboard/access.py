"""Per-group access control.

Groups are a shared workspace: every signed-in user is an editor, unless a
plugin narrows it through `Plugin.group_role` (for example by restricting a
group to named members, each at their own role). Global owners
(`User.role == "owner"`) and a group's creator are admin and are decided
before any plugin is asked, so a plugin can never lock the deployment's owner
out. Ungrouped applications are always shared.

Roles rank viewer < editor < admin. Reads need viewer, writes need editor
(`authorize_application`); managing the group itself needs admin.
"""

from __future__ import annotations

from typing import Literal

from fastapi import Depends, HTTPException, Request

from kresheen.dashboard.auth import get_current_user
from kresheen.dashboard.deps import get_repo
from kresheen.models.application_group import ApplicationGroup
from kresheen.models.user import User
from kresheen.plugins import get_registry
from kresheen.storage.repository import Repository

Role = Literal["viewer", "editor", "admin"]
_RANK: dict[str, int] = {"viewer": 1, "editor": 2, "admin": 3}
_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def effective_role(user: User, group: ApplicationGroup | None, repo: Repository) -> Role | None:
    """None means "no access" (callers answer 404, not 403, so a hidden
    group's existence is not disclosed)."""
    if user.role == "owner":
        return "admin"
    if group is None:
        return "editor"  # Ungrouped: the shared workspace
    if group.owner_user_id == user.id:
        return "admin"
    decision = get_registry().group_role(user, group, repo)
    if decision is None:
        return "editor"  # no plugin has an opinion: groups are a shared workspace
    return decision.role


def can_view_group(user: User, group: ApplicationGroup | None, repo: Repository) -> bool:
    return effective_role(user, group, repo) is not None


def require_group_role(user: User, group_id: str | None, needed: Role, repo: Repository, *, what: str) -> None:
    group = repo.get_group(group_id) if group_id else None
    role = effective_role(user, group, repo)
    if role is None:
        raise HTTPException(status_code=404, detail=f"Unknown {what}")
    if _RANK[role] < _RANK[needed]:
        raise HTTPException(status_code=403, detail=f"Requires {needed} access to this group")


def _authorize(request: Request, user: User, repo: Repository, needed: Role | None) -> None:
    application_id = request.path_params.get("application_id")
    if application_id is None:
        return
    application = repo.get_application(application_id)
    if application is None:
        return
    if needed is None:
        needed = "viewer" if request.method in _SAFE_METHODS else "editor"
    decision = get_registry().access_decision(user, application, needed, repo)
    if decision is not None:  # a plugin's access policy replaces the default rule below
        if not decision:
            raise HTTPException(status_code=404, detail="Unknown application")
        return
    require_group_role(user, application.group_id, needed, repo, what="application")


def authorize_application(
    request: Request, user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)
) -> None:
    """Router-level dependency for every `/api/applications/{application_id}/...`
    route: viewer for reads, editor for writes. An unknown application falls
    through so the route itself answers 404 as before."""
    _authorize(request, user, repo, None)


def authorize_application_read(
    request: Request, user: User = Depends(get_current_user), repo: Repository = Depends(get_repo)
) -> None:
    """Viewer access whatever the method, for a POST that only reads (it changes nothing and stores nothing)."""
    _authorize(request, user, repo, "viewer")
