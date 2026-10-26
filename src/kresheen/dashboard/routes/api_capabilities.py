"""What this installation can do, so the UI shows only what exists (no locked placeholders).

Unauthenticated on purpose: the login page needs the extra login methods before anyone is signed in. It lists plugin
names and versions, login buttons, and the names, categories and descriptions of the available methodologies.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from kresheen.dashboard.deps import get_repo
from kresheen.engine.llm.settings import ai_status
from kresheen.engine.threats.methodology import available_methodologies
from kresheen.plugins import get_registry
from kresheen.storage.repository import Repository

router = APIRouter(prefix="/api", tags=["capabilities"])


class PluginOut(BaseModel):
    name: str
    version: str
    features: list[str]


class AuthProviderOut(BaseModel):
    id: str
    label: str
    login_url: str
    password_login: bool = True


class AiCapabilityOut(BaseModel):
    """Instance level only: whether this user has a key comes from the agent-config endpoint."""

    enabled: bool
    experimental: bool = True


class MethodologyOut(BaseModel):
    """A threat-modelling methodology this installation can generate for (STRIDE, plus any a plugin offers)."""

    name: str
    description: str
    categories: list[str]
    category_descriptions: dict[str, str]


class CapabilitiesOut(BaseModel):
    plugins: list[PluginOut]
    features: list[str]
    auth_providers: list[AuthProviderOut]
    ai: AiCapabilityOut
    methodologies: list[MethodologyOut]


@router.get("/capabilities", response_model=CapabilitiesOut)
def capabilities(repo: Repository = Depends(get_repo)) -> CapabilitiesOut:
    registry = get_registry()
    plugins = [PluginOut(**p) for p in registry.describe()]
    features = sorted({f for p in plugins for f in p.features})
    providers = [
        AuthProviderOut(id=a.id, label=a.label, login_url=a.login_url, password_login=a.password_login)
        for a in registry.auth_providers()
    ]
    return CapabilitiesOut(
        plugins=plugins,
        features=features,
        auth_providers=providers,
        ai=AiCapabilityOut(enabled=ai_status(repo).enabled),
        methodologies=[
            MethodologyOut(
                name=m.name,
                description=m.description,
                categories=list(m.categories),
                category_descriptions=dict(m.category_descriptions),
            )
            for m in available_methodologies()
        ],
    )
