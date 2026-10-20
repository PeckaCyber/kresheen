"""The instance-level AI switch.

Two layers: the owner's stored `ai_enabled` setting (default off) and an operator override, `KRESHEEN_AI_DISABLED`,
which wins over the database so a deployment can guarantee no AI regardless of what an owner clicks. "Available to a
user" additionally needs that user's own stored key; that part lives in the agent-config routes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from kresheen.storage.repository import Repository

AI_ENABLED_KEY = "ai_enabled"
DISABLED_ENV = "KRESHEEN_AI_DISABLED"
_TRUTHY = ("1", "true", "yes", "on")


@dataclass(frozen=True)
class AiStatus:
    """`enabled` is the effective state: the owner's stored switch is on AND the operator has not forced it off."""

    enabled: bool
    forced_off: bool


def forced_off() -> bool:
    return os.environ.get(DISABLED_ENV, "").strip().lower() in _TRUTHY


def ai_status(repo: Repository) -> AiStatus:
    stored = repo.get_instance_setting(AI_ENABLED_KEY) is True
    off = forced_off()
    return AiStatus(enabled=stored and not off, forced_off=off)


def set_ai_enabled(repo: Repository, enabled: bool, updated_by: str | None) -> None:
    repo.set_instance_setting(AI_ENABLED_KEY, enabled, updated_by)
