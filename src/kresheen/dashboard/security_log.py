"""What counts as a security event: these rows are kept in their own retention pool in the audit log, so a flood of
routine writes cannot push them out. (Streaming them to a SIEM is a plugin's job, through `Plugin.audit_sinks`.)"""

from __future__ import annotations

from kresheen.plugins import get_registry

SECURITY_PREFIXES: tuple[str, ...] = ("auth.",)
SECURITY_ACTIONS: frozenset[str] = frozenset(
    {
        "ai.injection_signal",
        "POST /api/tokens",
        "DELETE /api/tokens/{token_id}",
        "POST /api/users",
        "PATCH /api/users/{user_id}",
        "report.export",
        "ai.instance_toggled",
        "ai.key_added",
        "ai.key_removed",
    }
)


def is_security_action(action: str) -> bool:
    return action in SECURITY_ACTIONS or action.startswith(SECURITY_PREFIXES) or action in get_registry().security_actions()
