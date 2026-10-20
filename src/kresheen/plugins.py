"""Extension points: how an optional package adds features to the core.

The core runs fully with no plugin installed. A plugin is a Python package that exposes an object (a `Plugin`
subclass instance, a class, or a zero-argument factory) under the entry-point group `kresheen.plugins`. Every hook
has a no-op default, so a plugin overrides only what it needs. A plugin that fails to load, or a hook that raises,
is logged and skipped; it never stops the core from starting or answering.

Hooks (see `Plugin`): routers, access_policy, group_role, auth_providers, password_login_allowed, logout_redirect, audit_sinks, threat_sources, config_rules, methodologies, action_guidance,
report_sections, dashboard_sections, cli_commands, storage, migration_locations, security_actions,
threat_neutral_api_areas, application_deleted, group_deleted, user_deleted.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    import click
    from fastapi import FastAPI
    from sqlalchemy import MetaData
    from sqlalchemy.engine import Engine

    from kresheen.dashboard.routes.api_dashboard import DashboardOut
    from kresheen.engine.threats.catalog import ThreatRule
    from kresheen.engine.threats.config_rules import ConfigRule
    from kresheen.engine.threats.methodology import MethodologySpec
    from kresheen.models.application import Application
    from kresheen.models.application_group import ApplicationGroup
    from kresheen.models.auth import Session
    from kresheen.models.user import User
    from kresheen.reporting.model import ThreatModelReport
    from kresheen.storage.repository import Repository

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "kresheen.plugins"

AuditSink = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class AuthProvider:
    """An extra login method. The login page shows a button that sends the browser to `login_url`.
    `password_login=False` tells the login page that passwords are refused for most users, so it tucks the password
    form behind an owner sign-in link (the server enforces it through `Plugin.password_login_allowed`)."""

    id: str
    label: str
    login_url: str
    password_login: bool = True


@dataclass(frozen=True)
class MigrationLocation:
    """One independent migration tree for the database. `script_location` is an Alembic folder (`env.py`,
    `versions/`), `version_table` is the table that records its revision (the core uses `alembic_version`; a plugin
    needs its own so the two upgrade independently), and `metadata` holds the tables the tree owns."""

    name: str
    script_location: Path
    version_table: str
    metadata: MetaData


@dataclass(frozen=True)
class GroupRole:
    """A plugin's decision about one user's access to one group. `role=None` means no access at all."""

    role: Literal["viewer", "editor", "admin"] | None


_GROUP_ROLES = ("viewer", "editor", "admin")


@dataclass(frozen=True)
class Guidance:
    """Optional help for an action-plan item: how to verify a fix, and an example of one."""

    verification: list[str] = field(default_factory=list)
    fix_example: str = ""
    fix_example_mitigation_index: int | None = None


@dataclass(frozen=True)
class AuditLimits:
    """How many audit rows the local log keeps. The core uses fixed defaults; a plugin can raise them."""

    max_entries: int | None = None
    max_security_entries: int | None = None
    max_failed_logins: int | None = None


@dataclass(frozen=True)
class ReportTable:
    headers: list[str]
    rows: list[list[str]]


@dataclass(frozen=True)
class ReportSection:
    """An extra section in the HTML, Word and PDF reports. Plain text only; renderers escape it."""

    title: str
    paragraphs: list[str] = field(default_factory=list)
    tables: list[ReportTable] = field(default_factory=list)


class Plugin:
    """Base class with a no-op default for every hook."""

    name: str = "unnamed"
    version: str = "0"
    features: tuple[str, ...] = ()  # names the UI can ask about through `/api/capabilities`

    def routers(self, app: FastAPI) -> None:
        """Mount extra FastAPI routers (`app.include_router(...)`)."""

    def access_policy(self, user: User, application: Application, needed: str, repo: Repository) -> bool | None:
        """Decide whether `user` may read (`needed == "viewer"`) or write (`"editor"`) `application`.
        Return None for no opinion. The first plugin with an opinion wins; a False answers 404."""
        return None

    def group_role(self, user: User, group: ApplicationGroup, repo: Repository) -> GroupRole | None:
        """Decide `user`'s role in `group`. Return None for no opinion (the core then treats the group as a shared
        workspace and the user as an editor), `GroupRole("viewer" | "editor" | "admin")` to set a role, or
        `GroupRole(None)` for no access (callers answer 404). Global owners, a group's creator and the Ungrouped
        bucket never reach this hook, so a plugin cannot lock the deployment's owner out. If the hook raises, the
        user gets no access to that group."""
        return None

    def auth_providers(self) -> list[AuthProvider]:
        return []

    def password_login_allowed(self, user: User) -> bool | None:
        """Called after a correct password for `user`. Return False to refuse the login (403, audited), True or None
        to leave it to the other plugins. Any plugin saying False refuses."""
        return None

    def logout_redirect(self, session: Session, user: User | None) -> str | None:
        """A URL the browser should be sent to after this session ends (for example an identity provider's
        sign-out page), or None."""
        return None

    def audit_sinks(self) -> list[AuditSink]:
        """Callables that receive every audit event as a dict: at, action, user, ip, status, via, detail, security."""
        return []

    def audit_limits(self) -> AuditLimits | None:
        """Override the local audit log's row caps (longer retention). None keeps the core defaults."""
        return None

    def threat_sources(self, repo: Repository) -> list[ThreatRule]:
        """Extra threat rules that run alongside the built-in catalog."""
        return []

    def config_rules(self) -> list[ConfigRule]:
        """Extra configuration-aware rules (detectors over ingested manifest and Terraform facts), run alongside
        the core's sample rules. Rule ids must be unique and must not reuse a core rule id."""
        return []

    def methodologies(self) -> list[MethodologySpec]:
        """Extra threat-modelling methodologies beyond the core's STRIDE: categories, CIA mapping, generation rules
        and any owner-stated properties the rules read. A name must be unique and must not be "STRIDE" or "Custom";
        a spec that reuses one is ignored. An application can select only the methodologies offered here."""
        return []

    def action_guidance(self, rule_id: str, methodology: str, category: str | None) -> Guidance | None:
        return None

    def report_sections(self, report: ThreatModelReport) -> list[ReportSection]:
        return []

    def dashboard_sections(self, repo: Repository, user: User, dashboard: DashboardOut) -> dict[str, Any]:
        """Extra JSON for `GET /api/dashboard`, returned under `extensions[<plugin name>]`. `dashboard` is what the
        core already built (visible applications, summary, trend)."""
        return {}

    def cli_commands(self) -> list[click.Command]:
        return []

    def storage(self, engine: Engine) -> None:
        """Prepare the plugin's storage. Called once per database, right after the core schema is migrated, with
        the same engine. The plugin's tables come from its `migration_locations`, which the core upgrades before
        this hook runs; use it to open the plugin's store. Keep the plugin's tables on its own `MetaData`, never on
        the core's, and make this idempotent (it runs on every start). If it raises, the core still starts and the
        plugin's storage is unavailable."""

    def migration_locations(self) -> list[MigrationLocation]:
        """The plugin's own migration trees. The core upgrades them with its own, under one lock and one backup,
        and never mixes their revisions with the core's."""
        return []

    def security_actions(self) -> frozenset[str]:
        """Audit actions (`"<METHOD> <route template>"`) that count as security events, in addition to the core's."""
        return frozenset()

    def threat_neutral_api_areas(self) -> frozenset[str]:
        """Top-level `/api/<area>` names whose writes never change derived threats, so they do not clear the
        threat cache. An area not listed here clears it, which is always safe."""
        return frozenset()

    def application_deleted(self, application_id: str) -> None:
        """Called after an application and its core data are deleted. Remove whatever the plugin stores for it."""

    def group_deleted(self, group_id: str) -> None:
        """Called after an application group is deleted (its applications have moved to Ungrouped). Remove
        whatever the plugin stores for it."""

    def user_deleted(self, user_id: str) -> None:
        """Called after a user is deleted outright. Remove whatever the plugin stores for them. (Deactivating a
        user, which SCIM does, is not a deletion.)"""


class PluginRegistry:
    def __init__(self, plugins: list[Plugin] | None = None) -> None:
        self.plugins: list[Plugin] = list(plugins or [])

    def _each(self, hook: str, *args: Any) -> list[tuple[Plugin, Any]]:
        results = []
        for plugin in self.plugins:
            try:
                results.append((plugin, getattr(plugin, hook)(*args)))
            except Exception:
                logger.exception("Plugin %s failed in %s", plugin.name, hook)
        return results

    def mount_routers(self, app: FastAPI) -> None:
        self._each("routers", app)

    def access_decision(self, user: User, application: Application, needed: str, repo: Repository) -> bool | None:
        for _plugin, decision in self._each("access_policy", user, application, needed, repo):
            if decision is not None:
                return bool(decision)
        return None

    def group_role(self, user: User, group: ApplicationGroup, repo: Repository) -> GroupRole | None:
        """The first plugin with an opinion wins. Access control fails closed: a plugin that raises, or answers
        with something that is not a `GroupRole`, denies access to this group (logged), instead of being skipped."""
        for plugin in self.plugins:
            try:
                decision = plugin.group_role(user, group, repo)
                if decision is None:
                    continue
                if not isinstance(decision, GroupRole) or (decision.role is not None and decision.role not in _GROUP_ROLES):
                    raise TypeError(f"invalid group role decision {decision!r}")
            except Exception:
                logger.exception("Plugin %s failed in group_role; denying access to group %s", plugin.name, group.id)
                return GroupRole(None)
            return decision
        return None

    def auth_providers(self) -> list[AuthProvider]:
        return [p for _, found in self._each("auth_providers") for p in found]

    def password_login_allowed(self, user: User) -> bool:
        """False if any plugin refuses. A plugin that raises refuses too (fail closed), except for a global owner,
        who a broken plugin must never lock out of password sign-in."""
        for plugin in self.plugins:
            try:
                if plugin.password_login_allowed(user) is False:
                    return False
            except Exception:
                logger.exception("Plugin %s failed in password_login_allowed", plugin.name)
                if user.role != "owner":
                    return False
        return True

    def logout_redirect(self, session: Session, user: User | None) -> str | None:
        for _plugin, url in self._each("logout_redirect", session, user):
            if isinstance(url, str) and url:
                return url
        return None

    def audit_sinks(self) -> list[AuditSink]:
        return [s for _, found in self._each("audit_sinks") for s in found]

    def audit_limit(self, name: str) -> int | None:
        for _plugin, limits in self._each("audit_limits"):
            value = getattr(limits, name, None) if limits is not None else None
            if value is not None and value > 0:
                return int(value)
        return None

    def threat_rules(self, repo: Repository) -> list[ThreatRule]:
        return [r for _, found in self._each("threat_sources", repo) for r in found]

    def config_rules(self) -> list[ConfigRule]:
        return [r for _, found in self._each("config_rules") for r in found]

    def methodologies(self) -> list[MethodologySpec]:
        return [m for _, found in self._each("methodologies") for m in found]

    def guidance(self, rule_id: str, methodology: str, category: str | None) -> Guidance | None:
        for _plugin, found in self._each("action_guidance", rule_id, methodology, category):
            if found is not None:
                return found
        return None

    def report_sections(self, report: ThreatModelReport) -> list[ReportSection]:
        return [s for _, found in self._each("report_sections", report) for s in found]

    def dashboard_extensions(self, repo: Repository, user: User, dashboard: DashboardOut) -> dict[str, Any]:
        return {plugin.name: data for plugin, data in self._each("dashboard_sections", repo, user, dashboard) if data}

    def cli_commands(self) -> list[click.Command]:
        return [c for _, found in self._each("cli_commands") for c in found]

    def migration_locations(self) -> list[MigrationLocation]:
        return [loc for _, found in self._each("migration_locations") for loc in found]

    def init_storage(self, engine: Engine) -> None:
        self._each("storage", engine)

    def security_actions(self) -> frozenset[str]:
        return frozenset(a for _, found in self._each("security_actions") for a in found)

    def threat_neutral_api_areas(self) -> frozenset[str]:
        return frozenset(a for _, found in self._each("threat_neutral_api_areas") for a in found)

    def application_deleted(self, application_id: str) -> None:
        self._each("application_deleted", application_id)

    def group_deleted(self, group_id: str) -> None:
        self._each("group_deleted", group_id)

    def user_deleted(self, user_id: str) -> None:
        self._each("user_deleted", user_id)

    def describe(self) -> list[dict[str, Any]]:
        return [{"name": p.name, "version": p.version, "features": list(p.features)} for p in self.plugins]


def load_plugins() -> PluginRegistry:
    """Discover installed plugins. Never raises."""
    plugins: list[Plugin] = []
    for entry in entry_points(group=ENTRY_POINT_GROUP):
        try:
            loaded = entry.load()
            plugin = loaded() if callable(loaded) else loaded
            if not isinstance(plugin, Plugin):
                logger.error("Plugin entry point %s did not produce a Plugin; skipped", entry.name)
                continue
            plugins.append(plugin)
        except Exception:
            logger.exception("Could not load plugin %s", entry.name)
    return PluginRegistry(plugins)


_registry = PluginRegistry()


def get_registry() -> PluginRegistry:
    """The active registry. Empty until `create_app` (or a CLI command) installs one."""
    return _registry


def set_registry(registry: PluginRegistry) -> None:
    global _registry
    _registry = registry
