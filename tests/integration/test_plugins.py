"""The plugin extension points (`kresheen.plugins`), exercised with a throwaway plugin."""

from __future__ import annotations

import io
import re
from datetime import UTC, datetime
from pathlib import Path

import click
from docx import Document
from fastapi import APIRouter
from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.engine.threats.catalog import ThreatRule
from kresheen.models.user import User
from kresheen.plugins import (
    AuthProvider,
    Guidance,
    Plugin,
    PluginRegistry,
    ReportSection,
    ReportTable,
    get_registry,
    set_registry,
)
from kresheen.reporting.docx_report import render_docx
from kresheen.reporting.html_report import render_html
from kresheen.reporting.model import build_report
from kresheen.reporting.pdf_report import render_pdf
from kresheen.storage.sql_repo import SQLRepository
from tests.unit.test_reporting import _repo_with_run

_PASSWORD = "correct-password"  # nosec: test fixture, not a real credential


class DemoPlugin(Plugin):
    name = "demo"
    version = "1.2.3"
    features = ("demo-feature",)

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.deny = False

    def routers(self, app):
        router = APIRouter()

        @router.get("/api/demo/ping")
        def ping() -> dict[str, str]:
            return {"pong": "yes"}

        app.include_router(router)

    def access_policy(self, user, application, needed, repo):
        return False if self.deny else None

    def auth_providers(self):
        return [AuthProvider(id="demo-sso", label="Demo SSO", login_url="/api/demo/login")]

    def audit_sinks(self):
        return [self.events.append]

    def threat_sources(self, repo):
        return [
            ThreatRule(
                id="DEMO-01",
                element_type="process",
                category="Spoofing",
                title="Demo threat on {name}",
                description="d",
                severity="low",
                mitigations=("m",),
            )
        ]

    def action_guidance(self, rule_id, methodology, category):
        return Guidance(verification=["demo verify"], fix_example="demo fix", fix_example_mitigation_index=0)

    def report_sections(self, report):
        return [ReportSection("Demo section", ["Demo paragraph"], [ReportTable(["A", "B"], [["1", "2"]])])]

    def dashboard_sections(self, repo, user, dashboard):
        return {"answer": 42}

    def cli_commands(self):
        return [click.Command("demo-cmd", callback=lambda: None)]


class BrokenPlugin(Plugin):
    name = "broken"

    def routers(self, app):
        raise RuntimeError("boom")

    def audit_sinks(self):
        raise RuntimeError("boom")

    def report_sections(self, report):
        raise RuntimeError("boom")


def _client(tmp_path, *plugins: Plugin) -> tuple[TestClient, SQLRepository]:
    db_url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(db_url)
    repo.save_user(
        User(
            id="U1",
            email="o@example.com",
            password_hash=hash_password(_PASSWORD),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    return TestClient(create_app(db_url=db_url, plugins=PluginRegistry(list(plugins)))), repo


def _login(client: TestClient) -> str:
    return client.post("/api/auth/login", json={"email": "o@example.com", "password": _PASSWORD}).json()["csrf_token"]


def teardown_function() -> None:
    set_registry(PluginRegistry())


def test_core_runs_with_no_plugin(tmp_path):
    client, _ = _client(tmp_path)
    body = client.get("/api/capabilities").json()
    assert [m["name"] for m in body.pop("methodologies")] == ["STRIDE"]
    assert body == {"plugins": [], "features": [], "auth_providers": [], "ai": {"enabled": False, "experimental": True}}
    _login(client)
    assert "extensions" in client.get("/api/dashboard").json()
    assert client.get("/api/dashboard").json()["extensions"] == {}


def test_plugin_adds_router_capabilities_and_dashboard_data(tmp_path):
    client, _ = _client(tmp_path, DemoPlugin())

    assert client.get("/api/demo/ping").json() == {"pong": "yes"}
    caps = client.get("/api/capabilities").json()
    assert caps["plugins"] == [{"name": "demo", "version": "1.2.3", "features": ["demo-feature"]}]
    assert caps["features"] == ["demo-feature"]
    assert caps["auth_providers"] == [
        {"id": "demo-sso", "label": "Demo SSO", "login_url": "/api/demo/login", "password_login": True}
    ]
    _login(client)
    assert client.get("/api/dashboard").json()["extensions"] == {"demo": {"answer": 42}}


def test_audit_sink_receives_events(tmp_path):
    plugin = DemoPlugin()
    client, _ = _client(tmp_path, plugin)
    _login(client)
    assert any(e["action"].startswith("auth.") and e["security"] for e in plugin.events)


def test_access_policy_replaces_the_default_rule(tmp_path):
    plugin = DemoPlugin()
    client, _ = _client(tmp_path, plugin)
    csrf = _login(client)
    created = client.post("/api/applications", json={"name": "Shop"}, headers={"X-CSRF-Token": csrf})
    assert created.status_code in (200, 201), created.text
    app_id = created.json()["id"]
    assert client.get(f"/api/applications/{app_id}").status_code == 200
    plugin.deny = True
    assert client.get(f"/api/applications/{app_id}").status_code == 404


def test_report_sections_render_in_html_docx_and_pdf(tmp_path):
    repo = _repo_with_run(tmp_path, {"repo_url": "https://github.com/org/repo", "ref": "main"})
    set_registry(PluginRegistry([DemoPlugin()]))

    report = build_report("APP-1", "RUN-1", repo)

    assert [s.title for s in report.extra_sections] == ["Demo section"]
    assert "Demo paragraph" in render_html(report)
    text = "\n".join(p.text for p in Document(io.BytesIO(render_docx(report))).paragraphs)
    assert "Demo section" in text
    assert render_pdf(report).startswith(b"%PDF")


def test_guidance_and_threat_source_hooks(tmp_path):
    set_registry(PluginRegistry([DemoPlugin()]))
    registry = get_registry()
    assert registry.guidance("X", "STRIDE", None).fix_example == "demo fix"
    assert [r.id for r in registry.threat_rules(None)] == ["DEMO-01"]


def test_cli_commands_and_migration_locations():
    from sqlalchemy import MetaData

    from kresheen.plugins import MigrationLocation

    location = MigrationLocation("demo", Path("/tmp/demo-migrations"), "alembic_version_demo", MetaData())

    class Migrating(Plugin):
        name = "migrating"

        def migration_locations(self):
            return [location]

    registry = PluginRegistry([DemoPlugin(), Migrating()])
    assert [c.name for c in registry.cli_commands()] == ["demo-cmd"]
    assert registry.migration_locations() == [location]


def test_a_broken_plugin_never_breaks_the_core(tmp_path):
    client, _ = _client(tmp_path, BrokenPlugin(), DemoPlugin())
    assert client.get("/api/demo/ping").status_code == 200
    _login(client)  # the failing audit sink does not fail the login
    repo = _repo_with_run(tmp_path, {"repo_url": "https://github.com/org/repo", "ref": "main"})
    report = build_report("APP-1", "RUN-1", repo)
    assert [s.title for s in report.extra_sections] == ["Demo section"]


def test_core_never_imports_a_plugin_package():
    """The open-source tree must not depend on the Pro package (it lives outside this repo)."""
    root = Path(__file__).resolve().parents[2]
    pattern = re.compile(r"^\s*(?:from|import)\s+kresheen_pro\b", re.MULTILINE)
    offenders = []
    files = list((root / "src" / "kresheen").rglob("*.py"))
    for path in (root / "frontend" / "src").rglob("*.ts*"):
        # `extensions.ts` is the one place that imports the `@kresheen/pro` alias, and its tests mock it.
        if "extensions" not in path.parts and not path.name.startswith("extensions."):
            files.append(path)
    for path in files:
        text = path.read_text(encoding="utf-8")
        if pattern.search(text) or "@kresheen/pro" in text:
            offenders.append(str(path.relative_to(root)))
    assert offenders == []


def test_core_threats_carry_no_guidance_without_a_plugin():
    from kresheen.models.threat import Threat

    set_registry(PluginRegistry())
    threat = Threat(
        key="k",
        rule_id="SC-T01",
        element_kind="component",
        element_id="1",
        element_name="X",
        element_type="process",
        category="DenialOfService",
        title="t",
        description="d",
        severity="high",
        mitigations=["m"],
    )
    assert threat.verification == [] and threat.fix_example == "" and threat.fix_example_for == ""


def test_lifecycle_hooks_reach_plugins_and_a_failing_one_is_isolated():
    seen: list[tuple[str, str]] = []

    class Boom(Plugin):
        name = "boom"

        def application_deleted(self, application_id):
            raise RuntimeError("boom")

    class Recorder(Plugin):
        name = "rec"

        def application_deleted(self, application_id):
            seen.append(("application", application_id))

        def group_deleted(self, group_id):
            seen.append(("group", group_id))

        def user_deleted(self, user_id):
            seen.append(("user", user_id))

    registry = PluginRegistry([Boom(), Recorder()])
    registry.application_deleted("A")
    registry.group_deleted("G")
    registry.user_deleted("U")
    assert seen == [("application", "A"), ("group", "G"), ("user", "U")]


def test_a_failing_storage_hook_is_isolated(tmp_path):
    class Boom(Plugin):
        name = "boom"

        def storage(self, engine):
            raise RuntimeError("boom")

    set_registry(PluginRegistry([Boom()]))
    try:
        assert SQLRepository(f"sqlite:///{tmp_path}/s.db").list_applications() == []
    finally:
        set_registry(PluginRegistry())


def _sample_plugin_rule():
    from kresheen.engine.threats.config_rules import ConfigRule, Hit

    return ConfigRule(
        "PLUG-CFG-01",
        "T01",
        "process",
        "Spoofing",
        "{name} is a plugin finding",
        "d",
        "low",
        ("m",),
        ("CWE-306",),
        (),
        "always",
        lambda ctx: [Hit("component", w.name, ["plugin evidence"]) for w in ctx.workloads],
    )


class RulePlugin(Plugin):
    name = "rules"

    def config_rules(self):
        return [_sample_plugin_rule()]


def test_plugin_config_rules_run_and_are_listed(tmp_path):
    from kresheen.engine.ingest.manifest_ingestor import ManifestUploadIngestor
    from kresheen.engine.threats.config_rules import CONFIG_RULES, FactContext, all_config_rules
    from kresheen.engine.threats.generate import DfdElement
    from kresheen.engine.threats.service import generate_config_threats

    manifest = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: n}\n"
        "spec: {template: {spec: {containers: [{name: c, image: app:1}]}}}\n"
    )
    nodes, edges = ManifestUploadIngestor().run(
        run_id="R", application_id="A", connection_details={"content": manifest}
    )
    context = FactContext(nodes, edges)
    elements = [DfdElement(id="E1", name="Deployment/web", type="process")]

    set_registry(PluginRegistry())
    assert all_config_rules() == CONFIG_RULES
    assert generate_config_threats(context, elements, []) == []

    client, _ = _client(tmp_path, RulePlugin())
    assert [r.id for r in all_config_rules()] == [*(r.id for r in CONFIG_RULES), "PLUG-CFG-01"]
    threats = generate_config_threats(context, elements, [])
    assert [(t.rule_id, t.risk_factors) for t in threats] == [("PLUG-CFG-01", ["plugin evidence"])]

    _login(client)
    listed = [r["id"] for r in client.get("/api/threat-kb/rules").json()]
    assert listed[-1] == "PLUG-CFG-01" and listed[-len(CONFIG_RULES) - 1 : -1] == [r.id for r in CONFIG_RULES]


def test_a_rule_that_supersedes_another_replaces_it_on_the_same_element_only():
    from dataclasses import replace

    from kresheen.engine.ingest.manifest_ingestor import ManifestUploadIngestor
    from kresheen.engine.threats.config_rules import FactContext, Hit
    from kresheen.engine.threats.generate import DfdElement
    from kresheen.engine.threats.service import generate_config_threats

    general = _sample_plugin_rule()
    specific = replace(
        general,
        id="PLUG-CFG-02",
        supersedes=("PLUG-CFG-01",),
        detect=lambda ctx: [Hit("component", w.name, ["specific"]) for w in ctx.workloads if w.name.endswith("/web")],
    )

    class Rules(Plugin):
        name = "superseding"

        def config_rules(self):
            return [general, specific]

    manifest = "".join(
        f"---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {{name: {n}, namespace: n}}\n"
        "spec: {template: {spec: {containers: [{name: c, image: app:1}]}}}\n"
        for n in ("web", "api")
    )
    nodes, edges = ManifestUploadIngestor().run(
        run_id="R", application_id="A", connection_details={"content": manifest}
    )
    elements = [
        DfdElement(id="E1", name="Deployment/web", type="process"),
        DfdElement(id="E2", name="Deployment/api", type="process"),
    ]
    set_registry(PluginRegistry([Rules()]))
    try:
        found = sorted(
            (t.rule_id, t.element_name) for t in generate_config_threats(FactContext(nodes, edges), elements, [])
        )
    finally:
        set_registry(PluginRegistry())
    assert found == [("PLUG-CFG-01", "Deployment/api"), ("PLUG-CFG-02", "Deployment/web")]


def test_plugin_config_rules_change_the_catalog_version_and_a_failing_hook_is_skipped():
    from kresheen.engine.provenance import rule_catalog_version

    class BrokenRules(Plugin):
        name = "broken-rules"

        def config_rules(self):
            raise RuntimeError("boom")

    set_registry(PluginRegistry())
    core_only = rule_catalog_version()
    set_registry(PluginRegistry([BrokenRules()]))
    assert rule_catalog_version() == core_only
    set_registry(PluginRegistry([RulePlugin()]))
    assert rule_catalog_version() != core_only
