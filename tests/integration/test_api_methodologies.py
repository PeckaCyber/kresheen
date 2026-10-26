"""Methodologies beyond STRIDE come only from plugins: what the API offers, accepts and generates."""

from __future__ import annotations

from kresheen.engine.threats.catalog import ThreatRule
from kresheen.engine.threats.methodology import MethodologySpec
from kresheen.engine.threats.properties import PropertySpec
from kresheen.plugins import Plugin, PluginRegistry, set_registry
from tests.integration.test_plugins import _client, _login


class DemoMethodology(Plugin):
    name = "demo-methodology"

    def methodologies(self):
        rule = ThreatRule(
            id="DEMO-M-01",
            element_type="process",
            category="Alpha",
            title="Demo threat on {name}",
            description="d",
            severity="medium",
            mitigations=("m",),
            methodology="Demo",
        )
        return [
            MethodologySpec(
                "Demo",
                "A demo methodology.",
                ("Alpha", "Beta"),
                {"Alpha": "First."},
                {"Alpha": frozenset({"Confidentiality"})},
                (rule,),
                (PropertySpec("demo_flag", "Demo flag", "bool"),),
            )
        ]


def teardown_function() -> None:
    set_registry(PluginRegistry())


def _application(client, csrf):
    headers = {"X-CSRF-Token": csrf}
    application = client.post("/api/applications", json={"name": "App"}, headers=headers).json()
    app_url = f"/api/applications/{application['id']}"
    run = client.post(f"{app_url}/runs", headers=headers).json()
    client.post(f"{app_url}/manual-assets", headers=headers, json={"name": "API", "type": "process"})
    return app_url, run, headers


def _threats(client, app_url, run):
    return client.get(f"{app_url}/runs/{run['id']}/threats").json()["threats"]


def test_core_alone_offers_exactly_stride(tmp_path):
    client, _ = _client(tmp_path)
    methodologies = client.get("/api/capabilities").json()["methodologies"]
    assert [m["name"] for m in methodologies] == ["STRIDE"]
    assert methodologies[0]["categories"][0] == "Spoofing" and len(methodologies[0]["categories"]) == 6
    csrf = _login(client)
    rules = client.get("/api/threat-kb/rules").json()
    assert {r["methodology"] for r in rules} == {"STRIDE"}
    app_url, _run, headers = _application(client, csrf)
    refused = client.patch(
        f"{app_url}/metadata", json={"name": "App", "methodologies": ["STRIDE", "Nonexistent"]}, headers=headers
    )
    assert refused.status_code == 422 and "Nonexistent" in refused.json()["detail"]
    assert client.get(app_url).json()["methodologies"] == ["STRIDE"]


def test_a_plugin_methodology_is_exposed_listed_selectable_and_generated(tmp_path):
    client, _ = _client(tmp_path, DemoMethodology())
    caps = client.get("/api/capabilities").json()["methodologies"]
    assert [m["name"] for m in caps] == ["STRIDE", "Demo"]
    assert caps[1] == {
        "name": "Demo",
        "description": "A demo methodology.",
        "categories": ["Alpha", "Beta"],
        "category_descriptions": {"Alpha": "First."},
    }

    csrf = _login(client)
    assert "DEMO-M-01" in {r["id"] for r in client.get("/api/threat-kb/rules").json()}
    keys = {s["key"] for s in client.get("/api/threat-kb/property-specs").json()["process"]}
    assert "demo_flag" in keys
    assert "demo_flag" not in {s["key"] for s in client.get("/api/threat-kb/property-specs").json()["data_flow"]}

    app_url, run, headers = _application(client, csrf)
    assert not any(t["methodology"] == "Demo" for t in _threats(client, app_url, run))

    saved = client.patch(
        f"{app_url}/metadata", json={"name": "App", "methodologies": ["STRIDE", "Demo"]}, headers=headers
    )
    assert saved.status_code == 200 and saved.json()["methodologies"] == ["STRIDE", "Demo"]
    demo = [t for t in _threats(client, app_url, run) if t["methodology"] == "Demo"]
    assert [t["rule_id"] for t in demo] == ["DEMO-M-01"] and demo[0]["cia_impacts"] == ["Confidentiality"]

    # Authoring a threat or a KB entry in an offered methodology works; in an unknown one it is a 422.
    entry = {"name": "n", "description": "d", "methodology": "Nope"}
    assert client.post("/api/threat-kb", json=entry, headers=headers).status_code == 422
    assert client.post("/api/threat-kb", json={**entry, "methodology": "Demo"}, headers=headers).status_code == 200
    assert client.post("/api/threat-kb", json={**entry, "methodology": "Custom"}, headers=headers).status_code == 200


def test_a_stale_selection_does_not_crash_and_generates_for_the_available_ones_only(tmp_path, monkeypatch):
    monkeypatch.setenv("KRESHEEN_THREATS_CACHE_TTL", "0")  # the plugin set changes under a running app only in a test
    client, _ = _client(tmp_path, DemoMethodology())
    csrf = _login(client)
    app_url, run, headers = _application(client, csrf)
    client.patch(f"{app_url}/metadata", json={"name": "App", "methodologies": ["STRIDE", "Demo"]}, headers=headers)
    assert any(t["methodology"] == "Demo" for t in _threats(client, app_url, run))

    # The plugin goes away (for example its licence lapsed); the application keeps its stored selection.
    set_registry(PluginRegistry())
    assert client.get(app_url).json()["methodologies"] == ["STRIDE", "Demo"]
    threats = _threats(client, app_url, run)
    assert threats and {t["methodology"] for t in threats} == {"STRIDE"}
    # The shorter list must not read as a clean result: the response names what was not generated.
    body = client.get(f"{app_url}/runs/{run['id']}/threats").json()
    assert body["unavailable_methodologies"] == ["Demo"]
    from kresheen.reporting.model import build_report

    report = build_report(app_url.rsplit("/", 1)[1], run["id"], client.app.state.repo)
    assert [a.element for a in report.partly_analysed] == ["Methodology Demo"]
    assert [m["name"] for m in client.get("/api/capabilities").json()["methodologies"]] == ["STRIDE"]

    # Saving the unchanged selection (a rename) is allowed; adding another unavailable one is not.
    renamed = client.patch(
        f"{app_url}/metadata", json={"name": "Renamed", "methodologies": ["STRIDE", "Demo"]}, headers=headers
    )
    assert renamed.status_code == 200
    added = client.patch(
        f"{app_url}/metadata", json={"name": "Renamed", "methodologies": ["STRIDE", "Demo", "Other"]}, headers=headers
    )
    assert added.status_code == 422
