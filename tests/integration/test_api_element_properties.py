"""Owner-stated properties of DFD elements."""

from tests.integration.test_api_applications import (
    _component_ids,
    _logged_in_client,
    _run_with_manifest,
)
from tests.integration.test_api_manual_modeling import _add, _blank_model, _threats


def _put(client, app_url, run, headers, **body):
    return client.put(f"{app_url}/runs/{run['id']}/element-properties", headers=headers, json=body)


def _rule_ids(client, app_url, run):
    return {t["rule_id"] for t in _threats(client, app_url, run)}


def test_property_specs_are_served_for_every_element_type(tmp_path):
    client, _csrf = _logged_in_client(tmp_path)

    specs = client.get("/api/threat-kb/property-specs").json()

    assert set(specs) == {"process", "data_store", "external_entity", "data_flow"}
    assert {"key": "is_encrypted", "label": "Encrypted at rest", "kind": "bool", "help": ""} in specs["data_store"]
    assert any(s["key"] == "protocol" and s["kind"] == "text" for s in specs["data_flow"])


def test_die_specs_are_served_for_process_and_data_store(tmp_path):
    """DIE ratings are owner-stated properties, not new threats/API surface -- see engine/threats/properties.py.
    A property only a plugin methodology reads is absent from the open-source core."""
    client, _csrf = _logged_in_client(tmp_path)

    specs = client.get("/api/threat-kb/property-specs").json()

    for element_type in ("process", "data_store"):
        keys = {s["key"] for s in specs[element_type]}
        assert {"die_distributed", "die_immutable", "die_ephemeral"} <= keys
        assert "is_ai_ml_component" not in keys
    assert "die_distributed" not in {s["key"] for s in specs["data_flow"]}
    assert "die_distributed" not in {s["key"] for s in specs["external_entity"]}


def test_stating_a_property_adds_a_threat_and_clearing_it_removes_it(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, run, app_url, headers = _blank_model(client, csrf)
    db = _add(client, app_url, headers, "DB", "data_store")
    assert "STORE-P-01" not in _rule_ids(client, app_url, run)

    saved = _put(
        client, app_url, run, headers, element_kind="component", element_id=db["id"], properties={"is_encrypted": False}
    )

    assert saved.status_code == 200
    assert saved.json() == {"element_key": "data_store:DB", "properties": {"is_encrypted": False}}
    threat = next(t for t in _threats(client, app_url, run) if t["rule_id"] == "STORE-P-01")
    assert threat["likelihood"] == "likely" and "owner states: not encrypted at rest" in threat["likelihood_factors"]
    node = next(n for n in client.get(f"{app_url}/runs/{run['id']}/dfd").json()["nodes"] if n["id"] == db["id"])
    assert node["properties"] == {"is_encrypted": False}

    _put(client, app_url, run, headers, element_kind="component", element_id=db["id"], properties={})

    assert "STORE-P-01" not in _rule_ids(client, app_url, run)


def test_flow_properties_generate_flow_threats_and_show_on_the_edge(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, run, app_url, headers = _blank_model(client, csrf)
    web, db = _add(client, app_url, headers, "Web"), _add(client, app_url, headers, "DB", "data_store")
    client.post(
        f"{app_url}/manual-flows",
        headers=headers,
        json={"source_ref": f"asset:{web['id']}", "target_ref": f"asset:{db['id']}"},
    )
    flow_id = client.get(f"{app_url}/runs/{run['id']}/dfd").json()["edges"][0]["id"]

    saved = _put(
        client,
        app_url,
        run,
        headers,
        element_kind="flow",
        element_id=flow_id,
        properties={"is_encrypted": False, "crosses_public_network": True, "protocol": " HTTP "},
    )

    assert saved.json()["element_key"] == "flow:Web->DB"
    assert saved.json()["properties"]["protocol"] == "HTTP"
    threat = next(t for t in _threats(client, app_url, run) if t["rule_id"] == "FLOW-P-01")
    assert "crosses a public network" in threat["risk_factors"]
    edge = client.get(f"{app_url}/runs/{run['id']}/dfd").json()["edges"][0]
    assert edge["properties"]["crosses_public_network"] is True


def test_invalid_requests_are_rejected(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, run, app_url, headers = _blank_model(client, csrf)
    web = _add(client, app_url, headers, "Web")
    body = {"element_kind": "component", "element_id": web["id"]}

    assert _put(client, app_url, run, headers, **body, properties={"is_encrypted": True}).status_code == 422
    assert _put(client, app_url, run, headers, **body, properties={"authenticates_callers": "no"}).status_code == 422
    assert (
        _put(client, app_url, run, headers, element_kind="component", element_id="nope", properties={}).status_code
        == 404
    )
    assert _put(client, app_url, run, headers, element_kind="flow", element_id="nope", properties={}).status_code == 404
    no_csrf = client.put(f"{app_url}/runs/{run['id']}/element-properties", json={**body, "properties": {}})
    assert no_csrf.status_code == 403


def test_properties_apply_to_scanned_components_and_survive_a_rerun(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run_1 = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    app_url = f"/api/applications/{application['id']}"
    name, component_id = next(iter(_component_ids(client, application, run_1).items()))

    _put(
        client,
        app_url,
        run_1,
        headers,
        element_kind="component",
        element_id=component_id,
        properties={"runs_privileged": True},
    )
    run_2 = client.post(f"{app_url}/runs", headers=headers).json()

    assert "PROC-P-02" in _rule_ids(client, app_url, run_2)
    node = next(n for n in client.get(f"{app_url}/runs/{run_2['id']}/dfd").json()["nodes"] if n["name"] == name)
    assert node["properties"] == {"runs_privileged": True}


def test_out_of_scope_hides_generated_threats_but_keeps_manual_ones(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, run, app_url, headers = _blank_model(client, csrf)
    web, db = _add(client, app_url, headers, "Web"), _add(client, app_url, headers, "DB", "data_store")
    client.post(
        f"{app_url}/manual-flows",
        headers=headers,
        json={"source_ref": f"asset:{web['id']}", "target_ref": f"asset:{db['id']}"},
    )
    client.post(
        f"{app_url}/runs/{run['id']}/manual-threats",
        headers=headers,
        json={"element_kind": "component", "element_id": web["id"], "title": "Session theft"},
    )
    before = _threats(client, app_url, run)
    assert {t["element_name"] for t in before} >= {"Web", "DB", "Web -> DB"}

    _put(
        client,
        app_url,
        run,
        headers,
        element_kind="component",
        element_id=web["id"],
        properties={"out_of_scope": True, "out_of_scope_reason": "Owned by another team"},
    )

    after = _threats(client, app_url, run)
    web_threats = [t for t in after if t["element_name"] == "Web"]
    assert [t["origin"] for t in web_threats] == ["manual"]
    assert any(t["element_name"] == "DB" for t in after)
    assert any(t["element_name"] == "Web -> DB" for t in after)  # the flow is its own element
    node = next(n for n in client.get(f"{app_url}/runs/{run['id']}/dfd").json()["nodes"] if n["id"] == web["id"])
    assert node["properties"]["out_of_scope_reason"] == "Owned by another team"

    flow_id = client.get(f"{app_url}/runs/{run['id']}/dfd").json()["edges"][0]["id"]
    _put(client, app_url, run, headers, element_kind="flow", element_id=flow_id, properties={"out_of_scope": True})
    assert not [t for t in _threats(client, app_url, run) if t["element_name"] == "Web -> DB"]


def test_properties_follow_a_rename(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, run, app_url, headers = _blank_model(client, csrf)
    web, db = _add(client, app_url, headers, "Web"), _add(client, app_url, headers, "DB", "data_store")
    client.post(
        f"{app_url}/manual-flows",
        headers=headers,
        json={"source_ref": f"asset:{web['id']}", "target_ref": f"asset:{db['id']}"},
    )
    flow_id = client.get(f"{app_url}/runs/{run['id']}/dfd").json()["edges"][0]["id"]
    _put(
        client,
        app_url,
        run,
        headers,
        element_kind="component",
        element_id=web["id"],
        properties={"runs_privileged": True},
    )
    _put(client, app_url, run, headers, element_kind="flow", element_id=flow_id, properties={"authenticated": False})

    client.patch(f"{app_url}/manual-assets/{web['id']}", headers=headers, json={"name": "Storefront"})

    dfd = client.get(f"{app_url}/runs/{run['id']}/dfd").json()
    assert next(n for n in dfd["nodes"] if n["id"] == web["id"])["properties"] == {"runs_privileged": True}
    assert dfd["edges"][0]["properties"] == {"authenticated": False}
    assert {"PROC-P-02", "FLOW-P-02"} <= _rule_ids(client, app_url, run)


def test_properties_are_deleted_with_their_application(tmp_path):
    from kresheen.storage.sql_repo import SQLRepository

    client, csrf = _logged_in_client(tmp_path)
    application, run, app_url, headers = _blank_model(client, csrf)
    web = _add(client, app_url, headers, "Web")
    _put(
        client,
        app_url,
        run,
        headers,
        element_kind="component",
        element_id=web["id"],
        properties={"is_web_application": True},
    )
    repo = SQLRepository(f"sqlite:///{tmp_path}/test.db")
    assert len(repo.list_element_properties(application["id"])) == 1

    client.delete(f"/api/applications/{application['id']}", headers=headers)

    assert repo.list_element_properties(application["id"]) == []
