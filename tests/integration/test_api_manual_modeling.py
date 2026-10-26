"""Blank-canvas models and editing what the user drew."""

from tests.integration.test_api_applications import _logged_in_client


def _blank_model(client, csrf) -> tuple[dict, dict, str, dict]:
    headers = {"X-CSRF-Token": csrf}
    application = client.post("/api/applications", json={"name": "Brainstorm"}, headers=headers).json()
    run = client.post(f"/api/applications/{application['id']}/runs", headers=headers).json()
    return application, run, f"/api/applications/{application['id']}", headers


def _add(client, app_url, headers, name, type_="process", boundary=None) -> dict:
    return client.post(
        f"{app_url}/manual-assets", headers=headers, json={"name": name, "type": type_, "trust_boundary": boundary}
    ).json()


def _threats(client, app_url, run) -> list[dict]:
    return client.get(f"{app_url}/runs/{run['id']}/threats").json()["threats"]


def test_blank_model_shows_only_manual_components_and_flows(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, run, app_url, headers = _blank_model(client, csrf)
    web = _add(client, app_url, headers, "Web")
    db = _add(client, app_url, headers, "DB", "data_store")
    client.post(
        f"{app_url}/manual-flows",
        headers=headers,
        json={"source_ref": f"asset:{web['id']}", "target_ref": f"asset:{db['id']}", "label": "SQL"},
    )

    dfd = client.get(f"{app_url}/runs/{run['id']}/dfd").json()

    assert {n["name"] for n in dfd["nodes"]} == {"Web", "DB"}
    assert [e["label"] for e in dfd["edges"]] == ["SQL"]
    assert _threats(client, app_url, run)  # design-level threats are generated for hand-drawn elements too


def test_rename_moves_every_name_keyed_overlay(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, run, app_url, headers = _blank_model(client, csrf)
    web = _add(client, app_url, headers, "Web")
    db = _add(client, app_url, headers, "DB", "data_store")
    client.post(
        f"{app_url}/manual-flows",
        headers=headers,
        json={"source_ref": f"asset:{web['id']}", "target_ref": f"asset:{db['id']}"},
    )
    client.put(
        f"{app_url}/trust-boundaries",
        headers=headers,
        json={"component_name": "Web", "trust_boundary": "internet-facing"},
    )
    on_component = client.post(
        f"{app_url}/runs/{run['id']}/manual-threats",
        headers=headers,
        json={"element_kind": "component", "element_id": web["id"], "title": "Session theft"},
    ).json()
    flow_id = client.get(f"{app_url}/runs/{run['id']}/dfd").json()["edges"][0]["id"]
    on_flow = client.post(
        f"{app_url}/runs/{run['id']}/manual-threats",
        headers=headers,
        json={"element_kind": "flow", "element_id": flow_id, "title": "Replay"},
    ).json()
    generated = next(
        t for t in _threats(client, app_url, run) if t["element_name"] == "Web" and t["origin"] != "manual"
    )
    for key in (generated["key"], on_component["key"], on_flow["key"]):
        assert (
            client.put(
                f"{app_url}/runs/{run['id']}/threats/status",
                headers=headers,
                json={"threat_key": key, "status": "mitigated", "note": "done"},
            ).status_code
            == 200
        )

    renamed = client.patch(f"{app_url}/manual-assets/{web['id']}", headers=headers, json={"name": "Storefront"})

    assert renamed.status_code == 200 and renamed.json()["name"] == "Storefront"
    dfd = client.get(f"{app_url}/runs/{run['id']}/dfd").json()
    node = next(n for n in dfd["nodes"] if n["id"] == web["id"])
    assert node["name"] == "Storefront" and node["trust_boundary"] == "internet-facing"
    assert len(dfd["edges"]) == 1
    threats = _threats(client, app_url, run)
    assert not [t for t in threats if "Web" in t["key"] or t["element_name"] == "Web"]
    mitigated = [t for t in threats if t["status"] == "mitigated"]
    assert len(mitigated) == 3 and all(t["note"] == "done" for t in mitigated)
    assert next(t for t in threats if t["manual_threat_id"] == on_flow["manual_threat_id"])["element_name"] == (
        "Storefront -> DB"
    )


def test_rename_rejects_empty_duplicate_non_manual_and_no_op_requests(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, _run, app_url, headers = _blank_model(client, csrf)
    web = _add(client, app_url, headers, "Web")
    _add(client, app_url, headers, "DB", "data_store")

    def patch(asset_id, body):
        return client.patch(f"{app_url}/manual-assets/{asset_id}", headers=headers, json=body)

    assert patch(web["id"], {"name": "   "}).status_code == 422
    assert patch(web["id"], {"name": "DB"}).status_code == 409
    assert patch(web["id"], {}).status_code == 422
    assert patch(web["id"], {"position_x": 1.0}).status_code == 422
    assert patch("MANUAL-deadbeef", {"name": "X"}).status_code == 404
    assert patch(web["id"], {"name": "Web"}).status_code == 200  # same name is a harmless no-op
    moved = patch(web["id"], {"position_x": 10.0, "position_y": 20.0}).json()
    assert (moved["position_x"], moved["position_y"], moved["name"]) == (10.0, 20.0, "Web")


def test_rename_rejects_name_used_by_an_auto_generated_component(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    headers = {"X-CSRF-Token": csrf}
    application = client.post("/api/applications", json={"name": "K8s"}, headers=headers).json()
    app_url = f"/api/applications/{application['id']}"
    manifest = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  template:\n    spec:\n      containers:\n      - name: api\n        image: nginx\n"
    client.post(
        f"{app_url}/data-sources",
        headers=headers,
        json={"type": "manifest_upload", "connection_details": {"content": manifest, "filename": "d.yaml"}},
    )
    run = client.post(f"{app_url}/runs", headers=headers).json()
    auto_name = next(n["name"] for n in client.get(f"{app_url}/runs/{run['id']}/dfd").json()["nodes"])
    mine = _add(client, app_url, headers, "Mine")

    response = client.patch(f"{app_url}/manual-assets/{mine['id']}", headers=headers, json={"name": auto_name})

    assert response.status_code == 409


def test_edit_manual_flow_label_and_manual_threat_keep_status(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, run, app_url, headers = _blank_model(client, csrf)
    web = _add(client, app_url, headers, "Web")
    db = _add(client, app_url, headers, "DB", "data_store")
    flow = client.post(
        f"{app_url}/manual-flows",
        headers=headers,
        json={"source_ref": f"asset:{web['id']}", "target_ref": f"asset:{db['id']}", "label": "old"},
    ).json()

    edited = client.patch(f"{app_url}/manual-flows/{flow['id']}", headers=headers, json={"label": "  SQL over TLS "})
    assert edited.status_code == 200 and edited.json()["label"] == "SQL over TLS"
    cleared = client.patch(f"{app_url}/manual-flows/{flow['id']}", headers=headers, json={"label": ""})
    assert cleared.json()["label"] is None
    assert (
        client.patch(f"{app_url}/manual-flows/MFLOW-deadbeef", headers=headers, json={"label": "x"}).status_code == 404
    )

    created = client.post(
        f"{app_url}/runs/{run['id']}/manual-threats",
        headers=headers,
        json={"element_kind": "component", "element_id": web["id"], "title": "Old title", "severity": "low"},
    ).json()
    client.put(
        f"{app_url}/runs/{run['id']}/threats/status",
        headers=headers,
        json={"threat_key": created["key"], "status": "accepted", "note": "known"},
    )

    updated = client.patch(
        f"{app_url}/runs/{run['id']}/manual-threats/{created['manual_threat_id']}",
        headers=headers,
        json={
            "title": "New title",
            "description": "why",
            "severity": "critical",
            "category": "Tampering",
            "mitigations": ["Sign requests."],
        },
    )

    assert updated.status_code == 200
    body = updated.json()
    assert (body["title"], body["severity"], body["category"]) == ("New title", "critical", "Tampering")
    assert body["mitigations"] == ["Sign requests."] and body["key"] == created["key"]
    assert body["status"] == "accepted" and body["note"] == "known"
    assert (
        client.patch(
            f"{app_url}/runs/{run['id']}/manual-threats/MT-nope", headers=headers, json={"title": "x"}
        ).status_code
        == 404
    )
    assert (
        client.patch(
            f"{app_url}/runs/{run['id']}/manual-threats/{created['manual_threat_id']}", json={"title": "x"}
        ).status_code
        == 403
    )
