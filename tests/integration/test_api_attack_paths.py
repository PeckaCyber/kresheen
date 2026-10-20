"""GET /api/applications/{id}/runs/{run_id}/attack-paths -- the endpoint's own
plumbing (auth, run resolution, response shape). engine/attack_paths.py's own
tracing logic is covered directly in tests/unit/test_attack_paths.py; this
file only needs one real path built through the manual-modeling API (a blank
run plus manual components/flows) to confirm the wiring end to end.
"""

from __future__ import annotations

from tests.integration.test_api_applications import _logged_in_client


def _post(client, csrf, path, body):
    return client.post(path, json=body, headers={"X-CSRF-Token": csrf})


def test_attack_paths_is_empty_for_a_blank_model_with_no_components(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _post(client, csrf, "/api/applications", {"name": "Blank"}).json()
    run = _post(client, csrf, f"/api/applications/{application['id']}/runs", {}).json()

    response = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/attack-paths")

    assert response.status_code == 200
    assert response.json()["paths"] == []


def test_attack_paths_traces_external_entity_to_a_crown_jewel_data_store(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _post(client, csrf, "/api/applications", {"name": "Shop"}).json()
    run = _post(client, csrf, f"/api/applications/{application['id']}/runs", {}).json()

    entity = _post(
        client, csrf, f"/api/applications/{application['id']}/manual-assets",
        {"name": "Customer", "type": "external_entity"},
    ).json()
    db = _post(
        client, csrf, f"/api/applications/{application['id']}/manual-assets",
        {"name": "Orders DB", "type": "data_store"},
    ).json()
    _post(
        client, csrf, f"/api/applications/{application['id']}/manual-flows",
        {"source_ref": f"asset:{entity['id']}", "target_ref": f"asset:{db['id']}", "label": "checkout"},
    )
    props = client.put(
        f"/api/applications/{application['id']}/runs/{run['id']}/element-properties",
        json={"element_kind": "component", "element_id": db["id"], "properties": {"data_classification": "PII"}},
        headers={"X-CSRF-Token": csrf},
    )
    assert props.status_code == 200

    response = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/attack-paths")

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert len(paths) == 1
    path = paths[0]
    assert path["source_name"] == "Customer"
    assert path["target_name"] == "Orders DB"
    assert path["is_crown_jewel"] is True
    assert path["risk"] == "critical"  # no authentication stated on the flow
    assert [h["to_name"] for h in path["hops"]] == ["Orders DB"]
    assert path["hops"][0]["flow_label"] == "checkout"


def test_attack_paths_404s_for_a_run_belonging_to_a_different_application(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    app_a = _post(client, csrf, "/api/applications", {"name": "A"}).json()
    app_b = _post(client, csrf, "/api/applications", {"name": "B"}).json()
    run_a = _post(client, csrf, f"/api/applications/{app_a['id']}/runs", {}).json()

    response = client.get(f"/api/applications/{app_b['id']}/runs/{run_a['id']}/attack-paths")

    assert response.status_code == 404
