"""Multiple diagrams per Application :
every Application always has at least one diagram; a diagram is a curated
*view* over the shared run/threats -- it can hide a component/flow/boundary
and give it its own position, but never changes what's generated."""

from tests.integration.test_api_applications import _logged_in_client


def _blank_model(client, csrf) -> tuple[dict, dict, str, dict]:
    headers = {"X-CSRF-Token": csrf}
    application = client.post("/api/applications", json={"name": "Diagrams"}, headers=headers).json()
    run = client.post(f"/api/applications/{application['id']}/runs", headers=headers).json()
    return application, run, f"/api/applications/{application['id']}", headers


def _add(client, app_url, headers, name, type_="process") -> dict:
    return client.post(f"{app_url}/manual-assets", headers=headers, json={"name": name, "type": type_}).json()


def test_get_diagrams_auto_creates_one_default(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, _run, app_url, _headers = _blank_model(client, csrf)

    diagrams = client.get(f"{app_url}/diagrams").json()

    assert len(diagrams) == 1
    assert diagrams[0]["name"] == "Main"
    assert diagrams[0]["application_id"] == application["id"]
    # Idempotent: asking again doesn't create a second one.
    assert client.get(f"{app_url}/diagrams").json() == diagrams


def test_create_rename_and_delete_diagram(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, _run, app_url, headers = _blank_model(client, csrf)
    main = client.get(f"{app_url}/diagrams").json()[0]

    created = client.post(f"{app_url}/diagrams", json={"name": "Context view"}, headers=headers)
    assert created.status_code == 200
    second = created.json()
    assert {d["id"] for d in client.get(f"{app_url}/diagrams").json()} == {main["id"], second["id"]}

    renamed = client.patch(f"{app_url}/diagrams/{second['id']}", json={"name": "Exec view"}, headers=headers)
    assert renamed.status_code == 200
    assert renamed.json()["name"] == "Exec view"

    assert client.delete(f"{app_url}/diagrams/{second['id']}", headers=headers).status_code == 204
    assert [d["id"] for d in client.get(f"{app_url}/diagrams").json()] == [main["id"]]


def test_cannot_delete_the_only_diagram(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, _run, app_url, headers = _blank_model(client, csrf)
    main = client.get(f"{app_url}/diagrams").json()[0]

    response = client.delete(f"{app_url}/diagrams/{main['id']}", headers=headers)

    assert response.status_code == 422
    assert len(client.get(f"{app_url}/diagrams").json()) == 1


def test_diagram_routes_require_csrf(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, _run, app_url, _headers = _blank_model(client, csrf)
    diagram = client.get(f"{app_url}/diagrams").json()[0]

    assert client.post(f"{app_url}/diagrams", json={"name": "X"}).status_code == 403
    assert client.patch(f"{app_url}/diagrams/{diagram['id']}", json={"name": "X"}).status_code == 403
    assert client.delete(f"{app_url}/diagrams/{diagram['id']}").status_code == 403
    assert (
        client.put(f"{app_url}/diagrams/{diagram['id']}/layout?element_key=process:X", json={"hidden": True}).status_code
        == 403
    )


def test_diagram_from_another_application_is_404(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    headers = {"X-CSRF-Token": csrf}
    _app_a, _run_a, app_a_url, _ = _blank_model(client, csrf)
    _app_b, _run_b, app_b_url, _ = _blank_model(client, csrf)
    diagram_a = client.get(f"{app_a_url}/diagrams").json()[0]

    assert client.get(f"{app_b_url}/diagrams/{diagram_a['id']}/layout").status_code == 404
    assert client.patch(f"{app_b_url}/diagrams/{diagram_a['id']}", json={"name": "X"}, headers=headers).status_code == 404


def test_hiding_a_component_on_one_diagram_does_not_affect_another(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, run, app_url, headers = _blank_model(client, csrf)
    _add(client, app_url, headers, "Widget")
    diagrams_url = f"{app_url}/diagrams"
    main = client.get(diagrams_url).json()[0]
    second = client.post(diagrams_url, json={"name": "Second"}, headers=headers).json()

    hide = client.put(
        f"{diagrams_url}/{second['id']}/layout?element_key=process:Widget", json={"hidden": True}, headers=headers
    )
    assert hide.status_code == 200
    assert hide.json()["hidden"] is True

    dfd_main = client.get(f"{app_url}/runs/{run['id']}/dfd?diagram_id={main['id']}").json()
    dfd_second = client.get(f"{app_url}/runs/{run['id']}/dfd?diagram_id={second['id']}").json()
    assert [n["name"] for n in dfd_main["nodes"]] == ["Widget"]
    assert dfd_second["nodes"] == []

    # Hiding it on one diagram never touches what threats get generated --
    # a diagram is a display filter, not a scoping rule for the engine.
    threats = client.get(f"{app_url}/runs/{run['id']}/threats").json()["threats"]
    assert any(t.get("element_name") == "Widget" for t in threats)


def test_component_position_is_independent_per_diagram(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, run, app_url, headers = _blank_model(client, csrf)
    _add(client, app_url, headers, "Widget")
    diagrams_url = f"{app_url}/diagrams"
    main = client.get(diagrams_url).json()[0]
    second = client.post(diagrams_url, json={"name": "Second"}, headers=headers).json()

    client.put(
        f"{diagrams_url}/{main['id']}/layout?element_key=process:Widget",
        json={"position_x": 10, "position_y": 20},
        headers=headers,
    )
    client.put(
        f"{diagrams_url}/{second['id']}/layout?element_key=process:Widget",
        json={"position_x": 300, "position_y": 400},
        headers=headers,
    )

    node_main = client.get(f"{app_url}/runs/{run['id']}/dfd?diagram_id={main['id']}").json()["nodes"][0]
    node_second = client.get(f"{app_url}/runs/{run['id']}/dfd?diagram_id={second['id']}").json()["nodes"][0]
    assert (node_main["position_x"], node_main["position_y"]) == (10, 20)
    assert (node_second["position_x"], node_second["position_y"]) == (300, 400)


def test_layout_list_includes_hidden_rows_and_clear_resets_to_default(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, _run, app_url, headers = _blank_model(client, csrf)
    _add(client, app_url, headers, "Widget")
    diagram = client.get(f"{app_url}/diagrams").json()[0]
    layout_url = f"{app_url}/diagrams/{diagram['id']}/layout"

    client.put(f"{layout_url}?element_key=process:Widget", json={"hidden": True}, headers=headers)
    rows = client.get(layout_url).json()
    assert len(rows) == 1
    assert rows[0]["element_key"] == "process:Widget"
    assert rows[0]["hidden"] is True

    assert client.delete(f"{layout_url}?element_key=process:Widget", headers=headers).status_code == 204
    assert client.get(layout_url).json() == []
