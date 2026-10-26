"""Diagram imports end to end."""

import pytest

from tests.integration.test_api_applications import _logged_in_client
from tests.unit.test_diagram_formats import DRAWIO_CELLS, MERMAID, TD, THREAGILE, _drawio


def _import(client, csrf, content, filename="diagram.txt"):
    headers = {"X-CSRF-Token": csrf}
    application = client.post("/api/applications", json={"name": "Imported"}, headers=headers).json()
    client.post(
        f"/api/applications/{application['id']}/data-sources",
        headers=headers,
        json={"type": "architecture_diagram", "connection_details": {"filename": filename, "content": content}},
    )
    run = client.post(f"/api/applications/{application['id']}/runs", headers=headers).json()
    return application, run, f"/api/applications/{application['id']}/runs/{run['id']}", headers


@pytest.mark.parametrize(
    ("content", "names"),
    [
        (TD, {"Customer", "Web app", "Orders DB"}),
        (_drawio(DRAWIO_CELLS), {"Web Server", "Orders DB", "Customer"}),
        (MERMAID, {"Customer", "Web frontend", "Orders API", "Orders DB", "Payment provider", "Logger"}),
        (THREAGILE, {"Customer Client", "Web App", "Orders DB"}),
    ],
    ids=["threat_dragon", "drawio", "mermaid", "threagile"],
)
def test_each_format_becomes_a_model_with_threats(tmp_path, content, names):
    client, csrf = _logged_in_client(tmp_path)
    _app, _run, base, _headers = _import(client, csrf, content)

    assert client.get(base).json()["source_results"][0]["status"] == "analysed"
    dfd = client.get(f"{base}/dfd").json()
    assert {n["name"] for n in dfd["nodes"]} == names
    assert dfd["edges"] and client.get(f"{base}/threats").json()["threats"]


def test_boundaries_and_types_from_the_file_reach_the_diagram(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _app, _run, base, _headers = _import(client, csrf, TD)

    nodes = {n["name"]: n for n in client.get(f"{base}/dfd").json()["nodes"]}

    assert nodes["Orders DB"]["type"] == "data_store" and nodes["Customer"]["type"] == "external_entity"
    assert nodes["Web app"]["trust_boundary"] == "Internal" and nodes["Orders DB"]["trust_boundary"] == "Data zone"


def test_facts_the_file_states_count_as_stated_and_the_owner_can_override_them(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _app, _run, base, headers = _import(client, csrf, TD)
    nodes = {n["name"]: n for n in client.get(f"{base}/dfd").json()["nodes"]}
    edges = client.get(f"{base}/dfd").json()["edges"]
    web_to_db = next(e for e in edges if e["label"] == "SQL")
    customer_to_web = next(e for e in edges if e["label"] == "HTTPS")

    assert nodes["Orders DB"]["properties"] == {"is_encrypted": True}
    questions = {i["element_name"] + "|" + i["check"] for i in client.get(f"{base}/completeness").json()["items"]}
    assert "Orders DB|encrypted_at_rest" not in questions  # the file already said so
    assert "Customer -> Web app|encrypted_in_transit" not in questions
    assert any(
        i.endswith("encrypted_in_transit") and "Web app -> Orders DB" in i for i in questions
    )  # not stated: still asked

    # The owner's own statement wins over the file's.
    client.put(
        f"{base}/element-properties",
        headers=headers,
        json={
            "element_kind": "component",
            "element_id": nodes["Orders DB"]["id"],
            "properties": {"is_encrypted": False},
        },
    )
    after = {n["name"]: n for n in client.get(f"{base}/dfd").json()["nodes"]}
    assert after["Orders DB"]["properties"]["is_encrypted"] is False
    assert customer_to_web["id"] and web_to_db["id"]


def test_an_unreadable_diagram_is_reported_as_not_analysed(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _app, _run, base, _headers = _import(client, csrf, "PNG binary data, not a diagram")

    result = client.get(base).json()["source_results"][0]

    assert result["status"] == "reference_only" and "format was not recognised" in result["message"]
    assert client.get(f"{base}/dfd").json()["nodes"] == []
