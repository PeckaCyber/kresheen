"""The bundled sample model."""

from tests.integration.test_api_applications import _logged_in_client


def _create(client, csrf):
    return client.post("/api/applications/sample", headers={"X-CSRF-Token": csrf})


def test_sample_is_a_real_runnable_model_with_facts_stated_and_some_left_open(tmp_path):
    client, csrf = _logged_in_client(tmp_path)

    response = _create(client, csrf)

    assert response.status_code == 200
    app_id, run_id = response.json()["application_id"], response.json()["run_id"]
    base = f"/api/applications/{app_id}/runs/{run_id}"
    assert client.get(base).json()["status"] == "completed"
    dfd = client.get(f"{base}/dfd").json()
    assert {n["name"] for n in dfd["nodes"]} == {"Shopper", "Storefront", "Orders API", "Orders DB", "Payment Provider"}
    assert len(dfd["edges"]) == 4

    threats = client.get(f"{base}/threats").json()["threats"]
    assert threats and any(t["basis"] == "specific" for t in threats)
    completeness = client.get(f"{base}/completeness").json()
    assert completeness["score"] is not None and 0 < completeness["score"] < 100
    assert completeness["items"]  # questions left on purpose


def test_sample_states_the_facts_it_says_it_does(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    ids = _create(client, csrf).json()
    base = f"/api/applications/{ids['application_id']}/runs/{ids['run_id']}"

    api = {n["name"]: n for n in client.get(f"{base}/dfd").json()["nodes"]}
    assert api["Orders API"]["properties"] == {"authenticates_callers": False}
    assert api["Orders DB"]["properties"] == {"data_classification": "PCI"}


def test_each_call_makes_an_independent_ungrouped_copy_that_can_be_deleted(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    first, second = _create(client, csrf).json(), _create(client, csrf).json()

    assert first["application_id"] != second["application_id"]
    listed = client.get("/api/applications?group_id=ungrouped").json()
    assert {a["id"] for a in listed} >= {first["application_id"], second["application_id"]}
    assert client.delete(f"/api/applications/{first['application_id']}", headers={"X-CSRF-Token": csrf}).status_code == 204
    assert client.get(f"/api/applications/{first['application_id']}").status_code == 404


def test_sample_is_csrf_protected(tmp_path):
    client, _csrf = _logged_in_client(tmp_path)

    assert client.post("/api/applications/sample").status_code == 403
