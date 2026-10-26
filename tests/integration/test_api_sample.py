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
    assert (
        client.delete(f"/api/applications/{first['application_id']}", headers={"X-CSRF-Token": csrf}).status_code == 204
    )
    assert client.get(f"/api/applications/{first['application_id']}").status_code == 404


def test_sample_is_csrf_protected(tmp_path):
    client, _csrf = _logged_in_client(tmp_path)

    assert client.post("/api/applications/sample").status_code == 403


def _threats_by_rule(client, ids):
    base = f"/api/applications/{ids['application_id']}/runs/{ids['run_id']}"
    assert client.get(base).json()["status"] == "completed"
    threats = client.get(f"{base}/threats").json()["threats"]
    return base, {t["rule_id"]: t for t in threats if t["rule_id"].startswith("SC-")}


def test_sample_keys_match_the_api_choices():
    from typing import get_args

    from kresheen.engine.samples import SAMPLES, SampleKey

    assert set(SAMPLES) == set(get_args(SampleKey))


def test_kubernetes_sample_ingests_its_manifests_and_shows_the_planted_weaknesses(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    response = client.post("/api/applications/sample", json={"sample": "kubernetes"}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    ids = response.json()

    base, config_hits = _threats_by_rule(client, ids)
    assert set(config_hits) == {"SC-T01", "SC-T02", "SC-T08"}
    assert config_hits["SC-T02"]["risk"] == "critical"
    dfd = client.get(f"{base}/dfd").json()
    assert {n["trust_boundary"] for n in dfd["nodes"] if n["type"] == "process"} == {
        "helpdesk",
        "helpdesk-data",
        "platform-ops",
    }
    assert len(dfd["edges"]) >= 4
    sources = client.get(f"/api/applications/{ids['application_id']}/data-sources").json()
    assert [s["type"] for s in sources] == ["manifest_upload"]
    # The planted ConfigMap password is redacted at ingest like any upload.
    assert "example-placeholder" not in client.get(f"{base}/dfd").text


def test_aws_sample_ingests_its_plan_and_shows_the_planted_weaknesses(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    response = client.post("/api/applications/sample", json={"sample": "aws"}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    ids = response.json()

    base, config_hits = _threats_by_rule(client, ids)
    assert set(config_hits) == {"SC-AWS-T01R", "SC-AWS-T05"}
    names = {n["id"]: n["name"] for n in client.get(f"{base}/dfd").json()["nodes"]}
    edges = {(names[e["source"]], names[e["target"]]) for e in client.get(f"{base}/dfd").json()["edges"]}
    assert ("Internet", "aws_lb.web") in edges
    assert ("Internet", "aws_db_instance.main") in edges
    assert ("aws_instance.app", "aws_s3_bucket.uploads") in edges


def test_unknown_sample_is_rejected(tmp_path):
    client, csrf = _logged_in_client(tmp_path)

    response = client.post("/api/applications/sample", json={"sample": "nope"}, headers={"X-CSRF-Token": csrf})

    assert response.status_code == 422
