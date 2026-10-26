"""Completeness endpoint and the merge-one-property PATCH."""

from tests.integration.test_api_applications import _logged_in_client
from tests.integration.test_api_manual_modeling import _add, _blank_model, _threats


def _drawn_model(client, csrf):
    _application, run, app_url, headers = _blank_model(client, csrf)
    user = _add(client, app_url, headers, "Patient", "external_entity", "Internet")
    web = _add(client, app_url, headers, "Portal", "process", "DMZ")
    db = _add(client, app_url, headers, "Patient DB", "data_store", "Data")
    for a, b, label in ((user, web, "HTTPS"), (web, db, "SQL")):
        client.post(
            f"{app_url}/manual-flows",
            headers=headers,
            json={"source_ref": f"asset:{a['id']}", "target_ref": f"asset:{b['id']}", "label": label},
        )
    return run, app_url, headers, {"web": web, "db": db}


def _completeness(client, app_url, run):
    return client.get(f"{app_url}/runs/{run['id']}/completeness").json()


def test_completeness_lists_questions_and_score_rises_as_they_are_answered(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    run, app_url, headers, parts = _drawn_model(client, csrf)

    before = _completeness(client, app_url, run)
    assert before["total"] > 0 and before["score"] == 0
    assert {"data_classification", "authenticates_callers", "encrypted_in_transit"} <= {
        i["check"] for i in before["items"]
    }

    client.patch(
        f"{app_url}/runs/{run['id']}/element-properties",
        headers=headers,
        json={
            "element_kind": "component",
            "element_id": parts["web"]["id"],
            "properties": {"authenticates_callers": True},
        },
    )
    after = _completeness(client, app_url, run)
    assert after["score"] > before["score"] and after["answered"] == before["answered"] + 1
    assert not any(i["check"] == "authenticates_callers" for i in after["items"])


def test_patch_merges_and_put_replaces(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    run, app_url, headers, parts = _drawn_model(client, csrf)
    url = f"{app_url}/runs/{run['id']}/element-properties"
    ident = {"element_kind": "component", "element_id": parts["db"]["id"]}

    client.patch(url, headers=headers, json={**ident, "properties": {"is_encrypted": True}})
    merged = client.patch(url, headers=headers, json={**ident, "properties": {"data_classification": "PHI"}}).json()
    assert merged["properties"] == {"is_encrypted": True, "data_classification": "PHI"}

    replaced = client.put(url, headers=headers, json={**ident, "properties": {"stores_credentials": True}}).json()
    assert replaced["properties"] == {"stores_credentials": True}


def test_patch_validates_and_needs_csrf(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    run, app_url, headers, parts = _drawn_model(client, csrf)
    url = f"{app_url}/runs/{run['id']}/element-properties"
    body = {"element_kind": "component", "element_id": parts["db"]["id"], "properties": {"nonsense": True}}

    assert client.patch(url, json=body).status_code == 403
    assert client.patch(url, headers=headers, json=body).status_code == 422
    assert (
        client.patch(
            url, headers=headers, json={**body, "element_id": "nope", "properties": {"is_encrypted": True}}
        ).status_code
        == 404
    )


def test_no_sensitive_data_answers_the_question_without_raising_impact(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    run, app_url, headers, parts = _drawn_model(client, csrf)
    severities_before = {t["key"]: t["severity"] for t in _threats(client, app_url, run)}

    client.patch(
        f"{app_url}/runs/{run['id']}/element-properties",
        headers=headers,
        json={"element_kind": "component", "element_id": parts["db"]["id"], "properties": {"no_sensitive_data": True}},
    )

    assert not any(i["check"] == "data_classification" for i in _completeness(client, app_url, run)["items"])
    assert {t["key"]: t["severity"] for t in _threats(client, app_url, run)} == severities_before


def test_classifying_data_raises_threat_impact_as_the_panel_promises(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    run, app_url, headers, parts = _drawn_model(client, csrf)
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    before = {t["key"]: t["severity"] for t in _threats(client, app_url, run) if t["element_name"] == "Patient DB"}

    client.patch(
        f"{app_url}/runs/{run['id']}/element-properties",
        headers=headers,
        json={
            "element_kind": "component",
            "element_id": parts["db"]["id"],
            "properties": {"data_classification": "PHI"},
        },
    )
    after = {t["key"]: t["severity"] for t in _threats(client, app_url, run) if t["element_name"] == "Patient DB"}
    assert before and all(rank[after[k]] >= rank[before[k]] for k in before) and after != before


def test_docs_only_model_reports_the_unanalysed_input(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    headers = {"X-CSRF-Token": csrf}
    application = client.post("/api/applications", json={"name": "Docs"}, headers=headers).json()
    client.post(
        f"/api/applications/{application['id']}/data-sources",
        headers=headers,
        json={"type": "documentation", "connection_details": {"filename": "d.md", "content": "x"}},
    )
    run = client.post(f"/api/applications/{application['id']}/runs", headers=headers).json()

    out = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/completeness").json()

    assert out["score"] is None and [i["check"] for i in out["items"]] == ["unanalysed_input"]


def test_unknown_run_is_404(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _run, app_url, _headers, _parts = _drawn_model(client, csrf)
    assert client.get(f"{app_url}/runs/RUN-nope/completeness").status_code == 404
