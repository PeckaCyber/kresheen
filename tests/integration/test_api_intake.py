"""Guided intake endpoints."""

from tests.integration.test_api_applications import _logged_in_client

ANSWERS = {
    "name": "Portal",
    "system_type": "web_app",
    "users": ["customers"],
    "authentication": "password",
    "data": ["health"],
    "third_parties": ["email"],
    "has_admin": True,
}


def _create(client, csrf, **overrides):
    return client.post("/api/intake", headers={"X-CSRF-Token": csrf}, json={**ANSWERS, **overrides})


def test_options_serve_every_question_and_the_templates(tmp_path):
    client, _csrf = _logged_in_client(tmp_path)

    options = client.get("/api/intake/options").json()

    assert {o["id"] for o in options["system_types"]} >= {"web_app", "ai_rag_app"}
    assert {o["id"] for o in options["authentication"]} == {"password", "sso", "api_keys", "none"}
    assert options["templates"] and all(
        {"id", "title", "description", "answers"} <= t.keys() for t in options["templates"]
    )


def test_intake_creates_and_runs_an_ordinary_editable_model(tmp_path):
    client, csrf = _logged_in_client(tmp_path)

    response = _create(client, csrf)

    assert response.status_code == 200
    ids = response.json()
    base = f"/api/applications/{ids['application_id']}/runs/{ids['run_id']}"
    assert client.get(base).json()["status"] == "completed"
    dfd = client.get(f"{base}/dfd").json()
    names = {n["name"] for n in dfd["nodes"]}
    assert {
        "Customer",
        "Web frontend",
        "Application server",
        "Database",
        "Email service",
        "Administrator",
        "Admin panel",
    } <= names
    assert all(n["is_manual"] for n in dfd["nodes"])  # editable like anything hand-drawn

    application = client.get(f"/api/applications/{ids['application_id']}").json()
    assert application["name"] == "Portal" and "guided intake" in application["description"]


def test_stated_answers_reach_the_results(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    ids = _create(client, csrf).json()
    base = f"/api/applications/{ids['application_id']}/runs/{ids['run_id']}"

    nodes = {n["name"]: n for n in client.get(f"{base}/dfd").json()["nodes"]}
    assert nodes["Database"]["properties"]["data_classification"] == "PHI"
    threats = client.get(f"{base}/threats").json()["threats"]
    assert any(t["basis"] == "specific" for t in threats)
    completeness = client.get(f"{base}/completeness").json()
    assert completeness["score"] is not None and completeness["score"] > 0  # answers already count as stated
    assert any(i["element_name"] == "Admin panel" for i in completeness["items"])  # what is left is asked


def test_invalid_answers_are_rejected(tmp_path):
    client, csrf = _logged_in_client(tmp_path)

    assert _create(client, csrf, system_type="mainframe").status_code == 422
    assert _create(client, csrf, users=[]).status_code == 422
    assert _create(client, csrf, name="").status_code == 422
    assert _create(client, csrf, group_id="GRP-nope").status_code == 422


def test_can_create_inside_a_group_and_needs_csrf(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    group = client.post("/api/groups", headers={"X-CSRF-Token": csrf}, json={"name": "Payments"}).json()

    created = _create(client, csrf, group_id=group["id"]).json()

    assert client.get(f"/api/applications/{created['application_id']}").json()["group_id"] == group["id"]
    assert client.post("/api/intake", json=ANSWERS).status_code == 403


def test_every_template_creates_a_model_that_runs(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    for template in client.get("/api/intake/options").json()["templates"]:
        response = _create(client, csrf, **template["answers"])
        assert response.status_code == 200, template["id"]
        run = client.get(
            f"/api/applications/{response.json()['application_id']}/runs/{response.json()['run_id']}"
        ).json()
        assert run["status"] == "completed", template["id"]
