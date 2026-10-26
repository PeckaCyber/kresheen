"""Action plan endpoints."""

from tests.integration.test_api_applications import _logged_in_client, _run_with_manifest


def _plan_url(application, run):
    return f"/api/applications/{application['id']}/runs/{run['id']}/action-plan"


def test_plan_lists_deduplicated_actions_ranked_by_score(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)

    plan = client.get(_plan_url(application, run)).json()

    threats = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/threats").json()["threats"]
    bullets = sum(len(t["mitigations"]) for t in threats)
    assert 0 < plan["summary"]["total"] <= bullets
    scores = [a["score"] for a in plan["actions"]]
    assert scores == sorted(scores, reverse=True)
    assert all(a["threat_count"] >= 1 and a["status"] == "todo" for a in plan["actions"])


def test_status_is_saved_and_survives_a_rerun(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    action = client.get(_plan_url(application, run)).json()["actions"][0]

    response = client.put(
        f"{_plan_url(application, run)}/{action['id']}/status", json={"status": "in_progress"}, headers=headers
    )
    assert response.status_code == 200
    assert next(a for a in response.json()["actions"] if a["id"] == action["id"])["status"] == "in_progress"

    rerun = client.post(f"/api/applications/{application['id']}/runs", headers=headers).json()
    again = client.get(_plan_url(application, rerun)).json()["actions"]
    assert next(a for a in again if a["id"] == action["id"])["status"] == "in_progress"


def test_declining_a_fix_needs_a_reason_and_unknown_actions_404(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    action_id = client.get(_plan_url(application, run)).json()["actions"][0]["id"]

    assert (
        client.put(
            f"{_plan_url(application, run)}/{action_id}/status", json={"status": "wont_do"}, headers=headers
        ).status_code
        == 422
    )
    ok = client.put(
        f"{_plan_url(application, run)}/{action_id}/status",
        json={"status": "wont_do", "note": "not our data"},
        headers=headers,
    )
    assert ok.status_code == 200
    assert (
        client.put(
            f"{_plan_url(application, run)}/ACT-nope/status", json={"status": "done"}, headers=headers
        ).status_code
        == 404
    )


def test_back_to_todo_clears_the_record_and_mutations_need_csrf(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    action_id = client.get(_plan_url(application, run)).json()["actions"][0]["id"]
    url = f"{_plan_url(application, run)}/{action_id}/status"

    assert client.put(url, json={"status": "done"}).status_code == 403
    client.put(url, json={"status": "done"}, headers=headers)
    reset = client.put(url, json={"status": "todo"}, headers=headers).json()
    assert next(a for a in reset["actions"] if a["id"] == action_id)["status"] == "todo"


def test_a_mitigated_threat_drops_out_of_the_plan(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    base = f"/api/applications/{application['id']}/runs/{run['id']}"
    threats = client.get(f"{base}/threats").json()["threats"]
    before = client.get(f"{base}/action-plan").json()["summary"]["open_threats_covered"]

    for threat in threats:
        client.put(f"{base}/threats/status", json={"threat_key": threat["key"], "status": "mitigated"}, headers=headers)

    after = client.get(f"{base}/action-plan").json()
    assert before > 0 and after["summary"]["total"] == 0 and after["summary"]["open_threats_covered"] == 0


def test_reports_and_csv_include_the_action_plan(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    base = f"/api/applications/{application['id']}/runs/{run['id']}"
    first = client.get(f"{base}/action-plan").json()["actions"][0]

    html = client.get(f"{base}/report.html").text
    assert "<h2>Action plan</h2>" in html and first["text"].split(".")[0][:30] in html
    assert client.get(f"{base}/report.docx").status_code == 200
    assert client.get(f"{base}/report.pdf").status_code == 200

    csv_response = client.get(f"{base}/action-plan.csv")
    assert csv_response.status_code == 200
    lines = csv_response.text.lstrip("\ufeff").splitlines()
    assert lines[0] == "rank,action,risk,basis,threats,elements,cwe,how_to_verify,status,note"
    assert len(lines) - 1 == len(client.get(f"{base}/action-plan").json()["actions"])


def test_action_plan_csv_neutralises_formula_text(tmp_path):
    from kresheen.reporting.csv_export import safe_cell

    assert safe_cell('=HYPERLINK("x")').startswith("'")
