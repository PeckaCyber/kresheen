from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.threat_model_run import SourceResult
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

PW = "correct-password-1"  # nosec: test fixture


def test_report_and_run_show_that_a_scan_step_did_not_run(tmp_path):
    url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(url)
    repo.save_user(User(id="U1", email="o@x.test", password_hash=hash_password(PW), role="owner", created_at=datetime.now(UTC)))
    c = TestClient(create_app(db_url=url))
    c.headers["X-CSRF-Token"] = c.post("/api/auth/login", json={"email": "o@x.test", "password": PW}).json()["csrf_token"]
    ids = c.post("/api/applications/sample").json()
    run = repo.get_run(ids["run_id"])
    run.source_results.append(SourceResult(data_source_id="DS-9", type="github_repository", status="analysed", component_count=3,
                                           warnings=["The vulnerability scan timed out, so dependencies were not checked."]))
    repo.save_run(run)
    api_run = c.get(f"/api/applications/{ids['application_id']}/runs/{ids['run_id']}").json()
    assert api_run["source_results"][-1]["warnings"]
    html = c.get(f"/api/applications/{ids['application_id']}/runs/{ids['run_id']}/report.html").text
    assert "not analysed" in html and "vulnerability scan timed out" in html
    assert c.get(f"/api/applications/{ids['application_id']}/runs/{ids['run_id']}/report.docx").status_code == 200
    comp = c.get(f"/api/applications/{ids['application_id']}/runs/{ids['run_id']}/completeness").json()
    assert any(i["check"] == "partial_input" for i in comp["items"])
