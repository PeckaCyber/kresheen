from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

PW = "correct-password-1"  # nosec: test fixture


def _client(tmp_path):
    url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(url)
    repo.save_user(
        User(id="U1", email="o@x.test", password_hash=hash_password(PW), role="owner", created_at=datetime.now(UTC))
    )
    c = TestClient(create_app(db_url=url))
    c.headers["X-CSRF-Token"] = c.post("/api/auth/login", json={"email": "o@x.test", "password": PW}).json()[
        "csrf_token"
    ]
    return c


def _pdf(c, aid, rid):
    r = c.get(f"/api/applications/{aid}/runs/{rid}/report.pdf")
    assert r.status_code == 200, r.text[:200]
    assert r.content.startswith(b"%PDF") and len(r.content) > 1000
    return r.content


def test_pdf_renders_a_model_with_hundreds_of_threats(tmp_path):
    c = _client(tmp_path)
    aid = c.post("/api/applications", json={"name": "big"}).json()["id"]
    for i in range(50):
        assert (
            c.post(f"/api/applications/{aid}/manual-assets", json={"name": f"svc-{i}", "type": "process"}).status_code
            == 200
        )
    run = c.post(f"/api/applications/{aid}/runs", json={}).json()
    threats = c.get(f"/api/applications/{aid}/runs/{run['id']}/threats").json()["summary"]["total"]
    assert threats > 250
    _pdf(c, aid, run["id"])


def test_pdf_renders_very_long_names_and_unbroken_tokens(tmp_path):
    c = _client(tmp_path)
    aid = c.post("/api/applications", json={"name": "N" * 3000, "description": "D" * 30000}).json()["id"]
    c.post(f"/api/applications/{aid}/manual-assets", json={"name": "A" * 20000, "type": "process"})
    c.post(f"/api/applications/{aid}/manual-assets", json={"name": "word " * 4000, "type": "data_store"})
    run = c.post(f"/api/applications/{aid}/runs", json={}).json()
    _pdf(c, aid, run["id"])


def test_pdf_still_renders_the_sample_and_normal_names(tmp_path):
    c = _client(tmp_path)
    s = c.post("/api/applications/sample").json()
    _pdf(c, s["application_id"], s["run_id"])
