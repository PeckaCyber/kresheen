from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

PW = "correct-password-1"  # nosec: test fixture
K8S = "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: prod}\nspec: {template: {spec: {containers: [{name: c, image: nginx}]}}}\n"


def _counts(repo):
    with repo.engine.connect() as conn:
        return {
            t: conn.exec_driver_sql(f"select count(*) from {t}").scalar()
            for t in (
                "fact_nodes",
                "fact_edges",
                "assets",
                "asset_flows",
                "threat_snapshots",
                "threat_model_runs",
                "applications",
            )
        }


def test_deleting_an_application_removes_everything_it_produced_and_leaves_others_alone(tmp_path):
    url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(url)
    repo.save_user(
        User(id="U1", email="o@x.test", password_hash=hash_password(PW), role="owner", created_at=datetime.now(UTC))
    )
    c = TestClient(create_app(db_url=url))
    c.headers["X-CSRF-Token"] = c.post("/api/auth/login", json={"email": "o@x.test", "password": PW}).json()[
        "csrf_token"
    ]

    def build(name):
        aid = c.post("/api/applications", json={"name": name}).json()["id"]
        c.post(
            f"/api/applications/{aid}/data-sources",
            json={"type": "manifest_upload", "connection_details": {"content": K8S, "filename": "m.yaml"}},
        )
        c.post(f"/api/applications/{aid}/manual-assets", json={"name": f"hand-{name}", "type": "process"})
        run = c.post(f"/api/applications/{aid}/runs", json={}).json()
        c.post(f"/api/applications/{aid}/runs", json={})  # a second run, so two runs' facts exist
        return aid, run["id"]

    keep_id, keep_run = build("keep")
    baseline = _counts(repo)
    drop_id, _ = build("drop")
    assert _counts(repo)["fact_nodes"] > baseline["fact_nodes"]
    assert c.delete(f"/api/applications/{drop_id}").status_code in (200, 204)
    assert _counts(repo) == baseline, "rows belonging to the deleted application were left behind"
    assert c.get(f"/api/applications/{keep_id}/runs/{keep_run}/dfd").json()["nodes"], "the other application lost data"
