import time

import pytest

from kresheen.engine.ingest.manifest_ingestor import ManifestUploadIngestor
from kresheen.engine.ingest.yaml_safety import MAX_YAML_ALIASES, check_yaml_aliases


def _bomb(levels: int) -> str:
    anchors = ["a0: &a0 [x,x,x,x,x,x,x,x,x]"] + [
        f"a{i}: &a{i} [" + ",".join([f"*a{i - 1}"] * 9) + "]" for i in range(1, levels)
    ]
    return (
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: bomb, namespace: prod}\nextra:\n"
        + "\n".join("  " + a for a in anchors)
        + f"\ndata:\n  x: *a{levels - 1}\n"
    )


def test_alias_bomb_in_a_real_component_document_is_refused_immediately():
    started = time.time()
    with pytest.raises(ValueError, match="YAML aliases"):
        ManifestUploadIngestor().run(run_id="R", application_id="A", connection_details={"content": _bomb(12)})
    assert time.time() - started < 2, "the refusal must not load or expand the document"


def test_a_few_aliases_are_allowed():
    text = "base: &b {a: 1}\n" + "\n".join(f"k{i}: *b" for i in range(MAX_YAML_ALIASES)) + "\n"
    check_yaml_aliases(text)  # exactly at the limit: fine
    with pytest.raises(ValueError):
        check_yaml_aliases(text + "extra: *b\n")


def test_ordinary_manifests_and_markdown_asterisks_are_unaffected():
    manifest = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: prod}\n"
        "spec: {template: {spec: {containers: [{name: c, image: nginx}]}}}\n"
    )
    nodes, _ = ManifestUploadIngestor().run(run_id="R", application_id="A", connection_details={"content": manifest})
    assert any(n.name.endswith("web") or "web" in n.name for n in nodes)
    check_yaml_aliases("description: 2*3 and a*b and **bold**\n")  # asterisks that are not aliases


def test_a_refused_upload_becomes_a_failed_run_with_the_reason(tmp_path):
    from datetime import UTC, datetime

    from fastapi.testclient import TestClient

    from kresheen.dashboard.app import create_app
    from kresheen.dashboard.auth import hash_password
    from kresheen.models.user import User
    from kresheen.storage.sql_repo import SQLRepository

    url = f"sqlite:///{tmp_path}/t.db"
    SQLRepository(url).save_user(
        User(
            id="U",
            email="o@x.test",
            password_hash=hash_password("correct-password-1"),
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    c = TestClient(create_app(db_url=url))
    c.headers["X-CSRF-Token"] = c.post(
        "/api/auth/login", json={"email": "o@x.test", "password": "correct-password-1"}
    ).json()["csrf_token"]
    aid = c.post("/api/applications", json={"name": "a"}).json()["id"]
    c.post(
        f"/api/applications/{aid}/data-sources",
        json={"type": "manifest_upload", "connection_details": {"content": _bomb(10)}},
    )
    run = c.post(f"/api/applications/{aid}/runs", json={}).json()
    assert run["status"] == "failed" and "YAML aliases" in run["error_message"]
