from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

_TEST_EMAIL = "owner@example.com"
_TEST_PASSWORD = "correct-password"  # nosec: test fixture, not a real credential


def _logged_in_client(tmp_path) -> tuple[TestClient, str]:
    db_url = f"sqlite:///{tmp_path}/test.db"
    repo = SQLRepository(db_url)
    repo.save_user(
        User(
            id="USER-test", email=_TEST_EMAIL, password_hash=hash_password(_TEST_PASSWORD),
            role="owner", created_at=datetime.now(UTC),
        )
    )
    client = TestClient(create_app(db_url=db_url))
    login = client.post("/api/auth/login", json={"email": _TEST_EMAIL, "password": _TEST_PASSWORD})
    return client, login.json()["csrf_token"]


def test_list_applications_requires_authentication(tmp_path):
    client = TestClient(create_app(db_url=f"sqlite:///{tmp_path}/test.db"))

    assert client.get("/api/applications").status_code == 401


def test_create_application_without_csrf_is_rejected(tmp_path):
    client, _csrf = _logged_in_client(tmp_path)

    response = client.post("/api/applications", json={"name": "Test App"})

    assert response.status_code == 403


def test_create_and_list_application(tmp_path):
    client, csrf = _logged_in_client(tmp_path)

    created = client.post(
        "/api/applications", json={"name": "Test App", "description": "desc"}, headers={"X-CSRF-Token": csrf}
    )
    assert created.status_code == 200
    body = created.json()
    assert body["name"] == "Test App"
    assert body["status"] == "draft"

    listed = client.get("/api/applications")
    assert listed.status_code == 200
    assert [a["id"] for a in listed.json()] == [body["id"]]


def test_create_application_with_metadata_and_update_it(tmp_path):
    """Model metadata : owner,
    reviewer, contributors -- settable at creation, editable after."""
    client, csrf = _logged_in_client(tmp_path)

    created = client.post(
        "/api/applications",
        json={"name": "Test App", "owner": "Jane Owner", "reviewer": "", "contributors": ["Alex", "Sam"]},
        headers={"X-CSRF-Token": csrf},
    ).json()
    assert created["owner"] == "Jane Owner"
    assert created["reviewer"] == ""
    assert created["contributors"] == ["Alex", "Sam"]

    updated = client.patch(
        f"/api/applications/{created['id']}/metadata",
        json={
            "name": "Renamed App",
            "description": "Now with a description",
            "owner": "Jane Owner",
            "reviewer": "Pat Reviewer",
            "contributors": ["Alex"],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["name"] == "Renamed App"
    assert body["description"] == "Now with a description"
    assert body["reviewer"] == "Pat Reviewer"
    assert body["contributors"] == ["Alex"]

    fetched = client.get(f"/api/applications/{created['id']}").json()
    assert fetched["name"] == "Renamed App" and fetched["reviewer"] == "Pat Reviewer"


def test_update_application_metadata_requires_csrf_and_404s_for_unknown_application(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = client.post("/api/applications", json={"name": "Test App"}, headers={"X-CSRF-Token": csrf}).json()

    no_csrf = client.patch(f"/api/applications/{application['id']}/metadata", json={"name": "x"})
    assert no_csrf.status_code == 403

    unknown = client.patch(
        "/api/applications/nope/metadata", json={"name": "x"}, headers={"X-CSRF-Token": csrf}
    )
    assert unknown.status_code == 404


def test_get_unknown_application_404s(tmp_path):
    client, _csrf = _logged_in_client(tmp_path)

    assert client.get("/api/applications/nope").status_code == 404


def test_delete_application_removes_it(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    created = client.post("/api/applications", json={"name": "Test App"}, headers={"X-CSRF-Token": csrf}).json()

    response = client.delete(f"/api/applications/{created['id']}", headers={"X-CSRF-Token": csrf})

    assert response.status_code == 204
    assert client.get(f"/api/applications/{created['id']}").status_code == 404


def test_create_run_without_data_sources_makes_an_empty_blank_model(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = client.post("/api/applications", json={"name": "Test App"}, headers={"X-CSRF-Token": csrf}).json()

    response = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200
    run = response.json()
    assert run["status"] == "completed" and run["data_source_config_ids"] == []
    dfd = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/dfd").json()
    assert dfd["nodes"] == [] and dfd["edges"] == []


def test_create_data_source_rejects_unsupported_type(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = client.post("/api/applications", json={"name": "Test App"}, headers={"X-CSRF-Token": csrf}).json()

    response = client.post(
        f"/api/applications/{application['id']}/data-sources",
        json={"type": "k8s_live", "connection_details": {}},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "data_source_type", ["manifest_upload", "github_repository", "architecture_diagram", "documentation"]
)
def test_create_data_source_accepts_every_registered_ingestor_type(tmp_path, data_source_type):
    """Regression test: `create_data_source` validates against
    `engine.orchestrator.SUPPORTED_DATA_SOURCE_TYPES` (derived from the same
    `_INGESTORS` dict `execute_run` uses), not a second, independently
    maintained list. This pins every registered type through the real route,
    not just the ingestor classes directly, so the two can't drift apart
    silently."""
    client, csrf = _logged_in_client(tmp_path)
    application = client.post("/api/applications", json={"name": "Test App"}, headers={"X-CSRF-Token": csrf}).json()

    response = client.post(
        f"/api/applications/{application['id']}/data-sources",
        json={"type": data_source_type, "connection_details": {}},
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 200
    assert response.json()["type"] == data_source_type


# These integration tests use `manifest_upload` (a k8s manifest with one hostNetwork pod, one
# notable enough to also produce a rule-based finding) as the representative working data source.
_MANIFEST_WITH_ONE_FINDING = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  hostNetwork: true
  template:
    spec:
      containers:
        - name: web
          image: myregistry/web:1.0.0
"""


def _create_application_with_manifest_source(client: TestClient, csrf: str) -> dict:
    application = client.post("/api/applications", json={"name": "Test App"}, headers={"X-CSRF-Token": csrf}).json()
    client.post(
        f"/api/applications/{application['id']}/data-sources",
        json={"type": "manifest_upload", "connection_details": {"content": _MANIFEST_WITH_ONE_FINDING}},
        headers={"X-CSRF-Token": csrf},
    )
    return application


def test_full_run_lifecycle_produces_dfd_and_findings(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)

    run_response = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf})
    assert run_response.status_code == 200
    run = run_response.json()
    assert run["status"] == "completed"

    application_after = client.get(f"/api/applications/{application['id']}").json()
    assert application_after["latest_run_id"] == run["id"]
    assert application_after["status"] == "active"

    dfd = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/dfd")
    assert dfd.status_code == 200
    assert len(dfd.json()["nodes"]) == 1

    findings = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/findings")
    assert findings.status_code == 200
    assert len(findings.json()) == 1
    assert findings.json()[0]["evidence"]["stride_category"] == "ElevationOfPrivilege"

    runs = client.get(f"/api/applications/{application['id']}/runs")
    assert [r["id"] for r in runs.json()] == [run["id"]]


def test_staleness_is_true_with_no_runs_yet(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = client.post("/api/applications", json={"name": "Test App"}, headers={"X-CSRF-Token": csrf}).json()

    response = client.get(f"/api/applications/{application['id']}/staleness")

    assert response.status_code == 200
    assert response.json()["stale"] is True


def test_staleness_is_false_right_after_a_run_and_true_once_a_source_is_added(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)
    client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf})

    fresh = client.get(f"/api/applications/{application['id']}/staleness").json()
    assert fresh["stale"] is False

    client.post(
        f"/api/applications/{application['id']}/data-sources",
        json={"type": "documentation", "connection_details": {"content": "notes", "filename": "notes.txt"}},
        headers={"X-CSRF-Token": csrf},
    )
    after_add = client.get(f"/api/applications/{application['id']}/staleness").json()
    assert after_add["stale"] is True
    assert len(after_add["new_data_source_ids"]) == 1


def test_run_diff_has_no_previous_run_on_the_first_run(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)
    run = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()

    response = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/diff")

    assert response.status_code == 200
    body = response.json()
    assert body["previous_run_id"] is None
    assert body["new_components"] == []


def test_run_diff_against_previous_run_shows_new_component_and_threat(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)
    run1 = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()

    # A second data source appears before the next run -- e.g. a new manifest.
    client.post(
        f"/api/applications/{application['id']}/data-sources",
        json={
            "type": "manifest_upload",
            "connection_details": {
                "content": (
                    "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
                    "  name: worker\n  namespace: prod\nspec:\n"
                    "  template:\n    spec:\n      containers:\n"
                    "        - name: worker\n          image: myregistry/worker:1.0.0\n"
                )
            },
        },
        headers={"X-CSRF-Token": csrf},
    )
    run2 = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()

    response = client.get(f"/api/applications/{application['id']}/runs/{run2['id']}/diff")

    assert response.status_code == 200
    body = response.json()
    assert body["previous_run_id"] == run1["id"]
    assert any(c["name"] == "Deployment/worker" for c in body["new_components"])
    assert body["removed_components"] == []


def test_run_diff_against_explicit_run_404s_for_a_run_belonging_to_a_different_application(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    app_a = _create_application_with_manifest_source(client, csrf)
    app_b = _create_application_with_manifest_source(client, csrf)
    run_a = client.post(f"/api/applications/{app_a['id']}/runs", headers={"X-CSRF-Token": csrf}).json()
    run_b = client.post(f"/api/applications/{app_b['id']}/runs", headers={"X-CSRF-Token": csrf}).json()

    response = client.get(f"/api/applications/{app_a['id']}/runs/{run_a['id']}/diff?against={run_b['id']}")

    assert response.status_code == 404


def test_get_run_404s_for_a_run_belonging_to_a_different_application(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    app_a = _create_application_with_manifest_source(client, csrf)
    app_b = client.post("/api/applications", json={"name": "App B"}, headers={"X-CSRF-Token": csrf}).json()
    run = client.post(f"/api/applications/{app_a['id']}/runs", headers={"X-CSRF-Token": csrf}).json()

    response = client.get(f"/api/applications/{app_b['id']}/runs/{run['id']}")

    assert response.status_code == 404


def test_sbom_endpoint_returns_null_when_a_run_has_no_sbom(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)
    run = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()

    response = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/sbom")

    assert response.status_code == 200
    assert response.json() is None


def test_full_run_lifecycle_with_github_source_produces_an_sbom_and_a_vulnerability_finding(tmp_path):
    import json
    import subprocess
    from pathlib import Path
    from unittest.mock import patch

    import responses

    from tests.conftest import build_tarball_bytes

    fixture = json.loads(
        (Path(__file__).parent.parent / "fixtures" / "grype" / "sample_cyclonedx.json").read_text()
    )
    tarball = build_tarball_bytes({"package.json": "{}", "package-lock.json": "{}"})

    client, csrf = _logged_in_client(tmp_path)
    application = client.post("/api/applications", json={"name": "GitHub App"}, headers={"X-CSRF-Token": csrf}).json()

    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET, "https://api.github.com/repos/acme/widget/tarball", body=tarball, status=200
        )

        client.post(
            f"/api/applications/{application['id']}/data-sources",
            json={"type": "github_repository", "connection_details": {"repo_url": "acme/widget"}},
            headers={"X-CSRF-Token": csrf},
        )

        def _write_grype_outputs(args, **kwargs):
            # _run_grype_scan asks Grype for two simultaneous outputs
            # (-o cyclonedx-json=<path> -o json=<path>) rather than one to
            # stdout -- mocking it means writing to whichever paths the
            # real command line asks for.
            for arg in args:
                if isinstance(arg, str) and arg.startswith("cyclonedx-json="):
                    Path(arg.split("=", 1)[1]).write_text(json.dumps(fixture))
                elif isinstance(arg, str) and arg.startswith("json="):
                    Path(arg.split("=", 1)[1]).write_text(json.dumps({"matches": []}))
            return subprocess.CompletedProcess(args=args, returncode=0, stdout=b"", stderr=b"")

        with patch("kresheen.engine.ingest.github_repository_ingestor.subprocess.run") as mock_run:
            mock_run.side_effect = _write_grype_outputs
            run = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()

    assert run["status"] == "completed"

    sbom_response = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/sbom")
    assert sbom_response.status_code == 200
    sbom = sbom_response.json()
    assert sbom is not None
    assert sbom["format"] == "cyclonedx-json"
    # The fixture has 3 raw components (fixture-app, lodash, and one
    # type="file" pseudo-component with no purl) -- only the two real npm
    # ones survive the application-dependency filter.
    assert sbom["component_count"] == 2
    assert sbom["vulnerability_count"] == len(fixture["vulnerabilities"])
    assert {c["name"] for c in sbom["components"]} == {"lodash", "fixture-app"}
    assert sbom["no_lockfile_detected"] is False

    findings = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/findings").json()
    vuln_findings = [f for f in findings if f["domain"] == "vulnerability"]
    assert len(vuln_findings) == 1
    assert vuln_findings[0]["evidence"]["cve_refs"] == ["GHSA-35jh-r3h4-6jhm"]


# -- Trust boundaries / manual DFD editing ----------------------
#
# `_MANIFEST_WITH_ONE_FINDING`'s Deployment "web" produces exactly one
# auto-generated Asset, named "Deployment/web" (see
# engine/ingest/manifest_ingestor.py's `name=f"{kind}/{name}"`).


def test_save_and_clear_trust_boundary_overrides_dfd_node_by_name(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)
    run = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()

    save = client.put(
        f"/api/applications/{application['id']}/trust-boundaries",
        json={"component_name": "Deployment/web", "trust_boundary": "internal"},
        headers={"X-CSRF-Token": csrf},
    )
    assert save.status_code == 200

    dfd = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/dfd").json()
    node = next(n for n in dfd["nodes"] if n["name"] == "Deployment/web")
    assert node["trust_boundary"] == "internal"
    assert node["boundary_overridden"] is True

    # Re-saving the same component's boundary updates the row rather than
    # accumulating a duplicate.
    client.put(
        f"/api/applications/{application['id']}/trust-boundaries",
        json={"component_name": "Deployment/web", "trust_boundary": "internet-facing"},
        headers={"X-CSRF-Token": csrf},
    )
    dfd_again = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/dfd").json()
    node_again = next(n for n in dfd_again["nodes"] if n["name"] == "Deployment/web")
    assert node_again["trust_boundary"] == "internet-facing"

    clear = client.delete(
        f"/api/applications/{application['id']}/trust-boundaries",
        params={"component_name": "Deployment/web"},
        headers={"X-CSRF-Token": csrf},
    )
    assert clear.status_code == 204
    dfd_cleared = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/dfd").json()
    node_cleared = next(n for n in dfd_cleared["nodes"] if n["name"] == "Deployment/web")
    # Clearing the override falls back to the auto-derived boundary, which for
    # a Kubernetes workload is its namespace.
    assert node_cleared["trust_boundary"] == "prod"
    assert node_cleared["boundary_overridden"] is False


def test_manual_asset_persists_across_reruns_and_is_flagged_in_dfd(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)

    created = client.post(
        f"/api/applications/{application['id']}/manual-assets",
        json={"name": "Third-party billing API", "type": "external_entity", "trust_boundary": "third-party"},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 200
    manual_asset = created.json()
    assert manual_asset["source"] == "manual"

    run_1 = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()
    dfd_1 = client.get(f"/api/applications/{application['id']}/runs/{run_1['id']}/dfd").json()
    node_1 = next(n for n in dfd_1["nodes"] if n["id"] == manual_asset["id"])
    assert node_1["is_manual"] is True
    assert node_1["trust_boundary"] == "third-party"

    # Re-running regenerates every auto-derived Asset with fresh ids, but
    # the manual one (run_id=None) is never touched by that delete -- it
    # must still show up, same id, on the new run's diagram too.
    run_2 = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()
    assert run_2["id"] != run_1["id"]
    dfd_2 = client.get(f"/api/applications/{application['id']}/runs/{run_2['id']}/dfd").json()
    node_2 = next(n for n in dfd_2["nodes"] if n["id"] == manual_asset["id"])
    assert node_2["is_manual"] is True

    delete = client.delete(
        f"/api/applications/{application['id']}/manual-assets/{manual_asset['id']}",
        headers={"X-CSRF-Token": csrf},
    )
    assert delete.status_code == 204
    dfd_after_delete = client.get(f"/api/applications/{application['id']}/runs/{run_2['id']}/dfd").json()
    assert all(n["id"] != manual_asset["id"] for n in dfd_after_delete["nodes"])


def test_manual_asset_position_round_trips_through_the_dfd_response(tmp_path):
    """Regression test for drag-and-drop placement:
    a manual asset's drop position must survive being written and then
    read back through the actual /dfd route, not just the raw model --
    that's the route the frontend's layoutNodes() depends on to keep a
    dropped component where the user put it instead of snapping back to
    the auto-grid layout on the next fetch."""
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)

    created = client.post(
        f"/api/applications/{application['id']}/manual-assets",
        json={"name": "Payment Gateway", "type": "external_entity", "position_x": 123.5, "position_y": -40.0},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 200
    manual_asset = created.json()
    assert manual_asset["position_x"] == 123.5
    assert manual_asset["position_y"] == -40.0

    run = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()
    dfd = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/dfd").json()
    node = next(n for n in dfd["nodes"] if n["id"] == manual_asset["id"])
    assert node["position_x"] == 123.5
    assert node["position_y"] == -40.0

    # An auto-generated node never carries a position, even though the
    # field exists on every node in the response -- confirms the "only
    # meaningful for is_manual" scoping in get_run_dfd, not just that the
    # key is present.
    auto_node = next(n for n in dfd["nodes"] if not n["is_manual"])
    assert auto_node["position_x"] is None
    assert auto_node["position_y"] is None


def test_manual_flow_resolves_name_ref_against_current_run_and_skips_unresolvable_ones(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)
    manual_asset = client.post(
        f"/api/applications/{application['id']}/manual-assets",
        json={"name": "Payment processor", "type": "external_entity"},
        headers={"X-CSRF-Token": csrf},
    ).json()

    resolvable = client.post(
        f"/api/applications/{application['id']}/manual-flows",
        json={
            "source_ref": f"asset:{manual_asset['id']}",
            "target_ref": "name:Deployment/web",
            "label": "processes payments for",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resolvable.status_code == 200

    unresolvable = client.post(
        f"/api/applications/{application['id']}/manual-flows",
        json={"source_ref": f"asset:{manual_asset['id']}", "target_ref": "name:Nonexistent/component"},
        headers={"X-CSRF-Token": csrf},
    )
    assert unresolvable.status_code == 200
    unresolvable_id = unresolvable.json()["id"]

    run = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()
    dfd = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/dfd").json()

    web_node = next(n for n in dfd["nodes"] if n["name"] == "Deployment/web")
    manual_edges = [e for e in dfd["edges"] if e["is_manual"]]
    assert len(manual_edges) == 1
    assert manual_edges[0]["source"] == manual_asset["id"]
    assert manual_edges[0]["target"] == web_node["id"]
    assert manual_edges[0]["label"] == "processes payments for"
    assert all(e["id"] != unresolvable_id for e in dfd["edges"])

    delete = client.delete(
        f"/api/applications/{application['id']}/manual-flows/{manual_edges[0]['id']}",
        headers={"X-CSRF-Token": csrf},
    )
    assert delete.status_code == 204
    dfd_after_delete = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/dfd").json()
    assert not any(e["is_manual"] for e in dfd_after_delete["edges"])


def _completed_run_dfd(client: TestClient, csrf: str, application_id: str) -> dict:
    run = client.post(f"/api/applications/{application_id}/runs", headers={"X-CSRF-Token": csrf}).json()
    return client.get(f"/api/applications/{application_id}/runs/{run['id']}/dfd").json()


def _default_diagram_id(client: TestClient, application_id: str) -> str:
    return client.get(f"/api/applications/{application_id}/diagrams").json()[0]["id"]


def test_diagram_boundary_layout_round_trips_and_upserts_by_key(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)
    diagram_id = _default_diagram_id(client, application["id"])
    url = f"/api/applications/{application['id']}/diagrams/{diagram_id}/layout"
    headers = {"X-CSRF-Token": csrf}

    first = client.put(
        f"{url}?element_key=boundary:internal", json={"position_x": 10, "position_y": 20}, headers=headers
    )
    second = client.put(
        f"{url}?element_key=boundary:internal", json={"position_x": -5.5, "position_y": 99}, headers=headers
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["id"] == second.json()["id"]  # moved, not duplicated

    dfd = _completed_run_dfd(client, csrf, application["id"])
    assert dfd["boundaries"] == [{"name": "internal", "position_x": -5.5, "position_y": 99}]

    assert client.delete(f"{url}?element_key=boundary:internal", headers=headers).status_code == 204
    assert _completed_run_dfd(client, csrf, application["id"])["boundaries"] == []


def test_diagram_layout_requires_csrf(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)
    diagram_id = _default_diagram_id(client, application["id"])

    response = client.put(
        f"/api/applications/{application['id']}/diagrams/{diagram_id}/layout?element_key=boundary:internal",
        json={"position_x": 1, "position_y": 2},
    )

    assert response.status_code == 403


def test_move_manual_asset_updates_position_and_rejects_non_manual_ids(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    base = f"/api/applications/{application['id']}"
    asset = client.post(
        f"{base}/manual-assets",
        json={"name": "Queue", "type": "data_store", "position_x": 1, "position_y": 2},
        headers=headers,
    ).json()

    moved = client.patch(f"{base}/manual-assets/{asset['id']}", json={"position_x": 300, "position_y": 400}, headers=headers)
    assert moved.status_code == 200
    dfd = _completed_run_dfd(client, csrf, application["id"])
    node = next(n for n in dfd["nodes"] if n["id"] == asset["id"])
    assert (node["position_x"], node["position_y"]) == (300, 400)

    auto_node = next(n for n in dfd["nodes"] if not n["is_manual"])
    rejected = client.patch(f"{base}/manual-assets/{auto_node['id']}", json={"position_x": 1, "position_y": 1}, headers=headers)
    assert rejected.status_code == 404


def test_manual_asset_can_be_restored_under_its_original_id_and_flows_reattach(tmp_path):
    """Undo of a delete re-creates the asset with its old id; a manual flow
    that referenced it as "asset:<id>" must resolve again."""
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    base = f"/api/applications/{application['id']}"
    a = client.post(f"{base}/manual-assets", json={"name": "A", "type": "process"}, headers=headers).json()
    b = client.post(f"{base}/manual-assets", json={"name": "B", "type": "process"}, headers=headers).json()
    client.post(f"{base}/manual-flows", json={"source_ref": f"asset:{a['id']}", "target_ref": f"asset:{b['id']}"}, headers=headers)

    assert client.delete(f"{base}/manual-assets/{a['id']}", headers=headers).status_code == 204
    assert _completed_run_dfd(client, csrf, application["id"])["edges"] == [] or all(
        not e["is_manual"] for e in _completed_run_dfd(client, csrf, application["id"])["edges"]
    )

    restored = client.post(
        f"{base}/manual-assets", json={"id": a["id"], "name": "A", "type": "process"}, headers=headers
    )
    assert restored.status_code == 200
    assert restored.json()["id"] == a["id"]
    edges = _completed_run_dfd(client, csrf, application["id"])["edges"]
    assert any(e["is_manual"] and e["source"] == a["id"] and e["target"] == b["id"] for e in edges)


def test_client_supplied_ids_are_validated_and_cannot_overwrite_existing_rows(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application = _create_application_with_manifest_source(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    base = f"/api/applications/{application['id']}"
    existing = client.post(f"{base}/manual-assets", json={"name": "A", "type": "process"}, headers=headers).json()

    collision = client.post(f"{base}/manual-assets", json={"id": existing["id"], "name": "X", "type": "process"}, headers=headers)
    bad_shape = client.post(f"{base}/manual-assets", json={"id": "not-a-manual-id", "name": "X", "type": "process"}, headers=headers)
    assert collision.status_code == 409
    assert bad_shape.status_code == 422

    flow = client.post(f"{base}/manual-flows", json={"source_ref": "name:a", "target_ref": "name:b"}, headers=headers).json()
    flow_collision = client.post(
        f"{base}/manual-flows", json={"id": flow["id"], "source_ref": "name:x", "target_ref": "name:y"}, headers=headers
    )
    assert flow_collision.status_code == 409


# -- Threat generation and triage status --------------------------------------


def _run_with_manifest(client: TestClient, csrf: str) -> tuple[dict, dict]:
    application = _create_application_with_manifest_source(client, csrf)
    run = client.post(f"/api/applications/{application['id']}/runs", headers={"X-CSRF-Token": csrf}).json()
    return application, run


def _threats_url(application: dict, run: dict) -> str:
    return f"/api/applications/{application['id']}/runs/{run['id']}/threats"


def test_threats_are_generated_for_dfd_components_with_mitigations(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)

    response = client.get(_threats_url(application, run))

    assert response.status_code == 200
    body = response.json()
    # One k8s Deployment -> a process -> all six STRIDE categories.
    assert {t["category"] for t in body["threats"]} == {
        "Spoofing", "Tampering", "Repudiation", "InformationDisclosure", "DenialOfService", "ElevationOfPrivilege",
    }
    assert all(t["mitigations"] and t["status"] == "open" for t in body["threats"])
    assert body["summary"]["total"] == len(body["threats"])
    assert body["summary"]["by_status"]["open"] == len(body["threats"])


def test_threats_reflect_manual_components_flows_and_boundary_overrides(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    app_url = f"/api/applications/{application['id']}"
    headers = {"X-CSRF-Token": csrf}
    process_name = client.get(f"{app_url}/runs/{run['id']}/dfd").json()["nodes"][0]["name"]

    manual = client.post(
        f"{app_url}/manual-assets",
        json={"name": "Orders DB", "type": "data_store", "trust_boundary": "internal"},
        headers=headers,
    ).json()
    client.post(
        f"{app_url}/manual-flows",
        json={"source_ref": f"name:{process_name}", "target_ref": f"asset:{manual['id']}"},
        headers=headers,
    )
    client.put(
        f"{app_url}/trust-boundaries",
        json={"component_name": process_name, "trust_boundary": "internet-facing"},
        headers=headers,
    )

    threats = client.get(_threats_url(application, run)).json()["threats"]
    rule_ids = {t["rule_id"] for t in threats}

    assert {t["element_name"] for t in threats if t["element_kind"] == "component"} == {process_name, "Orders DB"}
    assert "PROC-E-02" in rule_ids  # override made the process untrusted-facing
    assert {"FLOW-T-02", "FLOW-I-02"} <= rule_ids  # internet-facing -> internal crosses a boundary

    # Asserted-vs-verified provenance ("Core engine robustness" #10), wired
    # through the real API: a manual component/flow and a hand-set trust
    # boundary all say "owner states", not "exposed"/unlabelled, in the
    # threats they land on.
    orders_db_threat = next(t for t in threats if t["element_name"] == "Orders DB")
    assert any("added by hand" in f for f in orders_db_threat["likelihood_factors"])
    flow_threat = next(t for t in threats if t["element_kind"] == "flow")
    assert any("drawn by hand" in f for f in flow_threat["likelihood_factors"])
    process_e02 = next(t for t in threats if t["rule_id"] == "PROC-E-02")
    assert any("owner states: exposed" in f for f in process_e02["likelihood_factors"])


def test_setting_threat_status_persists_and_survives_a_rerun(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run_1 = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    threats = client.get(_threats_url(application, run_1)).json()["threats"]
    target = threats[0]

    updated = client.put(
        f"{_threats_url(application, run_1)}/status",
        json={"threat_key": target["key"], "status": "mitigated", "note": "Fixed in PR 12"},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "mitigated"

    # A re-run regenerates every fact/asset id; the status is keyed by name
    # so it must still attach to the same threat.
    run_2 = client.post(f"/api/applications/{application['id']}/runs", headers=headers).json()
    assert run_2["id"] != run_1["id"]
    body = client.get(_threats_url(application, run_2)).json()
    match = next(t for t in body["threats"] if t["key"] == target["key"])
    assert match["status"] == "mitigated"
    assert match["note"] == "Fixed in PR 12"
    assert body["summary"]["by_status"]["mitigated"] == 1
    assert body["summary"]["by_status"]["open"] == len(threats) - 1

    reopened = client.put(
        f"{_threats_url(application, run_2)}/status",
        json={"threat_key": target["key"], "status": "open"},
        headers=headers,
    )
    assert reopened.json()["status"] == "open"
    body = client.get(_threats_url(application, run_2)).json()
    assert body["summary"]["by_status"]["open"] == len(threats)


def test_dread_score_persists_survives_a_rerun_and_never_affects_risk_ranking(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run_1 = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    threats = client.get(_threats_url(application, run_1)).json()["threats"]
    target = threats[0]
    risk_before = target["risk_score"]

    dread = {"damage": 8, "reproducibility": 6, "exploitability": 7, "affected_users": 9, "discoverability": 5}
    updated = client.put(
        f"{_threats_url(application, run_1)}/status",
        # DREAD alone, status stays "open" -- confirms a note/DREAD-only save
        # persists without forcing a status change (SetThreatStatusRequest's
        # docstring).
        json={"threat_key": target["key"], "status": "open", "dread": dread},
        headers=headers,
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["status"] == "open"
    assert {k: body["dread"][k] for k in dread} == dread
    assert body["dread"]["average"] == pytest.approx(7.0)
    assert body["risk_score"] == risk_before  # DREAD is informational only

    run_2 = client.post(f"/api/applications/{application['id']}/runs", headers=headers).json()
    survived = client.get(_threats_url(application, run_2)).json()
    match = next(t for t in survived["threats"] if t["key"] == target["key"])
    assert {k: match["dread"][k] for k in dread} == dread

    cleared = client.put(
        f"{_threats_url(application, run_2)}/status",
        json={"threat_key": target["key"], "status": "open", "dread": None},
        headers=headers,
    )
    assert cleared.json()["dread"] is None


def test_open_severity_summary_excludes_triaged_threats(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    threats = client.get(_threats_url(application, run)).json()
    high = next(t for t in threats["threats"] if t["severity"] == "high")
    before = threats["summary"]["open_by_severity"]["high"]

    client.put(
        f"{_threats_url(application, run)}/status",
        json={"threat_key": high["key"], "status": "not_applicable", "note": "not reachable here"},
        headers={"X-CSRF-Token": csrf},
    )

    after = client.get(_threats_url(application, run)).json()["summary"]["open_by_severity"]["high"]
    assert after == before - 1


def test_threat_status_rejects_unknown_key_missing_csrf_and_bad_status(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    url = f"{_threats_url(application, run)}/status"
    key = client.get(_threats_url(application, run)).json()["threats"][0]["key"]

    assert client.put(url, json={"threat_key": "NOPE|x", "status": "accepted"},
                      headers={"X-CSRF-Token": csrf}).status_code == 404
    assert client.put(url, json={"threat_key": key, "status": "accepted"}).status_code == 403
    assert client.put(url, json={"threat_key": key, "status": "wontfix"},
                      headers={"X-CSRF-Token": csrf}).status_code == 422


def test_threats_404_for_a_run_of_a_different_application(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    _application, run = _run_with_manifest(client, csrf)
    other = client.post("/api/applications", json={"name": "Other"}, headers={"X-CSRF-Token": csrf}).json()

    assert client.get(f"/api/applications/{other['id']}/runs/{run['id']}/threats").status_code == 404


def test_threats_skip_scanned_files_and_repo_hub_grouping_edges(tmp_path):
    """A GitHub scan yields code_artifact facts (go.sum, Dockerfile) and a hub
    external_entity joined by `discovered_in` edges. None of those are system
    components or data flows, so none may attract threats."""
    from kresheen.models.asset import Asset, AssetFlow, AssetType
    from kresheen.models.facts import FactNode
    from kresheen.models.threat_model_run import ThreatModelRun

    client, csrf = _logged_in_client(tmp_path)
    application = client.post("/api/applications", json={"name": "Repo App"}, headers={"X-CSRF-Token": csrf}).json()
    repo = SQLRepository(f"sqlite:///{tmp_path}/test.db")
    now = datetime.now(UTC)
    repo.save_run(ThreatModelRun(
        id="RUN-x", application_id=application["id"], triggered_by_user_id="USER-test",
        status="completed", started_at=now,
    ))

    def fact(node_id, node_type, name, source_ref):
        return FactNode(id=node_id, run_id="RUN-x", application_id=application["id"], node_type=node_type,
                        name=name, source_ref=source_ref, discovered_at=now)

    repo.save_fact_nodes([
        fact("N-hub", "external_entity", "org/repo", "github_repository"),
        fact("N-file", "code_artifact", "go.sum", "github_repository"),
        fact("N-svc", "process", "billing-svc", "manifest_upload:k8s"),
    ])
    repo.replace_assets_for_run("RUN-x", [
        Asset(id="N-hub", name="org/repo", type=AssetType.EXTERNAL_ENTITY, source="threat_model_run", run_id="RUN-x", created_at=now),
        Asset(id="N-file", name="go.sum", type=AssetType.PROCESS, source="threat_model_run", run_id="RUN-x", created_at=now),
        Asset(id="N-svc", name="billing-svc", type=AssetType.PROCESS, source="threat_model_run", run_id="RUN-x", created_at=now),
    ])
    repo.replace_asset_flows_for_run("RUN-x", [
        AssetFlow(id="E-1", source_asset_id="N-hub", target_asset_id="N-file", label="discovered_in", run_id="RUN-x"),
        AssetFlow(id="E-2", source_asset_id="N-hub", target_asset_id="N-svc", label="discovered_in", run_id="RUN-x"),
    ])

    threats = client.get(f"/api/applications/{application['id']}/runs/RUN-x/threats").json()["threats"]

    assert {t["element_name"] for t in threats} == {"billing-svc"}


# -- Custom rules and manual threats ------------------------------------------------


def _component_ids(client: TestClient, application: dict, run: dict) -> dict[str, str]:
    dfd = client.get(f"/api/applications/{application['id']}/runs/{run['id']}/dfd").json()
    return {n["name"]: n["id"] for n in dfd["nodes"]}


def test_custom_kb_entry_with_applies_to_generates_threats_and_reference_only_does_not(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    process_name = next(iter(_component_ids(client, application, run)))

    applied = client.post("/api/threat-kb", headers=headers, json={
        "name": "Badge cloning at {name}", "description": "d", "applies_to": "process",
        "severity": "critical", "stride": "Spoofing", "mitigations": ["Rotate badges."],
    }).json()
    client.post("/api/threat-kb", headers=headers, json={"name": "Just a note", "description": "d"})

    threats = client.get(_threats_url(application, run)).json()["threats"]
    custom = [t for t in threats if t["origin"] == "custom_rule"]

    assert [t["title"] for t in custom] == [f"Badge cloning at {process_name}"]
    assert custom[0]["rule_id"] == applied["id"]
    assert custom[0]["severity"] == "critical"
    assert custom[0]["mitigations"] == ["Rotate badges."]
    # Critical sorts into the top risk tier. Within a tier an observed config threat
    # (SC-*) now ranks ahead of a specific one, so this is
    # no longer necessarily first.
    assert custom[0]["risk_score"] == max(t["risk_score"] for t in threats)

    # Status works on a custom-rule threat like any other.
    put = client.put(f"{_threats_url(application, run)}/status", headers=headers,
                     json={"threat_key": custom[0]["key"], "status": "accepted", "note": "known"})
    assert put.status_code == 200

    # Deleting the entry removes its threats.
    client.delete(f"/api/threat-kb/{applied['id']}", headers=headers)
    after = client.get(_threats_url(application, run)).json()["threats"]
    assert not [t for t in after if t["origin"] == "custom_rule"]


def test_kb_entry_validation_rejects_bad_applies_to_and_oversized_fields(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    headers = {"X-CSRF-Token": csrf}
    base = {"name": "n", "description": "d"}

    assert client.post("/api/threat-kb", headers=headers, json={**base, "applies_to": "server"}).status_code == 422
    assert client.post("/api/threat-kb", headers=headers, json={**base, "severity": "urgent"}).status_code == 422
    assert client.post("/api/threat-kb", headers=headers, json={**base, "mitigations": ["x"] * 21}).status_code == 422
    assert client.post("/api/threat-kb", headers=headers, json={**base, "mitigations": ["x" * 501]}).status_code == 422
    assert client.post("/api/threat-kb", headers=headers, json={"name": "", "description": "d"}).status_code == 422


def test_manual_threat_attaches_to_component_and_flow_survives_rerun_and_deletes_cleanly(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run_1 = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    app_url = f"/api/applications/{application['id']}"
    process_name, process_id = next(iter(_component_ids(client, application, run_1).items()))
    db = client.post(f"{app_url}/manual-assets", headers=headers,
                     json={"name": "Orders DB", "type": "data_store", "trust_boundary": "internal"}).json()
    client.post(f"{app_url}/manual-flows", headers=headers,
                json={"source_ref": f"name:{process_name}", "target_ref": f"asset:{db['id']}"})
    flow_id = client.get(f"{app_url}/runs/{run_1['id']}/dfd").json()["edges"][0]["id"]

    on_component = client.post(f"{_threats_url(application, run_1)[:-len('/threats')]}/manual-threats", headers=headers, json={
        "element_kind": "component", "element_id": process_id, "title": "Insider exports data",
        "severity": "high", "category": "InformationDisclosure", "mitigations": ["DLP on egress."],
    })
    assert on_component.status_code == 200
    created = on_component.json()
    assert created["origin"] == "manual" and created["element_name"] == process_name
    on_flow = client.post(f"{_threats_url(application, run_1)[:-len('/threats')]}/manual-threats", headers=headers, json={
        "element_kind": "flow", "element_id": flow_id, "title": "Replay of order messages",
    })
    assert on_flow.json()["element_type"] == "data_flow"
    assert on_flow.json()["category"] is None

    client.put(f"{_threats_url(application, run_1)}/status", headers=headers,
               json={"threat_key": created["key"], "status": "mitigated", "note": "DLP deployed"})

    run_2 = client.post(f"{app_url}/runs", headers=headers).json()
    body = client.get(_threats_url(application, run_2)).json()
    again = next(t for t in body["threats"] if t["manual_threat_id"] == created["manual_threat_id"])
    assert again["status"] == "mitigated" and again["note"] == "DLP deployed"

    assert client.delete(f"{app_url}/manual-threats/{created['manual_threat_id']}", headers=headers).status_code == 204
    after = client.get(_threats_url(application, run_2)).json()
    assert not [t for t in after["threats"] if t["manual_threat_id"] == created["manual_threat_id"]]
    assert after["summary"]["by_status"]["mitigated"] == 0  # its status row went with it


def test_manual_threat_rejects_unknown_element_kb_entry_missing_csrf_and_foreign_delete(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    headers = {"X-CSRF-Token": csrf}
    url = f"/api/applications/{application['id']}/runs/{run['id']}/manual-threats"
    component_id = next(iter(_component_ids(client, application, run).values()))
    good = {"element_kind": "component", "element_id": component_id, "title": "T"}

    assert client.post(url, headers=headers, json={**good, "element_id": "nope"}).status_code == 404
    assert client.post(url, headers=headers, json={**good, "element_kind": "flow"}).status_code == 404
    assert client.post(url, headers=headers, json={**good, "kb_entry_id": "KB-nope"}).status_code == 404
    assert client.post(url, json=good).status_code == 403
    assert client.post(url, headers=headers, json={**good, "title": ""}).status_code == 422
    assert client.post(url, headers=headers, json={**good, "severity": "urgent"}).status_code == 422

    created = client.post(url, headers=headers, json=good).json()
    other = client.post("/api/applications", json={"name": "Other"}, headers=headers).json()
    assert client.delete(f"/api/applications/{other['id']}/manual-threats/{created['manual_threat_id']}",
                         headers=headers).status_code == 404


def test_threats_carry_likelihood_evidence_and_a_risk_summary(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)

    body = client.get(_threats_url(application, run)).json()
    threats = body["threats"]

    assert all({"likelihood", "likelihood_factors", "evidence", "evidence_total", "risk", "risk_score"} <= t.keys() for t in threats)
    assert all(t["risk"] in ("critical", "high", "medium", "low") for t in threats)
    scores = [t["risk_score"] for t in threats]
    assert scores == sorted(scores, reverse=True)  # ranked by risk
    assert sum(body["summary"]["open_by_risk"].values()) == body["summary"]["by_status"]["open"]
    # The manifest's unpinned/hostNetwork findings are evidence on the matching STRIDE threat of that component.
    assert any(t["evidence_total"] > 0 and t["likelihood"] != "possible" for t in threats)
