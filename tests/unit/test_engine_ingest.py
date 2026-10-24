import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest
import requests
import responses

from kresheen.engine.ingest.architecture_diagram_ingestor import ArchitectureDiagramIngestor
from kresheen.engine.ingest.documentation_ingestor import DocumentationIngestor
from kresheen.engine.ingest.github_repository_ingestor import GithubRepositoryIngestor
from kresheen.engine.ingest.manifest_ingestor import ManifestUploadIngestor
from tests.conftest import build_tarball_bytes

_GRYPE_FIXTURE = Path(__file__).parent.parent / "fixtures" / "grype" / "sample_cyclonedx.json"
_GRYPE_NATIVE_FIXTURE = Path(__file__).parent.parent / "fixtures" / "grype" / "sample_matches.json"


def _grype_subprocess_side_effect(cyclonedx_doc: dict, native_doc: dict | None = None):
    """`_run_grype_scan` now asks Grype for two simultaneous outputs
    (`-o cyclonedx-json=<path> -o json=<path>`) instead of one to stdout, so
    mocking it means writing the requested fixture content to whichever
    paths the real command line asks for, not returning `stdout=`."""

    def _run(args, **kwargs):
        for arg in args:
            if isinstance(arg, str) and arg.startswith("cyclonedx-json="):
                Path(arg.split("=", 1)[1]).write_text(json.dumps(cyclonedx_doc))
            elif isinstance(arg, str) and arg.startswith("json="):
                Path(arg.split("=", 1)[1]).write_text(json.dumps(native_doc or {"matches": []}))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=b"", stderr=b"")

    return _run


def _github_reachable() -> bool:
    try:
        return requests.head("https://api.github.com", timeout=5).status_code < 500
    except requests.RequestException:
        return False


def test_manifest_ingestor_terraform_plan_flags_a_data_store_resource():
    plan = {
        "resource_changes": [
            {
                "address": "aws_db_instance.main",
                "type": "aws_db_instance",
                "name": "main",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["create"], "after": {"publicly_accessible": True, "engine": "postgres"}},
            },
            {
                "address": "aws_instance.web",
                "type": "aws_instance",
                "name": "web",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["create"], "after": {"ami": "ami-123"}},
            },
        ]
    }
    ingestor = ManifestUploadIngestor()

    nodes, edges = ingestor.run(
        run_id="RUN-1", application_id="APP-1", connection_details={"content": json.dumps(plan)}
    )

    assert edges == []
    by_address = {n.name: n for n in nodes}
    assert by_address["aws_db_instance.main"].node_type == "data_store"
    assert by_address["aws_instance.web"].node_type == "process"
    assert by_address["aws_db_instance.main"].attributes["publicly_accessible"] is True


def test_manifest_ingestor_terraform_plan_skips_deleted_resources():
    plan = {
        "resource_changes": [
            {"address": "aws_instance.old", "type": "aws_instance", "name": "old", "change": {"actions": ["delete"]}}
        ]
    }
    ingestor = ManifestUploadIngestor()

    nodes, _ = ingestor.run(run_id="RUN-1", application_id="APP-1", connection_details={"content": json.dumps(plan)})

    assert nodes == []


K8S_MANIFEST = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
  labels:
    app: web
spec:
  hostNetwork: true
  template:
    spec:
      containers:
        - name: web
          image: myregistry/web:latest
---
apiVersion: v1
kind: Service
metadata:
  name: web-svc
  namespace: prod
spec:
  selector:
    app: web
---
apiVersion: v1
kind: Secret
metadata:
  name: web-secret
  namespace: prod
"""


def test_manifest_ingestor_k8s_manifest_classifies_kinds_and_links_service_to_selector_match():
    ingestor = ManifestUploadIngestor()

    nodes, edges = ingestor.run(run_id="RUN-1", application_id="APP-1", connection_details={"content": K8S_MANIFEST})

    by_name = {n.name: n for n in nodes}
    assert by_name["Deployment/web"].node_type == "process"
    assert by_name["Deployment/web"].attributes["host_network"] is True
    assert by_name["Deployment/web"].attributes["container_images"] == ["myregistry/web:latest"]
    assert by_name["Secret/web-secret"].node_type == "data_store"

    assert len(edges) == 1
    assert edges[0].source_node_id == by_name["Service/web-svc"].id
    assert edges[0].target_node_id == by_name["Deployment/web"].id


@responses.activate
def test_github_repository_ingestor_flags_notable_files_recursively():
    """The core regression test for the bug that started this rework: a
    top-level-only scan could never see `frontend/package.json` -- pulling
    the whole tarball and walking it recursively finds it, with its real
    nested path preserved."""
    tarball = build_tarball_bytes(
        {
            "Dockerfile": "FROM node:20",
            "main.tf": 'resource "aws_instance" "x" {}',
            "k8s/deployment.yaml": "kind: Deployment",
            "README.md": "hello",
            "frontend/package.json": "{}",
        }
    )
    responses.add(
        responses.GET, "https://api.github.com/repos/acme/widget/tarball", body=tarball, status=200
    )
    ingestor = GithubRepositoryIngestor()

    with patch(
        "kresheen.engine.ingest.github_repository_ingestor._run_grype_scan", return_value=None
    ):
        nodes, edges = ingestor.run(
            run_id="RUN-1", application_id="APP-1", connection_details={"repo_url": "https://github.com/acme/widget"}
        )

    code_artifact_nodes = [n for n in nodes if n.node_type == "code_artifact"]
    by_file = {n.attributes["file"]: n for n in code_artifact_nodes}
    assert by_file["Dockerfile"].attributes["kind"] == "container_build"
    assert by_file["main.tf"].attributes["kind"] == "terraform"
    assert by_file["k8s"].attributes["kind"] == "kubernetes_manifests"
    assert by_file["frontend/package.json"].attributes["kind"] == "dependency_manifest"
    assert "README.md" not in by_file

    # The rest of `nodes` is the one hub-and-spoke root node (see the dedicated hub-node test below for edge
    # assertions) plus, because the scanner is stubbed out here (returns None), a note that the vulnerability
    # scan did not run.
    other_nodes = [n for n in nodes if n.node_type not in ("code_artifact", "scan_note")]
    assert len(other_nodes) == 1
    assert other_nodes[0].node_type == "external_entity"
    assert [n.node_type for n in nodes if n.node_type == "scan_note"] == ["scan_note"]
    assert len(edges) == len(code_artifact_nodes)


@responses.activate
def test_github_repository_ingestor_sends_bearer_token_when_given():
    tarball = build_tarball_bytes({})
    responses.add(
        responses.GET, "https://api.github.com/repos/acme/widget/tarball", body=tarball, status=200
    )
    ingestor = GithubRepositoryIngestor()

    with patch(
        "kresheen.engine.ingest.github_repository_ingestor._run_grype_scan", return_value=None
    ):
        ingestor.run(
            run_id="RUN-1",
            application_id="APP-1",
            connection_details={"repo_url": "acme/widget", "github_token": "gh-token"},
        )

    assert responses.calls[0].request.headers["Authorization"] == "Bearer gh-token"


@responses.activate
def test_github_repository_ingestor_uses_ref_when_given():
    tarball = build_tarball_bytes({})
    responses.add(
        responses.GET, "https://api.github.com/repos/acme/widget/tarball/v2.0.0", body=tarball, status=200
    )
    ingestor = GithubRepositoryIngestor()

    with patch(
        "kresheen.engine.ingest.github_repository_ingestor._run_grype_scan", return_value=None
    ):
        ingestor.run(
            run_id="RUN-1",
            application_id="APP-1",
            connection_details={"repo_url": "acme/widget", "ref": "v2.0.0"},
        )

    assert responses.calls[0].request.url == "https://api.github.com/repos/acme/widget/tarball/v2.0.0"


@responses.activate
def test_github_repository_ingestor_runs_grype_against_the_extracted_tree():
    tarball = build_tarball_bytes({"package.json": "{}", "package-lock.json": "{}", "README.md": "hello"})
    responses.add(
        responses.GET, "https://api.github.com/repos/acme/widget/tarball", body=tarball, status=200
    )
    fixture_document = json.loads(_GRYPE_FIXTURE.read_text())
    native_document = json.loads(_GRYPE_NATIVE_FIXTURE.read_text())

    with patch("kresheen.engine.ingest.github_repository_ingestor.subprocess.run") as mock_run:
        mock_run.side_effect = _grype_subprocess_side_effect(fixture_document, native_document)
        ingestor = GithubRepositoryIngestor()
        nodes, edges = ingestor.run(
            run_id="RUN-1", application_id="APP-1", connection_details={"repo_url": "acme/widget"}
        )

    # grype is now pointed at the real extracted repo directory, not a
    # synthetic scratch dir of hand-picked file copies.
    grype_cmd = mock_run.call_args.args[0]
    assert grype_cmd[0] == "grype"
    assert grype_cmd[1].startswith("dir:")

    vuln_nodes = [n for n in nodes if n.node_type == "vulnerability"]
    sbom_nodes = [n for n in nodes if n.node_type == "sbom_document"]
    assert len(sbom_nodes) == 1
    assert sbom_nodes[0].source_ref == "grype"
    # The fixture has 3 raw components (fixture-app, lodash, and one
    # type="file" pseudo-component with no purl) -- only the two real npm
    # ones survive the application-dependency filter.
    assert sbom_nodes[0].attributes["component_count"] == 2
    assert sbom_nodes[0].attributes["vulnerability_count"] == len(fixture_document["vulnerabilities"])
    assert sbom_nodes[0].attributes["document"] == fixture_document  # raw document kept verbatim for provenance
    assert sbom_nodes[0].attributes["no_lockfile_detected"] is False  # package-lock.json was present

    assert len(vuln_nodes) == 1
    vuln = vuln_nodes[0]
    assert vuln.source_ref == "grype"
    assert vuln.attributes["cve_id"] == "GHSA-35jh-r3h4-6jhm"
    assert vuln.attributes["package"] == "lodash"
    assert vuln.attributes["version"] == "4.17.15"
    assert vuln.attributes["severity"] == "high"
    assert vuln.attributes["purl"] == "pkg:npm/lodash@4.17.15"
    # From the native-json fixture, joined by (vuln id, package, version).
    assert vuln.attributes["fixed_versions"] == ["4.17.21"]
    assert vuln.attributes["fix_state"] == "fixed"
    assert vuln.attributes["epss_score"] == 0.21333
    assert vuln.attributes["known_exploited"] is False

    # Hub-and-spoke: every code_artifact/vulnerability fact connects to one
    # root node for the repo -- not the sbom_document summary node itself.
    hub_nodes = [n for n in nodes if n.node_type == "external_entity"]
    assert len(hub_nodes) == 1
    hub = hub_nodes[0]
    connected_target_ids = {e.target_node_id for e in edges if e.source_node_id == hub.id}
    expected_target_ids = {n.id for n in nodes if n.node_type in ("code_artifact", "vulnerability")}
    assert connected_target_ids == expected_target_ids
    assert all(e.edge_type == "discovered_in" for e in edges)
    assert sbom_nodes[0].id not in connected_target_ids


@responses.activate
def test_github_repository_ingestor_detects_missing_lockfile_end_to_end():
    """Full ingestor run reproducing the exact real-world juice-shop
    scenario: a manifest exists but no lockfile, and Grype's dir scan only
    turns up GitHub Actions usage (no real npm components)."""
    tarball = build_tarball_bytes({"package.json": "{}", ".github/workflows/ci.yml": "on: push"})
    responses.add(
        responses.GET, "https://api.github.com/repos/juice-shop/juice-shop/tarball", body=tarball, status=200
    )
    grype_document = {
        "components": [
            {"bom-ref": "action-ref", "type": "library", "name": "actions/checkout", "purl": "pkg:github/actions/checkout@v4"},
        ],
        "vulnerabilities": [],
    }

    with patch("kresheen.engine.ingest.github_repository_ingestor.subprocess.run") as mock_run:
        mock_run.side_effect = _grype_subprocess_side_effect(grype_document)
        ingestor = GithubRepositoryIngestor()
        nodes, _edges = ingestor.run(
            run_id="RUN-1", application_id="APP-1", connection_details={"repo_url": "juice-shop/juice-shop"}
        )

    sbom_node = next(n for n in nodes if n.node_type == "sbom_document")
    assert sbom_node.attributes["no_lockfile_detected"] is True
    assert sbom_node.attributes["manifest_files_found"] == ["package.json"]
    assert sbom_node.attributes["component_count"] == 0
    assert not any(n.node_type == "vulnerability" for n in nodes)


@responses.activate
def test_github_repository_ingestor_degrades_gracefully_when_grype_is_not_installed():
    tarball = build_tarball_bytes({"package.json": "{}", "package-lock.json": "{}"})
    responses.add(
        responses.GET, "https://api.github.com/repos/acme/widget/tarball", body=tarball, status=200
    )

    with patch(
        "kresheen.engine.ingest.github_repository_ingestor.subprocess.run",
        side_effect=FileNotFoundError("grype not found"),
    ):
        ingestor = GithubRepositoryIngestor()
        nodes, edges = ingestor.run(
            run_id="RUN-1", application_id="APP-1", connection_details={"repo_url": "acme/widget"}
        )

    # Ingestion doesn't raise, and the filename-only facts for the two
    # dependency files still show up -- only the SBOM/vulnerability facts
    # are missing. The hub-and-spoke root node/edges still get built from
    # whatever code_artifact facts exist, independent of Grype succeeding.
    code_artifact_nodes = [n for n in nodes if n.node_type == "code_artifact"]
    assert {n.attributes["file"] for n in code_artifact_nodes} == {"package.json", "package-lock.json"}
    assert not any(n.node_type in ("vulnerability", "sbom_document") for n in nodes)
    assert len(edges) == len(code_artifact_nodes)


@pytest.mark.skipif(not _github_reachable(), reason="no network access to github.com in this environment")
def test_github_repository_ingestor_against_a_real_small_public_repo():
    """Real end-to-end pull of a tiny, extremely stable public repo
    (GitHub's own long-standing Hello-World test repo) against the actual
    tarball endpoint -- proves the download + safe extraction + recursive
    notable-file walk work against a real GitHub response shape, not just
    a hand-built fixture. Skips cleanly with no network access (mirrors
    this session's established "skip if the real dependency isn't
    available, run for real when it is" convention). Grype is mocked out
    here deliberately -- this test is about the download/extraction path,
    the real-grype-binary path already has its own dedicated test below."""
    ingestor = GithubRepositoryIngestor()

    with patch(
        "kresheen.engine.ingest.github_repository_ingestor._run_grype_scan", return_value=None
    ):
        nodes, edges = ingestor.run(
            run_id="RUN-1",
            application_id="APP-1",
            connection_details={"repo_url": "https://github.com/octocat/Hello-World"},
        )

    assert edges == []
    # Hello-World's only real file is a README -- not a notable file, so an
    # empty (but successfully produced) fact list is the correct, honest
    # result; what this test actually proves is that the real
    # download+extraction path completes without error.
    assert isinstance(nodes, list)


def test_extract_tarball_safely_rejects_path_traversal_member(tmp_path):
    from kresheen.engine.ingest.github_repository_ingestor import _extract_tarball_safely

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        data = b"pwned"
        info = tarfile.TarInfo(name="../../../tmp/kresheen-test-pwned")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    tarball_path = tmp_path / "evil.tar.gz"
    tarball_path.write_bytes(buffer.getvalue())
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    with pytest.raises(ValueError, match="path-traversal"):
        _extract_tarball_safely(str(tarball_path), str(extract_dir))

    assert not Path("/tmp/kresheen-test-pwned").exists()
    assert list(extract_dir.iterdir()) == []


def test_extract_tarball_safely_rejects_absolute_path_member(tmp_path):
    from kresheen.engine.ingest.github_repository_ingestor import _extract_tarball_safely

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        data = b"pwned"
        info = tarfile.TarInfo(name="/tmp/kresheen-test-pwned-abs")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    tarball_path = tmp_path / "evil.tar.gz"
    tarball_path.write_bytes(buffer.getvalue())
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    with pytest.raises(ValueError, match="absolute path"):
        _extract_tarball_safely(str(tarball_path), str(extract_dir))

    assert not Path("/tmp/kresheen-test-pwned-abs").exists()


def test_extract_tarball_safely_rejects_extracted_size_over_cap(tmp_path, monkeypatch):
    from kresheen.engine.ingest import github_repository_ingestor as module

    monkeypatch.setattr(module, "_MAX_EXTRACTED_BYTES", 10)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        data = b"x" * 1000
        info = tarfile.TarInfo(name="big.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    tarball_path = tmp_path / "big.tar.gz"
    tarball_path.write_bytes(buffer.getvalue())
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    with pytest.raises(ValueError, match="decompression bomb"):
        module._extract_tarball_safely(str(tarball_path), str(extract_dir))

    assert list(extract_dir.iterdir()) == []


def _link_tarball(tmp_path, *members: tarfile.TarInfo) -> Path:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        data = b"inside"
        info = tarfile.TarInfo(name="a/b/file.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        for member in members:
            tar.addfile(member)
    tarball_path = tmp_path / "links.tar.gz"
    tarball_path.write_bytes(buffer.getvalue())
    return tarball_path


def test_extract_tarball_safely_rejects_hard_link_escaping_root(tmp_path):
    from kresheen.engine.ingest.github_repository_ingestor import _extract_tarball_safely

    # A hard link's target is relative to the archive root, not to the member's directory: from `a/b/` this name
    # would stay inside, from the root it climbs two levels out.
    link = tarfile.TarInfo(name="a/b/link")
    link.type = tarfile.LNKTYPE
    link.linkname = "../../outside"
    tarball_path = _link_tarball(tmp_path, link)
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    with pytest.raises(ValueError, match="escaping the archive root"):
        _extract_tarball_safely(str(tarball_path), str(extract_dir))

    assert list(extract_dir.iterdir()) == []


def test_extract_tarball_safely_rejects_symlink_escaping_root(tmp_path):
    from kresheen.engine.ingest.github_repository_ingestor import _extract_tarball_safely

    link = tarfile.TarInfo(name="a/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "../../outside"
    tarball_path = _link_tarball(tmp_path, link)
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    with pytest.raises(ValueError, match="escaping the archive root"):
        _extract_tarball_safely(str(tarball_path), str(extract_dir))


def test_extract_tarball_safely_keeps_hard_link_inside_root(tmp_path):
    from kresheen.engine.ingest.github_repository_ingestor import _extract_tarball_safely

    link = tarfile.TarInfo(name="c/copy.txt")
    link.type = tarfile.LNKTYPE
    link.linkname = "a/b/file.txt"
    tarball_path = _link_tarball(tmp_path, link)
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    _extract_tarball_safely(str(tarball_path), str(extract_dir))

    assert (extract_dir / "c" / "copy.txt").read_bytes() == b"inside"


def test_extract_tarball_safely_rejects_hard_link_to_missing_member(tmp_path):
    from kresheen.engine.ingest.github_repository_ingestor import _extract_tarball_safely

    # Found by tests/fuzz: tarfile raised KeyError for a hard link naming no earlier member.
    link = tarfile.TarInfo(name="c/copy.txt")
    link.type = tarfile.LNKTYPE
    link.linkname = "a/b/missing.txt"
    tarball_path = _link_tarball(tmp_path, link)
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    with pytest.raises(ValueError, match="hard link to a missing file"):
        _extract_tarball_safely(str(tarball_path), str(extract_dir))


def test_extract_tarball_safely_refuses_without_data_filter(tmp_path, monkeypatch):
    from kresheen.engine.ingest.github_repository_ingestor import _extract_tarball_safely

    tarball_path = _link_tarball(tmp_path)
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()
    monkeypatch.delattr(tarfile, "data_filter")

    with pytest.raises(ValueError, match="data' extraction filter"):
        _extract_tarball_safely(str(tarball_path), str(extract_dir))

    assert list(extract_dir.iterdir()) == []


def test_facts_from_cyclonedx_resolves_component_by_bom_ref_from_a_real_fixture():
    from datetime import UTC, datetime

    from kresheen.engine.ingest.github_repository_ingestor import _facts_from_cyclonedx

    document = json.loads(_GRYPE_FIXTURE.read_text())
    nodes = _facts_from_cyclonedx(
        document, run_id="RUN-1", application_id="APP-1", repo="acme/widget", now=datetime.now(UTC)
    )

    vuln_nodes = [n for n in nodes if n.node_type == "vulnerability"]
    assert len(vuln_nodes) == len(document["vulnerabilities"])
    assert vuln_nodes[0].attributes["package"] == "lodash"
    assert vuln_nodes[0].attributes["version"] == "4.17.15"
    assert vuln_nodes[0].name == "GHSA-35jh-r3h4-6jhm in lodash@4.17.15"

    sbom_nodes = [n for n in nodes if n.node_type == "sbom_document"]
    assert len(sbom_nodes) == 1
    assert sbom_nodes[0].name == "acme/widget: SBOM"


def test_facts_from_cyclonedx_blank_fix_epss_kev_without_native_matches():
    """A caller with only a CycloneDX document (no native json scan) gets
    blank fix/EPSS/KEV attributes, not a raise -- `native_matches` is
    optional precisely so pre-existing callers (and this fixture) still work."""
    from datetime import UTC, datetime

    from kresheen.engine.ingest.github_repository_ingestor import _facts_from_cyclonedx

    document = json.loads(_GRYPE_FIXTURE.read_text())
    nodes = _facts_from_cyclonedx(
        document, run_id="RUN-1", application_id="APP-1", repo="acme/widget", now=datetime.now(UTC)
    )

    vuln = next(n for n in nodes if n.node_type == "vulnerability")
    assert vuln.attributes["fixed_versions"] == []
    assert vuln.attributes["fix_state"] is None
    assert vuln.attributes["epss_score"] is None
    assert vuln.attributes["known_exploited"] is False


def test_facts_from_cyclonedx_joins_native_matches_by_vuln_id_package_version():
    from datetime import UTC, datetime

    from kresheen.engine.ingest.github_repository_ingestor import _facts_from_cyclonedx

    document = json.loads(_GRYPE_FIXTURE.read_text())
    native_matches = json.loads(_GRYPE_NATIVE_FIXTURE.read_text())
    nodes = _facts_from_cyclonedx(
        document,
        run_id="RUN-1",
        application_id="APP-1",
        repo="acme/widget",
        now=datetime.now(UTC),
        native_matches=native_matches,
    )

    vuln = next(n for n in nodes if n.node_type == "vulnerability")
    assert vuln.attributes["fixed_versions"] == ["4.17.21"]
    assert vuln.attributes["fix_state"] == "fixed"
    assert vuln.attributes["epss_score"] == 0.21333
    assert vuln.attributes["epss_percentile"] == 0.9749
    assert vuln.attributes["known_exploited"] is False


def test_facts_from_cyclonedx_known_exploited_true_when_native_match_lists_it():
    from datetime import UTC, datetime

    from kresheen.engine.ingest.github_repository_ingestor import _facts_from_cyclonedx

    document = {
        "components": [
            {"bom-ref": "npm-ref", "type": "library", "name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
        ],
        "vulnerabilities": [
            {"id": "CVE-2021-44228", "ratings": [{"severity": "critical"}], "affects": [{"ref": "npm-ref"}]},
        ],
    }
    native_matches = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2021-44228",
                    "fix": {"versions": ["2.15.0"], "state": "fixed"},
                    "epss": [{"epss": 0.99999}],
                    "knownExploited": [{"cve": "CVE-2021-44228", "vendorProject": "Apache"}],
                },
                "artifact": {"name": "log4j-core", "version": "2.14.1"},
            }
        ]
    }

    nodes = _facts_from_cyclonedx(
        document,
        run_id="RUN-1",
        application_id="APP-1",
        repo="acme/widget",
        now=datetime.now(UTC),
        native_matches=native_matches,
    )

    vuln = next(n for n in nodes if n.node_type == "vulnerability")
    assert vuln.attributes["known_exploited"] is True
    assert vuln.attributes["epss_score"] == 0.99999


def test_facts_from_cyclonedx_excludes_github_actions_and_file_pseudo_components():
    """Regression test for the exact defect a live juice-shop scan
    surfaced by a live scan: Grype's `dir:` scan also catalogs GitHub Actions
    usage (`purl` starting with `pkg:github...`) and a `type: "file"`
    pseudo-component for the scanned directory itself -- neither is a real
    application dependency. A synthetic document mixing one real npm
    component (with a real vulnerability) alongside a GitHub Actions
    component (also given a bogus "vulnerability" to prove it's excluded
    too) and a file-type pseudo-component confirms only the real one
    survives."""
    from datetime import UTC, datetime

    from kresheen.engine.ingest.github_repository_ingestor import _facts_from_cyclonedx

    document = {
        "components": [
            {"bom-ref": "npm-ref", "type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
            {"bom-ref": "action-ref", "type": "library", "name": "actions/checkout", "version": "v4", "purl": "pkg:github/actions/checkout@v4"},
            {"bom-ref": "file-ref", "type": "file", "name": "/tmp/some-scan-dir"},
        ],
        "vulnerabilities": [
            {"id": "GHSA-real", "ratings": [{"severity": "high"}], "affects": [{"ref": "npm-ref"}]},
            {"id": "GHSA-bogus", "ratings": [{"severity": "critical"}], "affects": [{"ref": "action-ref"}]},
        ],
    }

    nodes = _facts_from_cyclonedx(
        document, run_id="RUN-1", application_id="APP-1", repo="acme/widget", now=datetime.now(UTC)
    )

    vuln_nodes = [n for n in nodes if n.node_type == "vulnerability"]
    assert len(vuln_nodes) == 1
    assert vuln_nodes[0].attributes["cve_id"] == "GHSA-real"
    assert vuln_nodes[0].attributes["package"] == "lodash"

    sbom_node = next(n for n in nodes if n.node_type == "sbom_document")
    assert sbom_node.attributes["component_count"] == 1
    assert sbom_node.attributes["vulnerability_count"] == 1
    assert [c["name"] for c in sbom_node.attributes["components"]] == ["lodash"]
    assert sbom_node.attributes["document"] == document  # raw document untouched, for provenance


def test_facts_from_cyclonedx_flags_no_lockfile_detected():
    from datetime import UTC, datetime

    from kresheen.engine.ingest.github_repository_ingestor import _facts_from_cyclonedx

    # Shape of what a real juice-shop-style scan returns: a manifest exists
    # but no lockfile, so Grype only found GitHub Actions usage -- zero
    # real application dependencies.
    document = {
        "components": [
            {"bom-ref": "action-ref", "type": "library", "name": "actions/checkout", "purl": "pkg:github/actions/checkout@v4"},
        ],
        "vulnerabilities": [],
    }

    nodes = _facts_from_cyclonedx(
        document,
        run_id="RUN-1",
        application_id="APP-1",
        repo="juice-shop/juice-shop",
        now=datetime.now(UTC),
        no_lockfile_detected=True,
        manifest_files_found=["package.json", "frontend/package.json"],
    )

    sbom_node = next(n for n in nodes if n.node_type == "sbom_document")
    assert sbom_node.attributes["component_count"] == 0
    assert sbom_node.attributes["no_lockfile_detected"] is True
    assert sbom_node.attributes["manifest_files_found"] == ["package.json", "frontend/package.json"]


@pytest.mark.skipif(shutil.which("grype") is None, reason="grype is not installed")
def test_run_grype_scan_against_a_real_grype_binary(tmp_path):
    """Unlike every other test in this file, this one does NOT mock
    subprocess -- it shells out to a real `grype` binary against a real,
    known-vulnerable package.json+package-lock.json pair on disk, the same
    live-verified combination (lodash 4.17.15) used to design this
    feature. Skips cleanly in any environment without grype installed
    (mirrors this codebase's existing Docker-availability skip pattern in
    tests/unit/test_sql_repo_postgres.py); runs for real wherever it is."""
    from kresheen.engine.ingest.github_repository_ingestor import _run_grype_scan

    package_json = json.dumps({"name": "probe", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}})
    package_lock = json.dumps(
        {
            "name": "probe",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "packages": {"": {"name": "probe", "version": "1.0.0"}, "node_modules/lodash": {"version": "4.17.15"}},
            "dependencies": {"lodash": {"version": "4.17.15"}},
        }
    )
    (tmp_path / "package.json").write_text(package_json)
    (tmp_path / "package-lock.json").write_text(package_lock)

    result = _run_grype_scan(tmp_path)

    assert result is not None
    document, native_matches = result
    assert document["bomFormat"] == "CycloneDX"
    component_names = {c["name"] for c in document["components"]}
    assert "lodash" in component_names

    # The native json output is what carries fix/EPSS/KEV data that
    # cyclonedx-json does not -- confirmed live against a real grype binary,
    # not just a hand-built fixture.
    lodash_matches = [m for m in native_matches["matches"] if m["artifact"]["name"] == "lodash"]
    assert lodash_matches
    fix_versions = {v for m in lodash_matches for v in (m["vulnerability"].get("fix") or {}).get("versions", [])}
    assert "4.17.21" in fix_versions
    assert any(m["vulnerability"].get("epss") for m in lodash_matches)
    # Whether real CVEs are found depends on the local grype vulnerability
    # DB's freshness (an operational concern that
    # this test can't control) -- assert the scan itself succeeded
    # and produced a well-formed document, not a specific match count.
    assert isinstance(document["vulnerabilities"], list)


def test_architecture_diagram_ingestor_falls_back_to_reference_node_for_unrecognized_content():
    ingestor = ArchitectureDiagramIngestor()

    nodes, edges = ingestor.run(
        run_id="RUN-1",
        application_id="APP-1",
        connection_details={"filename": "diagram.png", "content": "not-json-or-a-diagram"},
    )

    assert edges == []
    assert len(nodes) == 1
    assert nodes[0].node_type == "reference_document"
    assert nodes[0].attributes["filename"] == "diagram.png"


def test_architecture_diagram_ingestor_parses_threat_dragon_cells_into_nodes_and_edges():
    model = {
        "detail": {
            "diagrams": [
                {
                    "cells": [
                        {"id": "c1", "data": {"name": "Web App"}},
                        {"id": "c2", "data": {"name": "Database"}},
                        {
                            "id": "c3",
                            "source": {"cell": "c1"},
                            "target": {"cell": "c2"},
                            "data": {"name": "reads/writes"},
                        },
                    ]
                }
            ]
        }
    }
    ingestor = ArchitectureDiagramIngestor()

    nodes, edges = ingestor.run(
        run_id="RUN-1",
        application_id="APP-1",
        connection_details={"filename": "model.json", "content": json.dumps(model)},
    )

    by_name = {n.name: n for n in nodes}
    assert set(by_name) == {"Web App", "Database"}
    assert len(edges) == 1
    assert edges[0].source_node_id == by_name["Web App"].id
    assert edges[0].target_node_id == by_name["Database"].id
    assert edges[0].label == "reads/writes"


def test_documentation_ingestor_produces_one_reference_node_with_a_content_preview():
    ingestor = DocumentationIngestor()

    nodes, edges = ingestor.run(
        run_id="RUN-1",
        application_id="APP-1",
        connection_details={"filename": "runbook.md", "content": "x" * 3000},
    )

    assert edges == []
    assert len(nodes) == 1
    assert nodes[0].node_type == "reference_document"
    assert nodes[0].attributes["filename"] == "runbook.md"
    assert len(nodes[0].attributes["content"]) == 2000


def test_repository_manifest_with_a_wrongly_typed_field_is_skipped_and_counted(tmp_path):
    from kresheen.engine.ingest.github_repository_ingestor import _collect_k8s_records

    (tmp_path / "good.yaml").write_text("apiVersion: v1\nkind: Service\nmetadata: {name: web}\nspec: {ports: [{port: 80}]}\n")
    (tmp_path / "bad.yaml").write_text("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: api}\nspec: {template: {spec: {containers: 5}}}\n")

    records, stats = _collect_k8s_records(tmp_path)

    assert [r["metadata"]["name"] for r in records] == ["web"]
    assert stats["unparseable_skipped"] == 1
