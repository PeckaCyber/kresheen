"""Regression tests for four core-engine defects: a GitHub-only run producing no
threats, same-named components in different namespaces collapsing, namespace
names read as internet exposure, and (in test_threat_reference_ids.py)
unvalidated CWE/ATT&CK ids."""

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
import responses

from kresheen.engine.facts.naming import qualify_colliding_names, unqualified_name
from kresheen.engine.ingest.github_repository_ingestor import GithubRepositoryIngestor
from kresheen.engine.orchestrator import execute_run
from kresheen.engine.threats.generate import DfdElement, generate_threats
from kresheen.engine.threats.service import generate_run_threats, load_dfd_model
from kresheen.models.data_source import DataSourceConfig
from kresheen.models.facts import FactNode
from kresheen.models.threat_model_run import ThreatModelRun
from kresheen.models.trust_boundary import (
    TrustBoundaryAssignment,
    new_trust_boundary_assignment_id,
)
from kresheen.storage.sql_repo import SQLRepository
from tests.conftest import build_tarball_bytes


def _deployment(name: str, namespace: str, app: str | None = None) -> str:
    app = app or name
    return f"""
apiVersion: apps/v1
kind: Deployment
metadata: {{name: {name}, namespace: {namespace}}}
spec:
  selector: {{matchLabels: {{app: {app}}}}}
  template:
    metadata: {{labels: {{app: {app}}}}}
    spec:
      containers:
        - name: main
          image: registry.example/{app}:1.0
"""


def _load_balancer(name: str, namespace: str, app: str) -> str:
    return f"""
apiVersion: v1
kind: Service
metadata: {{name: {name}, namespace: {namespace}}}
spec:
  type: LoadBalancer
  selector: {{app: {app}}}
  ports: [{{name: https, port: 443}}]
"""


def _run_manifest(tmp_path, *docs: str) -> tuple[SQLRepository, str]:
    repo = SQLRepository(f"sqlite:///{tmp_path}/test.db")
    repo.save_data_source(
        DataSourceConfig(
            id="DS-1", application_id="APP-1", type="manifest_upload",
            connection_details={"content": "\n---\n".join(docs)}, created_at=datetime.now(UTC),
        )
    )
    repo.save_run(
        ThreatModelRun(
            id="RUN-1", application_id="APP-1", triggered_by_user_id="U", data_source_config_ids=["DS-1"],
            started_at=datetime.now(UTC),
        )
    )
    execute_run(repo, "RUN-1")
    return repo, "RUN-1"


# -- 2. same-named components in different namespaces ------------------------------------------------------


def _fact(name: str, namespace: str, node_type: str = "process") -> FactNode:
    return FactNode(
        id=f"{namespace}-{name}", run_id="R", application_id="A", node_type=node_type, name=name,
        attributes={"namespace": namespace}, source_ref="t", discovered_at=datetime.now(UTC),
    )


def test_colliding_names_are_qualified_and_unique_ones_are_untouched():
    a, b, solo = _fact("Deployment/redis", "team-a"), _fact("Deployment/redis", "team-b"), _fact("Deployment/api", "team-a")
    qualify_colliding_names([a, b, solo])

    assert (a.name, b.name) == ("Deployment/redis (team-a)", "Deployment/redis (team-b)")
    assert solo.name == "Deployment/api"  # unchanged, so stored statuses for it keep matching
    assert unqualified_name(a) == "Deployment/redis" and unqualified_name(solo) == "Deployment/api"


def test_same_name_in_the_same_namespace_is_not_renamed():
    a, b = _fact("Deployment/redis", "team-a"), _fact("Deployment/redis", "team-a")
    qualify_colliding_names([a, b])
    assert a.name == b.name == "Deployment/redis"


def test_two_workloads_with_one_name_yield_separate_threats(tmp_path):
    repo, run_id = _run_manifest(tmp_path, _deployment("redis", "team-a"), _deployment("redis", "team-b"))

    elements, _ = load_dfd_model("APP-1", run_id, repo)
    assert sorted(e.name for e in elements) == ["Deployment/redis (team-a)", "Deployment/redis (team-b)"]

    threats = generate_run_threats("APP-1", run_id, repo)
    spoofing = [t for t in threats if t.rule_id == "PROC-S-01"]
    assert len(spoofing) == 2
    assert len({t.key for t in spoofing}) == 2  # distinct keys, so each gets its own status


def test_a_uniquely_named_workload_keeps_its_original_name_and_threat_key(tmp_path):
    repo, run_id = _run_manifest(tmp_path, _deployment("api", "team-a"), _deployment("redis", "team-b"))
    keys = {t.key for t in generate_run_threats("APP-1", run_id, repo)}
    assert "PROC-S-01|process:Deployment/api" in keys


# -- 3. exposure judged from evidence for namespace-derived boundaries --------------------------------------


def test_explicit_untrusted_flag_overrides_the_label_in_both_directions():
    keyword_trap = generate_threats([DfdElement("p", "Operator", "process", "external-secrets", untrusted_facing=False)], [])
    quiet_label = generate_threats([DfdElement("p", "Web", "process", "prod", untrusted_facing=True)], [])
    assert "PROC-E-02" not in {t.rule_id for t in keyword_trap}
    exposed = next(t for t in quiet_label if t.rule_id == "PROC-E-02")
    assert exposed.risk_factors == ["directly reachable from an external entity"]


def test_a_user_typed_label_is_still_judged_by_its_text():
    threats = generate_threats([DfdElement("p", "API", "process", "Internet-facing")], [])
    assert "PROC-E-02" in {t.rule_id for t in threats}


def test_namespace_named_external_is_not_internet_facing_but_a_load_balanced_workload_is(tmp_path):
    repo, run_id = _run_manifest(
        tmp_path,
        _deployment("operator", "external-secrets"),
        _deployment("web", "shop"),
        _load_balancer("web", "shop", "web"),
    )
    threats = generate_run_threats("APP-1", run_id, repo)
    exposed = {t.element_name for t in threats if t.rule_id == "PROC-E-02"}

    assert "Deployment/web" in exposed
    assert "Deployment/operator" not in exposed


def test_relabelling_a_component_hands_exposure_back_to_the_label_text(tmp_path):
    repo, run_id = _run_manifest(tmp_path, _deployment("operator", "kube-system"))
    repo.save_trust_boundary_assignment(
        TrustBoundaryAssignment(
            id=new_trust_boundary_assignment_id(), application_id="APP-1", component_name="Deployment/operator",
            trust_boundary="Public DMZ", created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
        )
    )
    threats = generate_run_threats("APP-1", run_id, repo)
    assert "PROC-E-02" in {t.rule_id for t in threats if t.element_name == "Deployment/operator"}


# -- 1. a repository that ships Kubernetes manifests -------------------------------------------------------

_REPO_FILES = {
    "deploy/web.yaml": _deployment("web", "shop") + "\n---\n" + _load_balancer("web", "shop", "web"),
    "deploy/chart/templates/dep.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Values.name }}\n",
    "deploy/kustomization.yaml": "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nmetadata: {name: k}\n",
    ".github/workflows/ci.yml": "name: ci\non: push\njobs: {}\n",
    "deploy/alias-bomb.yaml": "a: &a [x]\n" + "".join(f"k{i}: [*a, *a, *a]\n" for i in range(40)),
    "vendor/dep/deploy.yaml": _deployment("vendored", "shop"),
    "package.json": "{}",
}


def _github_run(tmp_path, files: dict[str, str]) -> tuple[SQLRepository, str]:
    repo = SQLRepository(f"sqlite:///{tmp_path}/gh.db")
    repo.save_data_source(
        DataSourceConfig(
            id="DS-1", application_id="APP-1", type="github_repository",
            connection_details={"repo_url": "https://github.com/acme/widget"}, created_at=datetime.now(UTC),
        )
    )
    repo.save_run(
        ThreatModelRun(
            id="RUN-1", application_id="APP-1", triggered_by_user_id="U", data_source_config_ids=["DS-1"],
            started_at=datetime.now(UTC),
        )
    )
    with responses.RequestsMock() as mock, patch(
        "kresheen.engine.ingest.github_repository_ingestor._run_grype_scan", return_value=None
    ):
        mock.add(
            responses.GET, "https://api.github.com/repos/acme/widget/tarball",
            body=build_tarball_bytes(files), status=200,
        )
        execute_run(repo, "RUN-1")
    return repo, "RUN-1"


def test_github_repository_manifests_become_components_with_threats(tmp_path):
    repo, run_id = _github_run(tmp_path, _REPO_FILES)

    elements, flows = load_dfd_model("APP-1", run_id, repo)
    names = {e.name for e in elements}
    assert "Deployment/web" in names
    assert "Internet" in names and len(flows) == 1  # evidence-based flow from the LoadBalancer Service

    threats = generate_run_threats("APP-1", run_id, repo)
    assert any(t.element_name == "Deployment/web" for t in threats)
    assert "PROC-E-02" in {t.rule_id for t in threats if t.element_name == "Deployment/web"}


def test_repository_scan_skips_what_is_not_a_plain_manifest_and_says_so(tmp_path):
    ingestor = GithubRepositoryIngestor()
    with responses.RequestsMock() as mock, patch(
        "kresheen.engine.ingest.github_repository_ingestor._run_grype_scan", return_value=None
    ):
        mock.add(
            responses.GET, "https://api.github.com/repos/acme/widget/tarball",
            body=build_tarball_bytes(_REPO_FILES), status=200,
        )
        nodes, _ = ingestor.run(
            run_id="R", application_id="A", connection_details={"repo_url": "https://github.com/acme/widget"}
        )

    components = {n.name for n in nodes if n.node_type in ("process", "data_store")}
    assert components == {"Deployment/web"}  # not the Helm template, Kustomization, workflow, alias bomb or vendor/ copy
    hub = next(n for n in nodes if n.source_ref == "github_repository" and n.node_type == "external_entity")
    stats = hub.attributes["k8s_manifests"]
    assert stats["templated_skipped"] == 1
    assert stats["unparseable_skipped"] == 1  # the alias bomb
    assert all(n.source_ref == "github_repository:k8s" for n in nodes if n.node_type in ("process", "data_store"))


def test_repository_with_no_manifests_still_has_no_components(tmp_path):
    repo, run_id = _github_run(tmp_path, {"package.json": "{}", "README.md": "hi"})
    elements, _ = load_dfd_model("APP-1", run_id, repo)
    assert elements == []  # honest: nothing to threat-model, and the UI now says why


@pytest.mark.parametrize("payload", ["kind: Deployment\n", "- not\n- a\n- mapping\n", "apiVersion: v1\nkind: [x]\nmetadata: {name: y}\n"])
def test_malformed_or_partial_yaml_never_becomes_a_component(tmp_path, payload):
    repo, run_id = _github_run(tmp_path, {"deploy/x.yaml": payload, "package.json": "{}"})
    elements, _ = load_dfd_model("APP-1", run_id, repo)
    assert elements == []
