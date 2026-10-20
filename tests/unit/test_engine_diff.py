"""Run-to-run diff: engine/diff.py.

Pure unit tests against hand-built fixtures (no DB) for the four diff
functions, plus one end-to-end wiring test that runs a real Application
twice through `execute_run` and diffs the two runs via `build_run_diff`,
mirroring `test_engine_provenance.py`'s new-module-plus-wiring-test pattern.
"""

from datetime import UTC, datetime

from kresheen.engine.dfd.merge import MergedDfd
from kresheen.engine.diff import (
    build_run_diff,
    diff_components,
    diff_findings,
    diff_flows,
    diff_threats,
    finding_identity_key,
)
from kresheen.engine.orchestrator import execute_run
from kresheen.engine.threats.service import generate_run_threats
from kresheen.models.asset import Asset, AssetType
from kresheen.models.data_source import DataSourceConfig
from kresheen.models.finding import Domain, Evidence, Finding, Severity
from kresheen.models.threat import Threat
from kresheen.models.threat_model_run import ThreatModelRun
from kresheen.storage.sql_repo import SQLRepository


def _now():
    return datetime.now(UTC)


def _asset(asset_id: str, name: str, type_: AssetType = AssetType.PROCESS) -> Asset:
    return Asset(id=asset_id, name=name, type=type_, source="threat_model_run", created_at=_now())


def _dfd(assets: list[Asset], edges: list[dict] | None = None) -> MergedDfd:
    return MergedDfd(
        assets=assets, manual_asset_ids=set(), boundary_by_name={}, edges=edges or [], properties_by_key={}
    )


def _threat(key: str, title: str = "A threat", severity: str = "medium") -> Threat:
    return Threat(
        key=key, rule_id=key.split("|")[0], element_kind="component", element_id="ignored",
        element_name="ignored", element_type="process", title=title, description="d",
        severity=severity, mitigations=[],
    )


def _finding(asset_id: str, title: str = "A finding", stride: str | None = "Tampering") -> Finding:
    return Finding.create(
        domain=Domain.THREAT_MODEL, source_tool="kresheen", title=title, description="d",
        severity=Severity.MEDIUM, asset_id=asset_id, evidence=Evidence(stride_category=stride),
    )


# -- diff_components ----------------------------------------------------------


def test_diff_components_matches_by_type_and_name_not_id():
    """Two runs' web assets carry different ids (ids regenerate every run)
    but the same (type, name) -- must not show up as removed+new."""
    previous = _dfd([_asset("A-1", "web"), _asset("A-2", "db", AssetType.DATA_STORE)])
    current = _dfd([_asset("B-1", "web"), _asset("B-2", "cache", AssetType.DATA_STORE)])

    new, removed = diff_components(previous, current)

    assert [c.name for c in new] == ["cache"]
    assert [c.name for c in removed] == ["db"]


def test_diff_components_no_changes_is_empty():
    assets = [_asset("A-1", "web")]
    new, removed = diff_components(_dfd(assets), _dfd([_asset("B-1", "web")]))
    assert new == [] and removed == []


# -- diff_flows ----------------------------------------------------------------


def test_diff_flows_matches_by_endpoint_names():
    previous = _dfd(
        [_asset("A-1", "web"), _asset("A-2", "db", AssetType.DATA_STORE)],
        edges=[{"id": "F-1", "source": "A-1", "target": "A-2", "label": None, "is_manual": False}],
    )
    current = _dfd(
        [_asset("B-1", "web"), _asset("B-2", "db", AssetType.DATA_STORE), _asset("B-3", "cache", AssetType.DATA_STORE)],
        edges=[
            {"id": "F-2", "source": "B-1", "target": "B-2", "label": None, "is_manual": False},
            {"id": "F-3", "source": "B-1", "target": "B-3", "label": None, "is_manual": False},
        ],
    )

    new, removed = diff_flows(previous, current)

    assert [f.target_name for f in new] == ["cache"]
    assert removed == []


# -- diff_threats ---------------------------------------------------------------


def test_diff_threats_diffs_directly_by_stable_key():
    previous = [_threat("RULE-A|process:web"), _threat("RULE-B|process:db")]
    current = [_threat("RULE-A|process:web"), _threat("RULE-C|process:web")]

    new, resolved = diff_threats(previous, current)

    assert [t.key for t in new] == ["RULE-C|process:web"]
    assert [t.key for t in resolved] == ["RULE-B|process:db"]


# -- finding_identity_key / diff_findings ----------------------------------------


def test_finding_identity_key_resolves_asset_id_to_stable_name_not_run_scoped_id():
    assets_by_id = {"A-1": _asset("A-1", "web")}
    finding = _finding("A-1")

    key = finding_identity_key(finding, assets_by_id)

    assert key == ("process:web", "Tampering:A finding")


def test_finding_identity_key_falls_back_to_raw_asset_id_when_unresolvable():
    key = finding_identity_key(_finding("dangling-id"), {})
    assert key == ("dangling-id", "Tampering:A finding")


def test_finding_identity_key_prefers_cve_over_stride_and_title():
    finding = Finding.create(
        domain=Domain.VULNERABILITY, source_tool="grype", title="lodash vuln", description="d",
        severity=Severity.HIGH, asset_id="A-1", evidence=Evidence(cve_refs=["CVE-2024-1234"]),
    )
    assert finding_identity_key(finding, {"A-1": _asset("A-1", "web")}) == ("process:web", "CVE-2024-1234")


def test_diff_findings_matches_same_finding_across_runs_by_resolved_asset_name():
    """The finding's asset has a different id in each run (ids regenerate
    every run) but the same name -- must be treated as persistent, not
    resolved+new."""
    previous_assets = {"A-1": _asset("A-1", "web")}
    current_assets = {"B-1": _asset("B-1", "web")}
    previous = [_finding("A-1", title="Same finding")]
    current = [_finding("B-1", title="Same finding"), _finding("B-1", title="New finding")]

    new, resolved = diff_findings(previous, previous_assets, current, current_assets)

    assert [f.title for f in new] == ["New finding"]
    assert resolved == []


# -- build_run_diff (end-to-end wiring) ------------------------------------------

_MANIFEST_V1 = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  template:
    spec:
      containers:
        - name: web
          image: myregistry/web:1.0.0
"""

_MANIFEST_V2 = """
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
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
  namespace: prod
spec:
  template:
    spec:
      containers:
        - name: worker
          image: myregistry/worker:1.0.0
"""


def test_build_run_diff_end_to_end_across_two_real_runs(tmp_path):
    """A data source is edited between two runs (a new hostNetwork pod and a
    new `worker` component) -- the diff should surface the new component and
    the new hostNetwork-driven threat without needing any manual key-matching
    from the caller."""
    repo = SQLRepository(f"sqlite:///{tmp_path}/diff.db")
    repo.save_data_source(
        DataSourceConfig(
            id="DS-1", application_id="APP-1", type="manifest_upload",
            connection_details={"content": _MANIFEST_V1}, created_at=_now(),
        )
    )
    repo.save_run(
        ThreatModelRun(
            id="RUN-1", application_id="APP-1", triggered_by_user_id="U",
            data_source_config_ids=["DS-1"], started_at=_now(),
        )
    )
    execute_run(repo, "RUN-1")

    # Simulate "the user edited the data source and re-ran".
    repo.save_data_source(
        DataSourceConfig(
            id="DS-1", application_id="APP-1", type="manifest_upload",
            connection_details={"content": _MANIFEST_V2}, created_at=_now(),
        )
    )
    repo.save_run(
        ThreatModelRun(
            id="RUN-2", application_id="APP-1", triggered_by_user_id="U",
            data_source_config_ids=["DS-1"], started_at=_now(),
        )
    )
    execute_run(repo, "RUN-2")

    previous_threats = generate_run_threats("APP-1", "RUN-1", repo)
    current_threats = generate_run_threats("APP-1", "RUN-2", repo)
    diff = build_run_diff(
        "APP-1", "RUN-1", "RUN-2", repo, previous_threats=previous_threats, current_threats=current_threats
    )

    assert [c.name for c in diff.new_components] == ["Deployment/worker"]
    assert diff.removed_components == []
    assert any(t.title for t in diff.new_threats)  # hostNetwork-driven threats now present
