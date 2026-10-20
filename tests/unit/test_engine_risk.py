"""The risk model and the finding <-> threat evidence join (engine/threats/risk.py)."""

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import responses

from kresheen.engine.orchestrator import execute_run
from kresheen.engine.threats.generate import DfdElement, DfdFlow, generate_threats, sort_threats
from kresheen.engine.threats.risk import EVIDENCE_LIMIT, assess_threats
from kresheen.engine.threats.service import generate_run_threats
from kresheen.models.data_source import DataSourceConfig
from kresheen.models.finding import Domain, Evidence, Finding, Severity
from kresheen.models.threat import risk_rating_for, risk_score_for
from kresheen.models.threat_model_run import ThreatModelRun
from kresheen.storage.sql_repo import SQLRepository
from tests.conftest import build_tarball_bytes
from tests.unit.test_engine_robustness_fixes import _deployment

_GRYPE_FIXTURE = Path(__file__).parent.parent / "fixtures" / "grype" / "sample_cyclonedx.json"


def _finding(asset_id: str, *, stride: str | None, severity=Severity.HIGH, status="open", **kw) -> Finding:
    return Finding.create(
        domain=Domain.THREAT_MODEL, source_tool="kresheen", title=f"{severity.value} issue", description="d",
        severity=severity, asset_id=asset_id, evidence=Evidence(stride_category=stride), status=status, **kw,
    )


def _assess(elements, findings=(), fact_nodes=()):
    threats = generate_threats(elements, [])
    return {t.rule_id: t for t in assess_threats(threats, elements=elements, flows=[], findings=list(findings), fact_nodes=list(fact_nodes))}


_INTERNAL = DfdElement("p", "API", "process", "internal")
_EXPOSED = DfdElement("p", "API", "process", "Internet-facing")


def test_risk_is_impact_times_likelihood():
    assert risk_score_for("critical", "almost_certain") == 20
    assert risk_score_for("low", "very_rare") == 1
    assert [risk_rating_for(s) for s in (4, 5, 9, 10, 14, 15)] == ["low", "medium", "medium", "high", "high", "critical"]


def test_a_threat_with_nothing_known_is_possible_and_unexplained():
    threat = _assess([_INTERNAL])["PROC-T-01"]
    assert (threat.likelihood, threat.likelihood_factors, threat.evidence, threat.evidence_total) == ("possible", [], [], 0)
    assert (threat.severity, threat.risk) == ("high", "medium")  # high impact x possible


def test_exposure_lifts_likelihood_and_says_why():
    threat = _assess([_EXPOSED])["PROC-T-01"]
    assert threat.likelihood == "likely" and threat.risk == "high"
    assert threat.likelihood_factors == ["exposed: directly reachable from an untrusted caller"]


# -- asserted vs. verified provenance ("Core engine robustness" #10) ----------


def test_manual_component_threat_is_tagged_as_an_owner_assertion():
    manual = DfdElement("p", "API", "process", is_manual=True)
    threat = _assess([manual])["PROC-T-01"]
    assert "owner states: this component was added by hand, not found in any ingested source" in threat.likelihood_factors


def test_manual_flow_threat_is_tagged_as_an_owner_assertion():
    a = DfdElement("a", "Web", "process", "internal")
    b = DfdElement("b", "API", "process", "internal")
    flow = DfdFlow("f", "a", "b", is_manual=True)
    threats = {
        t.rule_id: t
        for t in assess_threats(
            generate_threats([a, b], [flow]), elements=[a, b], flows=[flow], findings=[], fact_nodes=[]
        )
    }
    assert "owner states: this connection was drawn by hand, not found in any ingested source" in threats["FLOW-T-01"].likelihood_factors


def test_asserted_trust_boundary_exposure_is_worded_differently_from_evidence():
    """A user-typed/overridden boundary label changes threat output the same
    way evidence does (same likelihood bump) but must say so differently --
    "owner states" versus "exposed"."""
    asserted = DfdElement("p", "API", "process", "Internet-facing", boundary_asserted=True)
    threat = _assess([asserted])["PROC-T-01"]
    assert threat.likelihood == "likely"  # same bump as the evidence-derived case
    assert threat.likelihood_factors == ["owner states: exposed (trust boundary set by hand, not derived from evidence)"]

    # Unchanged from before this tagging existed: no override, not asserted.
    evidence_based = _assess([_EXPOSED])["PROC-T-01"]
    assert evidence_based.likelihood_factors == ["exposed: directly reachable from an untrusted caller"]


def test_loader_evidence_wins_over_an_asserted_boundary_label():
    """untrusted_facing=True (the loader observed a real external flow) is
    evidence, even if the label was also user-overridden -- evidence must
    never be described as a mere assertion."""
    both = DfdElement("p", "API", "process", "Internet-facing", untrusted_facing=True, boundary_asserted=True)
    threat = _assess([both])["PROC-T-01"]
    assert threat.likelihood_factors == ["exposed: directly reachable from an untrusted caller"]


def test_a_finding_on_the_component_and_stride_is_evidence():
    finding = _finding("p", stride="Tampering", severity=Severity.MEDIUM)
    tampering = _assess([_INTERNAL], [finding])["PROC-T-01"]
    other_stride = _assess([_INTERNAL], [finding])["PROC-S-01"]

    assert tampering.likelihood == "likely"
    assert [(e.finding_id, e.scope) for e in tampering.evidence] == [(finding.id, "component")]
    assert tampering.evidence_total == 1
    assert other_stride.evidence == [] and other_stride.likelihood == "possible"


def test_findings_on_another_component_or_no_longer_open_are_not_evidence():
    elsewhere = _finding("other", stride="Tampering")
    resolved = _finding("p", stride="Tampering", status="resolved")
    threat = _assess([_INTERNAL], [elsewhere, resolved])["PROC-T-01"]
    assert threat.evidence == [] and threat.likelihood == "possible"


def test_evidence_alone_never_reaches_almost_certain_but_evidence_on_an_exposed_component_can():
    critical = _finding("p", stride="Tampering", severity=Severity.CRITICAL)
    assert _assess([_INTERNAL], [critical])["PROC-T-01"].likelihood == "likely"
    exposed = _assess([_EXPOSED], [critical])["PROC-T-01"]
    assert exposed.likelihood == "almost_certain" and exposed.risk == "critical"


def test_fixing_the_finding_leaves_the_threat_at_its_base_likelihood():
    """A threat outlives its evidence: it is not deleted, its likelihood just falls."""
    finding = _finding("p", stride="Tampering", severity=Severity.HIGH)
    assert _assess([_INTERNAL], [finding])["PROC-T-01"].likelihood == "likely"
    fixed = finding.model_copy(update={"status": "resolved"})
    assert _assess([_INTERNAL], [fixed])["PROC-T-01"].likelihood == "possible"


def test_a_component_with_findings_outranks_an_identical_one_without():
    with_finding = DfdElement("a", "Risky", "process", "internal")
    clean = DfdElement("b", "Clean", "process", "internal")
    elements = [with_finding, clean]
    findings = [_finding("a", stride="Tampering", severity=Severity.HIGH)]
    threats = sort_threats(assess_threats(generate_threats(elements, []), elements=elements, flows=[], findings=findings, fact_nodes=[]))
    tampering = [t for t in threats if t.rule_id == "PROC-T-01"]
    assert [t.element_name for t in tampering] == ["Risky", "Clean"]
    assert threats[0].element_name == "Risky"


def test_listed_evidence_is_capped_worst_first_and_still_counted():
    findings = [_finding("p", stride="Tampering", severity=Severity.LOW) for _ in range(EVIDENCE_LIMIT + 5)]
    findings.append(_finding("p", stride="Tampering", severity=Severity.CRITICAL))
    threat = _assess([_INTERNAL], findings)["PROC-T-01"]
    assert len(threat.evidence) == EVIDENCE_LIMIT and threat.evidence_total == EVIDENCE_LIMIT + 6
    assert threat.evidence[0].severity == "critical"


# -- controls ---------------------------------------------------------


def test_an_asserted_control_withholds_the_exposure_bump_for_the_rule_it_covers():
    authenticated = DfdElement("p", "API", "process", "Internet-facing", properties={"authenticates_callers": True})
    threats = _assess([authenticated])
    spoof = threats["PROC-S-01"]
    assert spoof.likelihood == "possible"  # exposed, but the control covers it
    assert any("control in place" in f for f in spoof.likelihood_factors)
    assert not any(f.startswith("exposed:") for f in spoof.likelihood_factors)
    # An unrelated rule on the same exposed component is unaffected.
    assert threats["PROC-T-01"].likelihood == "likely"


def test_an_asserted_control_does_not_lower_evidence_based_likelihood():
    """A control is what's configured; a finding is what was observed. Evidence wins."""
    authenticated = DfdElement("p", "API", "process", "Internet-facing", properties={"authenticates_callers": True})
    finding = _finding("p", stride="Spoofing", severity=Severity.CRITICAL)
    spoof = _assess([authenticated], [finding])["PROC-S-01"]
    assert spoof.likelihood == "almost_certain"


def test_an_encrypted_data_store_withholds_the_exposure_bump():
    store = DfdElement("s", "DB", "data_store", "Internet-facing", properties={"is_encrypted": True})
    threat = _assess([store])["STORE-I-01"]
    assert threat.likelihood == "possible"
    assert any("control in place" in f for f in threat.likelihood_factors)


def test_an_encrypted_flow_control_is_not_bumped_by_crossing_a_boundary():
    a = DfdElement("a", "Web", "process", "dmz")
    b = DfdElement("b", "API", "process", "internal")
    flow = DfdFlow("f", "a", "b", properties={"is_encrypted": True})
    threats = {
        t.rule_id: t
        for t in assess_threats(
            generate_threats([a, b], [flow]), elements=[a, b], flows=[flow], findings=[], fact_nodes=[]
        )
    }
    intercept = threats["FLOW-I-01"]
    assert intercept.likelihood == "possible"
    assert any("control in place" in f for f in intercept.likelihood_factors)
    # FLOW-T-02 (crosses_boundary, unrelated to encryption) is untouched.
    assert threats["FLOW-T-02"].likelihood == "likely"


def test_every_incoming_flow_authenticated_covers_the_component_even_with_no_component_property():
    api = DfdElement("api", "API", "process", "Internet-facing")
    caller = DfdElement("caller", "Caller", "external_entity")
    flow = DfdFlow("f", "caller", "api", properties={"authenticated": True})
    threats = {
        t.rule_id: t
        for t in assess_threats(
            generate_threats([caller, api], [flow]), elements=[caller, api], flows=[flow], findings=[], fact_nodes=[]
        )
    }
    assert threats["PROC-S-01"].likelihood == "possible"
    assert any("every entry path" in f for f in threats["PROC-S-01"].likelihood_factors)


def _lb_manifest(name: str, *, declares_auth: bool) -> str:
    config = (
        f"""
apiVersion: v1
kind: ConfigMap
metadata: {{name: {name}-cfg, namespace: n}}
data: {{OIDC_ISSUER: "https://sso"}}
---"""
        if declares_auth
        else ""
    )
    env_from = f"        envFrom: [{{configMapRef: {{name: {name}-cfg}}}}]\n" if declares_auth else ""
    return f"""
apiVersion: apps/v1
kind: Deployment
metadata: {{name: {name}, namespace: n}}
spec:
  template:
    metadata: {{labels: {{app: {name}}}}}
    spec:
      containers:
      - name: c
        image: app:1
{env_from}
---
apiVersion: v1
kind: Service
metadata: {{name: {name}, namespace: n}}
spec: {{type: LoadBalancer, selector: {{app: {name}}}, ports: [{{name: https, port: 443}}]}}
{config}"""


def test_declared_auth_in_the_manifest_is_derived_into_the_control_end_to_end(tmp_path):
    """service.py wiring: a workload that already declares real authentication
    shouldn't also read as unauthenticated generic-rule noise."""
    repo = SQLRepository(f"sqlite:///{tmp_path}/risk.db")
    for name, declares in (("open", False), ("guarded", True)):
        repo.save_data_source(
            DataSourceConfig(
                id=f"DS-{name}", application_id="APP-1", type="manifest_upload",
                connection_details={"content": _lb_manifest(name, declares_auth=declares)}, created_at=datetime.now(UTC),
            )
        )
        repo.save_run(
            ThreatModelRun(
                id=f"RUN-{name}", application_id="APP-1", triggered_by_user_id="U",
                data_source_config_ids=[f"DS-{name}"], started_at=datetime.now(UTC),
            )
        )
        execute_run(repo, f"RUN-{name}")

    open_threats = {t.rule_id: t for t in generate_run_threats("APP-1", "RUN-open", repo)}
    guarded_threats = {t.rule_id: t for t in generate_run_threats("APP-1", "RUN-guarded", repo)}

    assert open_threats["PROC-S-01"].likelihood == "likely"
    assert guarded_threats["PROC-S-01"].likelihood == "possible"
    assert any("control in place" in f for f in guarded_threats["PROC-S-01"].likelihood_factors)
    # SC-T01 (the specific config-rule hit) already correctly distinguished these two;
    # this confirms the generic rule now agrees instead of firing at full volume regardless.
    assert not any(t.rule_id == "SC-T01" for t in guarded_threats.values())
    assert any(t.rule_id == "SC-T01" for t in open_threats.values())


def test_only_some_entry_paths_authenticated_is_partially_mitigated_but_still_bumped():
    api = DfdElement("api", "API", "process", "Internet-facing")
    caller1 = DfdElement("c1", "Caller1", "external_entity")
    caller2 = DfdElement("c2", "Caller2", "external_entity")
    authed = DfdFlow("f1", "c1", "api", properties={"authenticated": True})
    open_flow = DfdFlow("f2", "c2", "api", properties={})
    elements = [caller1, caller2, api]
    flows = [authed, open_flow]
    threat = {
        t.rule_id: t
        for t in assess_threats(generate_threats(elements, flows), elements=elements, flows=flows, findings=[], fact_nodes=[])
    }["PROC-S-01"]
    assert threat.likelihood == "likely"  # the gap on the unauthenticated path still counts
    assert any("partially mitigated: 1 of 2 entry paths" in f for f in threat.likelihood_factors)


# -- repository dependency vulnerabilities ---------------------------------------------------------------------


def _repo_run(tmp_path, *, with_vulns: bool):
    repo = SQLRepository(f"sqlite:///{tmp_path}/risk.db")
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
    files = {"deploy/web.yaml": _deployment("web", "shop"), "package-lock.json": "{}"}
    sbom = json.loads(_GRYPE_FIXTURE.read_text()) if with_vulns else None
    grype_result = (sbom, {"matches": []}) if with_vulns else None
    with responses.RequestsMock() as mock, patch(
        "kresheen.engine.ingest.github_repository_ingestor._run_grype_scan", return_value=grype_result
    ):
        mock.add(responses.GET, "https://api.github.com/repos/acme/widget/tarball", body=build_tarball_bytes(files), status=200)
        execute_run(repo, "RUN-1")
    return repo


def test_repository_vulnerabilities_support_the_dependency_threat_of_that_repos_workloads(tmp_path):
    repo = _repo_run(tmp_path, with_vulns=True)
    threats = {t.rule_id: t for t in generate_run_threats("APP-1", "RUN-1", repo) if t.element_name == "Deployment/web"}

    tampering = threats["PROC-T-01"]
    assert tampering.evidence_total >= 1
    assert {e.scope for e in tampering.evidence} == {"repository"}
    assert tampering.likelihood == "likely"  # the fixture's vulnerability is high severity
    assert any("not confirmed to be present" in f for f in tampering.likelihood_factors)
    # Only the dependency-tampering rule is supported by them.
    assert all(t.evidence == [] for rule_id, t in threats.items() if rule_id != "PROC-T-01" and t.category != "Tampering")
    assert threats["PROC-S-01"].likelihood == "possible"


def test_no_repository_vulnerabilities_no_evidence(tmp_path):
    repo = _repo_run(tmp_path, with_vulns=False)
    threats = [t for t in generate_run_threats("APP-1", "RUN-1", repo) if t.element_name == "Deployment/web"]
    assert all(t.evidence == [] and t.likelihood == "possible" for t in threats if t.rule_id == "PROC-T-01")
