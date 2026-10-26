from datetime import UTC, datetime

from kresheen.engine.facts.graph import FactGraph
from kresheen.engine.reasoning import generate_findings
from kresheen.models.facts import FactNode
from kresheen.models.finding import Severity


def _node(node_id: str, source_ref: str, node_type: str = "process", **attributes) -> FactNode:
    return FactNode(
        id=node_id,
        run_id="RUN-1",
        application_id="APP-1",
        node_type=node_type,
        name=node_id,
        attributes=attributes,
        source_ref=source_ref,
        discovered_at=datetime.now(UTC),
    )


def test_host_network_check_flags_a_manifest_node():
    node = _node("n1", "manifest_upload:k8s", host_network=True)
    graph = FactGraph.build([node], [])

    findings = generate_findings(graph, [], run_id="RUN-1")

    assert len(findings) == 1
    assert "host network" in findings[0].title.lower()
    assert findings[0].severity == Severity.HIGH
    assert findings[0].source_tool == "kresheen"


def test_unpinned_image_check_flags_a_latest_tag():
    node = _node("n1", "manifest_upload:k8s", container_images=["myapp:latest"])
    graph = FactGraph.build([node], [])

    findings = generate_findings(graph, [], run_id="RUN-1")

    assert len(findings) == 1
    assert "unpinned" in findings[0].title.lower()


def test_pinned_image_does_not_trigger_a_finding():
    node = _node("n1", "manifest_upload:k8s", container_images=["myapp:1.2.3"])
    graph = FactGraph.build([node], [])

    assert generate_findings(graph, [], run_id="RUN-1") == []


def test_a_clean_manifest_node_produces_no_findings():
    node = _node("n1", "manifest_upload:terraform", provider="aws")
    graph = FactGraph.build([node], [])

    assert generate_findings(graph, [], run_id="RUN-1") == []


def test_kb_matches_only_enrich_an_already_raised_finding_never_trigger_one():
    from kresheen.models.threat_kb import ThreatKBEntry

    now = datetime.now(UTC)
    attack_entry = ThreatKBEntry(
        id="KB-1",
        source="mitre_attack",
        external_id="T1610",
        name="host network",
        description="host network namespace sharing",
        created_at=now,
        updated_at=now,
    )
    # A node with no risky attributes at all should still produce zero
    # findings even though a KB entry could textually match its name --
    # the KB never independently decides to raise a finding.
    clean_node = _node("clean", "manifest_upload:k8s")
    graph = FactGraph.build([clean_node], [])
    assert generate_findings(graph, [attack_entry], run_id="RUN-1") == []

    # But a node that DOES trigger a rule-based check gets enriched with a
    # matching KB citation.
    risky_node = _node("risky", "manifest_upload:k8s", host_network=True)
    graph = FactGraph.build([risky_node], [])
    findings = generate_findings(graph, [attack_entry], run_id="RUN-1")
    assert findings[0].evidence.mitre_technique_ids == ["T1610"]


def test_grype_vulnerability_node_converts_directly_to_a_finding():
    from kresheen.models.finding import Domain

    node = _node(
        "vuln-1",
        "grype",
        node_type="vulnerability",
        cve_id="GHSA-35jh-r3h4-6jhm",
        severity="high",
        package="lodash",
        version="4.17.15",
        description="Command Injection in lodash",
    )
    graph = FactGraph.build([node], [])

    findings = generate_findings(graph, [], run_id="RUN-1")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.domain == Domain.VULNERABILITY
    assert finding.severity == Severity.HIGH
    assert finding.title == "GHSA-35jh-r3h4-6jhm in lodash@4.17.15"
    assert finding.evidence.cve_refs == ["GHSA-35jh-r3h4-6jhm"]
    assert finding.evidence.attack_path == ["vuln-1"]
    # No fix/EPSS/KEV attributes on this node -- blank, not raising.
    assert finding.evidence.fixed_versions == []
    assert finding.evidence.fix_state is None
    assert finding.evidence.epss_score is None
    assert finding.evidence.known_exploited is False


def test_grype_vulnerability_finding_carries_fix_epss_kev_from_the_fact():
    node = _node(
        "vuln-1",
        "grype",
        node_type="vulnerability",
        cve_id="CVE-2021-44228",
        severity="critical",
        package="log4j-core",
        version="2.14.1",
        description="Log4Shell",
        fixed_versions=["2.15.0"],
        fix_state="fixed",
        epss_score=0.99999,
        epss_percentile=1.0,
        known_exploited=True,
    )
    graph = FactGraph.build([node], [])

    findings = generate_findings(graph, [], run_id="RUN-1")

    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence.fixed_versions == ["2.15.0"]
    assert evidence.fix_state == "fixed"
    assert evidence.epss_score == 0.99999
    assert evidence.epss_percentile == 1.0
    assert evidence.known_exploited is True


def test_grype_severity_strings_map_onto_this_apps_severity_enum():
    for grype_severity, expected in [
        ("critical", Severity.CRITICAL),
        ("negligible", Severity.INFO),
        ("unknown", Severity.INFO),
        ("something-grype-has-never-actually-returned", Severity.INFO),
    ]:
        node = _node("vuln", "grype", node_type="vulnerability", cve_id="CVE-1", severity=grype_severity, package="x")
        graph = FactGraph.build([node], [])
        findings = generate_findings(graph, [], run_id="RUN-1")
        assert findings[0].severity == expected, grype_severity


def test_grype_vulnerability_attaches_to_the_matching_lockfile_not_itself():
    """Regression test: a real run (openshift/splunk-forwarder-operator)
    showed vulnerability findings attached to the vulnerability
    fact's own id -- but that fact is excluded from the DFD entirely (see
    engine/dfd/derive.py), so the finding was unreachable from the diagram.
    It must attach to the real dependency-manifest/lockfile fact for its
    ecosystem instead."""
    vuln = _node(
        "vuln-1",
        "grype",
        node_type="vulnerability",
        cve_id="GO-2026-6180",
        severity="high",
        package="golang.org/x/mod",
        version="v0.39.0",
        purl="pkg:golang/golang.org/x/mod@v0.39.0",
    )
    manifest = _node(
        "gomod-1", "github_repository", node_type="code_artifact", kind="dependency_manifest", language="go"
    )
    lockfile = _node(
        "gosum-1", "github_repository", node_type="code_artifact", kind="dependency_lockfile", language="go"
    )
    graph = FactGraph.build([vuln, manifest, lockfile], [])

    findings = generate_findings(graph, [], run_id="RUN-1")

    assert len(findings) == 1
    assert findings[0].asset_id == "gosum-1"  # lockfile preferred over bare manifest


def test_grype_vulnerability_falls_back_to_manifest_when_no_lockfile_exists():
    vuln = _node(
        "vuln-1",
        "grype",
        node_type="vulnerability",
        cve_id="CVE-1",
        severity="high",
        package="x",
        purl="pkg:npm/x@1.0.0",
    )
    manifest = _node(
        "pkgjson-1", "github_repository", node_type="code_artifact", kind="dependency_manifest", language="node"
    )
    graph = FactGraph.build([vuln, manifest], [])

    findings = generate_findings(graph, [], run_id="RUN-1")

    assert findings[0].asset_id == "pkgjson-1"


def test_two_vulnerabilities_in_the_same_ecosystem_attach_to_the_same_asset():
    vuln_a = _node(
        "vuln-a",
        "grype",
        node_type="vulnerability",
        cve_id="CVE-A",
        severity="high",
        package="x",
        purl="pkg:npm/x@1.0.0",
    )
    vuln_b = _node(
        "vuln-b",
        "grype",
        node_type="vulnerability",
        cve_id="CVE-B",
        severity="medium",
        package="y",
        purl="pkg:npm/y@2.0.0",
    )
    lockfile = _node(
        "lock-1", "github_repository", node_type="code_artifact", kind="dependency_lockfile", language="node"
    )
    graph = FactGraph.build([vuln_a, vuln_b, lockfile], [])

    findings = generate_findings(graph, [], run_id="RUN-1")

    assert {f.asset_id for f in findings} == {"lock-1"}


def test_grype_vulnerability_falls_back_to_the_hub_node_when_no_manifest_matches():
    vuln = _node(
        "vuln-1",
        "grype",
        node_type="vulnerability",
        cve_id="CVE-1",
        severity="high",
        package="x",
        purl="pkg:npm/x@1.0.0",
    )
    hub = _node("hub-1", "github_repository", node_type="external_entity")
    graph = FactGraph.build([vuln, hub], [])

    findings = generate_findings(graph, [], run_id="RUN-1")

    assert findings[0].asset_id == "hub-1"


def test_grype_sbom_document_node_produces_no_finding_of_its_own():
    node = _node(
        "sbom-1",
        "grype",
        node_type="sbom_document",
        format="cyclonedx-json",
        document={"components": [], "vulnerabilities": []},
        component_count=0,
        vulnerability_count=0,
    )
    graph = FactGraph.build([node], [])

    assert generate_findings(graph, [], run_id="RUN-1") == []
