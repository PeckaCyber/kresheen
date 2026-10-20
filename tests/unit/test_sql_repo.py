from datetime import UTC, datetime

from kresheen.models.finding import Domain, Evidence, Finding, Severity
from kresheen.storage.sql_repo import SQLRepository


def _finding() -> Finding:
    return Finding.create(
        domain=Domain.VULNERABILITY,
        source_tool="grype",
        title="t",
        description="d",
        severity=Severity.HIGH,
        asset_id="asset-1",
        evidence=Evidence(cve_refs=["CVE-2021-1"]),
        discovered_at=datetime.now(UTC),
    )


def _repo(tmp_path) -> SQLRepository:
    return SQLRepository(f"sqlite:///{tmp_path}/test.db")


def test_save_and_list_roundtrips(tmp_path):
    repo = _repo(tmp_path)
    finding = _finding()

    repo.save_findings([finding])
    loaded = repo.list_findings()

    assert len(loaded) == 1
    assert loaded[0].id == finding.id
    assert loaded[0].evidence.cve_refs == ["CVE-2021-1"]


def test_upsert_updates_status(tmp_path):
    repo = _repo(tmp_path)
    finding = _finding()
    repo.save_findings([finding])

    resolved = finding.model_copy(update={"status": "resolved"})
    repo.save_findings([resolved])

    loaded = repo.get_finding(finding.id)
    assert loaded.status == "resolved"


def test_filter_by_domain_and_status(tmp_path):
    repo = _repo(tmp_path)
    open_finding = _finding()
    resolved_finding = _finding().model_copy(update={"status": "resolved"})
    repo.save_findings([open_finding, resolved_finding])

    open_only = repo.list_findings(status="open")
    assert {f.id for f in open_only} == {open_finding.id}


def test_finding_json_with_keys_from_older_schemas_still_loads():
    """Stored finding blobs may carry fields the schema no longer has; they are ignored."""
    stored = _finding().model_dump(mode="json")
    stored["priority"] = "P1"
    stored["remediation_ref"] = "ISSUE-1"
    stored["evidence"].update(
        {
            "oscap_rule_id": "xccdf_rule_1",
            "oval_ref": "oval:1",
            "control_ids": ["CIS-3"],
            "cloud_check_id": "check-1",
        }
    )

    loaded = Finding.model_validate(stored)

    assert loaded.id == stored["id"]
    assert loaded.evidence.cve_refs == ["CVE-2021-1"]
    assert not hasattr(loaded, "priority")
    assert not hasattr(loaded.evidence, "control_ids")
