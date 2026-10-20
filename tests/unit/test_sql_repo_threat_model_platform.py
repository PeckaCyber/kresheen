"""Round-trip coverage for the threat-modeling platform's new SQLRepository
surface: applications, data sources, runs, facts, threat KB entries,
construct mappings, connectors, agent configs, and encrypted secret blobs.
"""

from datetime import UTC, datetime, timedelta

from kresheen.models.agent_config import AgentConfig
from kresheen.models.application import Application
from kresheen.models.asset import Asset, AssetFlow, AssetType
from kresheen.models.data_source import DataSourceConfig
from kresheen.models.facts import FactEdge, FactNode
from kresheen.models.finding import Domain, Evidence, Finding, Severity
from kresheen.models.threat_kb import ThreatKBEntry
from kresheen.models.threat_model_run import ThreatModelRun
from kresheen.storage.sql_repo import SQLRepository


def _repo(tmp_path) -> SQLRepository:
    return SQLRepository(f"sqlite:///{tmp_path}/test.db")


def _now():
    return datetime.now(UTC)


# -- Applications -------------------------------------------------------------


def test_save_and_get_application_roundtrips(tmp_path):
    repo = _repo(tmp_path)
    application = Application(
        id="APP-1", name="Test App", owner_user_id="USER-1", created_at=_now(), updated_at=_now()
    )

    repo.save_application(application)

    assert repo.get_application("APP-1") == application
    assert repo.list_applications() == [application]


def test_get_application_returns_none_for_unknown_id(tmp_path):
    repo = _repo(tmp_path)

    assert repo.get_application("nope") is None


def test_delete_application_removes_it_and_its_data_sources_and_runs(tmp_path):
    repo = _repo(tmp_path)
    now = _now()
    repo.save_application(Application(id="APP-1", name="Test App", owner_user_id="USER-1", created_at=now, updated_at=now))
    repo.save_data_source(
        DataSourceConfig(id="DS-1", application_id="APP-1", type="manifest_upload", created_at=now)
    )
    repo.save_run(
        ThreatModelRun(id="RUN-1", application_id="APP-1", triggered_by_user_id="USER-1", started_at=now)
    )

    repo.delete_application("APP-1")

    assert repo.get_application("APP-1") is None
    assert repo.list_data_sources_for_application("APP-1") == []
    assert repo.list_runs_for_application("APP-1") == []


# -- Data sources ---------------------------------------------------------------


def test_save_and_list_data_sources_for_application(tmp_path):
    repo = _repo(tmp_path)
    ds = DataSourceConfig(
        id="DS-1", application_id="APP-1", type="manifest_upload", connection_details={"content": "{}"}, created_at=_now()
    )

    repo.save_data_source(ds)

    assert repo.get_data_source("DS-1") == ds
    assert repo.list_data_sources_for_application("APP-1") == [ds]
    assert repo.list_data_sources_for_application("APP-2") == []


def test_delete_data_source_removes_it(tmp_path):
    repo = _repo(tmp_path)
    repo.save_data_source(DataSourceConfig(id="DS-1", application_id="APP-1", type="manifest_upload", created_at=_now()))

    repo.delete_data_source("DS-1")

    assert repo.get_data_source("DS-1") is None


# -- Runs -------------------------------------------------------------------


def test_save_and_get_run_roundtrips(tmp_path):
    repo = _repo(tmp_path)
    run = ThreatModelRun(id="RUN-1", application_id="APP-1", triggered_by_user_id="USER-1", started_at=_now())

    repo.save_run(run)

    assert repo.get_run("RUN-1") == run
    assert repo.list_runs_for_application("APP-1") == [run]


def test_list_runs_for_application_orders_chronologically_regardless_of_insertion_order(tmp_path):
    """started_at lives in the JSON blob, not a promoted column, so the
    underlying query has no natural order -- run history and the diff
    endpoint's "immediately preceding run" lookup both depend on this being
    sorted, not insertion order."""
    repo = _repo(tmp_path)
    base = _now()
    newest = ThreatModelRun(
        id="RUN-newest", application_id="APP-1", triggered_by_user_id="USER-1", started_at=base + timedelta(hours=2)
    )
    oldest = ThreatModelRun(
        id="RUN-oldest", application_id="APP-1", triggered_by_user_id="USER-1", started_at=base
    )
    middle = ThreatModelRun(
        id="RUN-middle", application_id="APP-1", triggered_by_user_id="USER-1", started_at=base + timedelta(hours=1)
    )
    # Saved out of chronological order on purpose.
    repo.save_run(newest)
    repo.save_run(oldest)
    repo.save_run(middle)

    assert [r.id for r in repo.list_runs_for_application("APP-1")] == ["RUN-oldest", "RUN-middle", "RUN-newest"]


# -- Facts --------------------------------------------------------------------


def test_save_and_list_fact_nodes_and_edges_for_run(tmp_path):
    repo = _repo(tmp_path)
    node_a = FactNode(
        id="FACT-N-a", run_id="RUN-1", application_id="APP-1", node_type="process", name="a",
        source_ref="test", discovered_at=_now(),
    )
    node_b = FactNode(
        id="FACT-N-b", run_id="RUN-1", application_id="APP-1", node_type="data_store", name="b",
        source_ref="test", discovered_at=_now(),
    )
    edge = FactEdge(
        id="FACT-E-1", run_id="RUN-1", application_id="APP-1", source_node_id="FACT-N-a",
        target_node_id="FACT-N-b", edge_type="data_flow",
    )

    repo.save_fact_nodes([node_a, node_b])
    repo.save_fact_edges([edge])

    assert {n.id for n in repo.list_fact_nodes_for_run("RUN-1")} == {"FACT-N-a", "FACT-N-b"}
    assert repo.list_fact_edges_for_run("RUN-1") == [edge]
    assert repo.list_fact_nodes_for_run("RUN-other") == []


def test_findings_filter_by_run_id(tmp_path):
    repo = _repo(tmp_path)
    in_run = Finding.create(
        domain=Domain.THREAT_MODEL, source_tool="kresheen", title="t1", description="d",
        severity=Severity.HIGH, asset_id="a", run_id="RUN-1", evidence=Evidence(),
    )
    other_run = Finding.create(
        domain=Domain.THREAT_MODEL, source_tool="kresheen", title="t2", description="d",
        severity=Severity.HIGH, asset_id="a", run_id="RUN-2", evidence=Evidence(),
    )
    repo.save_findings([in_run, other_run])

    assert [f.id for f in repo.list_findings(run_id="RUN-1")] == [in_run.id]


# -- Assets scoped to a run -----------------------------------------------------


def test_replace_assets_for_run_only_touches_that_run(tmp_path):
    repo = _repo(tmp_path)
    now = _now()
    asset_run_1 = Asset(
        id="a1", name="a1", type=AssetType.PROCESS, source="threat_model_run", run_id="RUN-1", created_at=now
    )
    asset_run_2 = Asset(
        id="a2", name="a2", type=AssetType.PROCESS, source="threat_model_run", run_id="RUN-2", created_at=now
    )
    repo.replace_assets_for_run("RUN-1", [asset_run_1])
    repo.replace_assets_for_run("RUN-2", [asset_run_2])

    repo.replace_assets_for_run("RUN-1", [])

    assert repo.list_assets_for_run("RUN-1") == []
    assert repo.list_assets_for_run("RUN-2") == [asset_run_2]


def test_replace_asset_flows_for_run_roundtrips(tmp_path):
    repo = _repo(tmp_path)
    flow = AssetFlow(id="FLOW-1", source_asset_id="a", target_asset_id="b", run_id="RUN-1")

    repo.replace_asset_flows_for_run("RUN-1", [flow])

    assert repo.list_asset_flows_for_run("RUN-1") == [flow]
    assert repo.list_asset_flows_for_run("RUN-2") == []


# -- Threat KB ------------------------------------------------------------------


def test_save_and_list_kb_entries_filters_by_source(tmp_path):
    repo = _repo(tmp_path)
    now = _now()
    attack = ThreatKBEntry(
        id="KB-1", source="mitre_attack", external_id="T1190", name="Exploit Public-Facing Application",
        description="d", created_at=now, updated_at=now,
    )
    cwe = ThreatKBEntry(id="KB-2", source="cwe", external_id="CWE-79", name="XSS", description="d", created_at=now, updated_at=now)

    repo.save_kb_entries([attack, cwe])

    assert repo.list_kb_entries(source="mitre_attack") == [attack]
    assert {e.id for e in repo.list_kb_entries()} == {"KB-1", "KB-2"}
    assert repo.get_kb_entry("KB-1") == attack


def test_delete_kb_entry_removes_it(tmp_path):
    repo = _repo(tmp_path)
    now = _now()
    repo.save_kb_entries([ThreatKBEntry(id="KB-1", source="custom", name="n", description="d", created_at=now, updated_at=now)])

    repo.delete_kb_entry("KB-1")

    assert repo.get_kb_entry("KB-1") is None


# -- Agent config -------------------------------------


def test_save_and_get_agent_config_by_scope(tmp_path):
    repo = _repo(tmp_path)
    now = _now()
    config = AgentConfig(
        id="AGENT-1", scope="user", scope_id="USER-1", api_key_ref="SECRET-1",
        created_at=now, updated_at=now,
    )

    repo.save_agent_config(config)

    assert repo.get_agent_config("user", "USER-1") == config
    assert repo.get_agent_config("user", "USER-2") is None


# -- Secrets ----------------------------------------------------------------


def test_save_and_get_secret_blob_roundtrips(tmp_path):
    repo = _repo(tmp_path)

    repo.save_secret_blob("SECRET-1", b"ciphertext-bytes", "user:USER-1")

    assert repo.get_secret_blob("SECRET-1") == b"ciphertext-bytes"


def test_get_secret_blob_returns_none_for_unknown_ref(tmp_path):
    repo = _repo(tmp_path)

    assert repo.get_secret_blob("nope") is None


def test_delete_secret_blob_removes_it(tmp_path):
    repo = _repo(tmp_path)
    repo.save_secret_blob("SECRET-1", b"x", "user:USER-1")

    repo.delete_secret_blob("SECRET-1")

    assert repo.get_secret_blob("SECRET-1") is None


# -- Threat triage status ---------------------------------------------------


def test_threat_status_upserts_lists_per_application_and_deletes(tmp_path):
    from kresheen.models.threat import ThreatStatusRecord, threat_status_id

    repo = _repo(tmp_path)
    key = "PROC-S-01|process:API"
    status_id = threat_status_id("APP-1", key)
    assert status_id == threat_status_id("APP-1", key)
    assert status_id != threat_status_id("APP-2", key)

    def record(status, app="APP-1"):
        return ThreatStatusRecord(
            id=threat_status_id(app, key), application_id=app, threat_key=key, status=status, updated_at=_now()
        )

    repo.save_threat_status(record("mitigated"))
    repo.save_threat_status(record("accepted"))  # same id: upsert, not a second row
    repo.save_threat_status(record("mitigated", app="APP-2"))

    listed = repo.list_threat_statuses("APP-1")
    assert [r.status for r in listed] == ["accepted"]

    repo.delete_threat_status(status_id)
    assert repo.list_threat_statuses("APP-1") == []
    assert len(repo.list_threat_statuses("APP-2")) == 1
