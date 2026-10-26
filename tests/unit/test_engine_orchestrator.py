import json
from datetime import UTC, datetime

import pytest

from kresheen.engine.orchestrator import execute_run
from kresheen.models.data_source import DataSourceConfig
from kresheen.models.threat_model_run import ThreatModelRun
from kresheen.storage.sql_repo import SQLRepository

# `manifest_upload` is the orchestrator's representative "one working ingestor" case.
_ONE_DATA_STORE_MANIFEST = json.dumps(
    {
        "resource_changes": [
            {
                "address": "aws_db_instance.main",
                "type": "aws_db_instance",
                "name": "main",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["create"], "after": {"publicly_accessible": True}},
            }
        ]
    }
)


def _repo(tmp_path) -> SQLRepository:
    return SQLRepository(f"sqlite:///{tmp_path}/test.db")


def test_execute_run_end_to_end_with_a_manifest_upload_source(tmp_path):
    repo = _repo(tmp_path)
    ds = DataSourceConfig(
        id="DS-1",
        application_id="APP-1",
        type="manifest_upload",
        connection_details={"content": _ONE_DATA_STORE_MANIFEST},
        created_at=datetime.now(UTC),
    )
    repo.save_data_source(ds)
    run = ThreatModelRun(
        id="RUN-1",
        application_id="APP-1",
        triggered_by_user_id="USER-1",
        data_source_config_ids=["DS-1"],
        started_at=datetime.now(UTC),
    )
    repo.save_run(run)

    execute_run(repo, "RUN-1")

    completed = repo.get_run("RUN-1")
    assert completed.status == "completed"
    assert completed.completed_at is not None

    assets = repo.list_assets_for_run("RUN-1")
    assert len(assets) == 1
    assert all(a.source == "threat_model_run" for a in assets)

    ds_after = repo.get_data_source("DS-1")
    assert ds_after.last_ingested_at is not None


def test_execute_run_marks_failed_and_reraises_on_ingestor_error(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    repo.save_data_source(
        DataSourceConfig(
            id="DS-1",
            application_id="APP-1",
            type="manifest_upload",
            connection_details={"content": _ONE_DATA_STORE_MANIFEST},
            created_at=datetime.now(UTC),
        )
    )
    run = ThreatModelRun(
        id="RUN-1",
        application_id="APP-1",
        triggered_by_user_id="USER-1",
        data_source_config_ids=["DS-1"],
        started_at=datetime.now(UTC),
    )
    repo.save_run(run)

    def _boom(*args, **kwargs):
        raise RuntimeError("ingestion exploded")

    monkeypatch.setattr("kresheen.engine.orchestrator.ManifestUploadIngestor.run", _boom)

    with pytest.raises(RuntimeError, match="ingestion exploded"):
        execute_run(repo, "RUN-1")

    failed = repo.get_run("RUN-1")
    assert failed.status == "failed"
    assert failed.error_message == 'Could not read data source "manifest upload": ingestion exploded'


def test_failed_run_names_the_data_source_by_filename_without_paths_or_tokens(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    repo.save_data_source(
        DataSourceConfig(
            id="DS-1",
            application_id="APP-1",
            type="manifest_upload",
            connection_details={"content": "x", "filename": "bad-deploy.yaml"},
            created_at=datetime.now(UTC),
        )
    )
    repo.save_run(
        ThreatModelRun(
            id="RUN-1",
            application_id="APP-1",
            triggered_by_user_id="USER-1",
            data_source_config_ids=["DS-1"],
            started_at=datetime.now(UTC),
        )
    )

    def _boom(*args, **kwargs):
        raise ValueError("bad yaml at /tmp/secret/dir/file.yaml line 3")

    monkeypatch.setattr("kresheen.engine.orchestrator.ManifestUploadIngestor.run", _boom)
    with pytest.raises(ValueError):
        execute_run(repo, "RUN-1")

    message = repo.get_run("RUN-1").error_message
    assert message == 'Could not read data source "bad-deploy.yaml": bad yaml at <path> line 3'


def test_execute_run_skips_unregistered_data_source_type(tmp_path):
    """ "container_image" is a valid schema value (DataSourceConfig.type) but has no
    entry in `_INGESTORS` -- the orchestrator should skip it (with a warning), not crash."""
    repo = _repo(tmp_path)
    repo.save_data_source(
        DataSourceConfig(id="DS-1", application_id="APP-1", type="container_image", created_at=datetime.now(UTC))
    )
    run = ThreatModelRun(
        id="RUN-1",
        application_id="APP-1",
        triggered_by_user_id="USER-1",
        data_source_config_ids=["DS-1"],
        started_at=datetime.now(UTC),
    )
    repo.save_run(run)

    execute_run(repo, "RUN-1")

    completed = repo.get_run("RUN-1")
    assert completed.status == "completed"
    assert repo.list_findings(run_id="RUN-1") == []


def test_execute_run_raises_for_unknown_run_id(tmp_path):
    repo = _repo(tmp_path)

    with pytest.raises(ValueError, match="Unknown run"):
        execute_run(repo, "does-not-exist")
