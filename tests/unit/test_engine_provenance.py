"""Run provenance stamp:
engine/provenance.py."""

from datetime import UTC, datetime

from kresheen.engine.orchestrator import execute_run
from kresheen.engine.provenance import (
    compute_staleness,
    engine_version,
    input_digest,
    rule_catalog_version,
)
from kresheen.models.application import Application
from kresheen.models.data_source import DataSourceConfig
from kresheen.models.threat_model_run import ThreatModelRun
from kresheen.storage.sql_repo import SQLRepository


def _source(**details) -> DataSourceConfig:
    return DataSourceConfig(
        id="DS-1", application_id="APP-1", type="github_repository",
        connection_details=details, created_at=datetime.now(UTC),
    )


def test_engine_version_is_a_non_empty_string():
    assert engine_version() and isinstance(engine_version(), str)


def test_rule_catalog_version_is_deterministic():
    assert rule_catalog_version() == rule_catalog_version()
    assert len(rule_catalog_version()) == 16


def test_input_digest_is_deterministic_for_the_same_content():
    a = _source(repo_url="https://github.com/acme/widget", ref="main")
    b = _source(repo_url="https://github.com/acme/widget", ref="main")
    assert input_digest(a) == input_digest(b)


def test_input_digest_differs_for_different_content():
    a = _source(repo_url="https://github.com/acme/widget", ref="main")
    b = _source(repo_url="https://github.com/acme/widget", ref="v2")
    assert input_digest(a) != input_digest(b)


def test_input_digest_ignores_a_rotated_token_pointed_at_the_same_content():
    """A credential isn't content: rotating it doesn't change what gets
    ingested, so the digest -- and never the raw token -- stays the same."""
    a = _source(repo_url="https://github.com/acme/widget", github_token="ghp_one")
    b = _source(repo_url="https://github.com/acme/widget", github_token="ghp_two")
    assert input_digest(a) == input_digest(b)


def test_end_to_end_a_completed_run_is_stamped(tmp_path):
    repo = SQLRepository(f"sqlite:///{tmp_path}/prov.db")
    repo.save_data_source(DataSourceConfig(
        id="DS-1", application_id="APP-1", type="manifest_upload",
        connection_details={"content": "apiVersion: v1\nkind: Namespace\nmetadata: {name: n}\n"},
        created_at=datetime.now(UTC),
    ))
    repo.save_run(ThreatModelRun(
        id="RUN-1", application_id="APP-1", triggered_by_user_id="U",
        data_source_config_ids=["DS-1"], started_at=datetime.now(UTC),
    ))
    execute_run(repo, "RUN-1")

    run = repo.get_run("RUN-1")
    assert run is not None
    assert run.engine_version == engine_version()
    assert run.rule_catalog_version == rule_catalog_version()
    assert set(run.input_digests) == {"DS-1"}
    assert len(run.input_digests["DS-1"]) == 16


def _blank_app(repo: SQLRepository) -> Application:
    app = Application(id="APP-1", name="Blank", owner_user_id="U", created_at=datetime.now(UTC), updated_at=datetime.now(UTC))
    repo.save_application(app)
    return app


def test_blank_model_is_not_stale_after_a_run(tmp_path):
    """Regression: a stamped run with zero data
    sources has an empty digest map, which must not read as 'never stamped'."""
    repo = SQLRepository(f"sqlite:///{tmp_path}/blank.db")
    app = _blank_app(repo)
    repo.save_run(ThreatModelRun(
        id="RUN-1", application_id="APP-1", triggered_by_user_id="U", started_at=datetime.now(UTC),
    ))
    execute_run(repo, "RUN-1")
    repo.save_application(app.model_copy(update={"latest_run_id": "RUN-1"}))

    assert compute_staleness(repo.get_application("APP-1"), repo).stale is False


def test_blank_model_becomes_stale_when_a_source_is_added(tmp_path):
    repo = SQLRepository(f"sqlite:///{tmp_path}/blank2.db")
    app = _blank_app(repo)
    repo.save_run(ThreatModelRun(
        id="RUN-1", application_id="APP-1", triggered_by_user_id="U", started_at=datetime.now(UTC),
    ))
    execute_run(repo, "RUN-1")
    repo.save_application(app.model_copy(update={"latest_run_id": "RUN-1"}))
    repo.save_data_source(_source(repo_url="https://github.com/acme/widget"))

    result = compute_staleness(repo.get_application("APP-1"), repo)
    assert result.stale is True and result.new_data_source_ids == ["DS-1"]


def test_unstamped_run_is_still_unconditionally_stale(tmp_path):
    repo = SQLRepository(f"sqlite:///{tmp_path}/old.db")
    app = _blank_app(repo)
    repo.save_run(ThreatModelRun(
        id="RUN-1", application_id="APP-1", triggered_by_user_id="U", status="completed",
        started_at=datetime.now(UTC),
    ))
    repo.save_application(app.model_copy(update={"latest_run_id": "RUN-1"}))

    assert compute_staleness(repo.get_application("APP-1"), repo).stale is True
