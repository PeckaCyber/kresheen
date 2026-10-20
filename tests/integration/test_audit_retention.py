from __future__ import annotations

from datetime import UTC, datetime, timedelta

from click.testing import CliRunner

from kresheen.cli.main import cli
from kresheen.dashboard.app import create_app
from tests.integration.test_api_applications import _logged_in_client


def _seed_old_and_new(repo):
    from kresheen.models.audit import AuditEvent

    now = datetime.now(UTC)
    for i, age in enumerate((100, 40, 1)):
        repo.add_audit_event(AuditEvent(id=f"AUD-{i}", at=now - timedelta(days=age), action=f"old{age}"))


def test_prune_command_deletes_only_events_older_than_the_window(tmp_path):
    db = f"sqlite:///{tmp_path}/t.db"
    repo = create_app(db_url=db).state.repo
    _seed_old_and_new(repo)
    out = CliRunner().invoke(cli, ["audit-prune", "--days", "30", "--db", db])
    assert "Deleted 2" in out.output
    assert [e.action for e in repo.list_audit_events()] == ["old1"]


def test_env_retention_prunes_from_the_request_path(tmp_path, monkeypatch):
    monkeypatch.setenv("KRESHEEN_AUDIT_RETENTION_DAYS", "30")
    client, _ = _logged_in_client(tmp_path)
    _seed_old_and_new(client.app.state.repo)
    client.app.state.audit_last_prune = 0.0
    client.get("/api/applications")
    actions = {e.action for e in client.app.state.repo.list_audit_events(limit=50)}
    assert "old100" not in actions and "old40" not in actions and "old1" in actions


def test_no_retention_env_keeps_everything(tmp_path):
    client, _ = _logged_in_client(tmp_path)
    _seed_old_and_new(client.app.state.repo)
    client.get("/api/applications")
    assert len(client.app.state.repo.list_audit_events(limit=50)) >= 3


def test_entry_cap_drops_oldest_and_summary_reports_it(tmp_path, monkeypatch):
    monkeypatch.setattr("kresheen.dashboard.audit.DEFAULT_MAX_ENTRIES", 5)
    client, _ = _logged_in_client(tmp_path)
    repo = client.app.state.repo
    from kresheen.dashboard.audit import record_event
    from kresheen.models.audit import AuditEvent

    now = datetime.now(UTC)
    for i in range(8):
        repo.add_audit_event(AuditEvent(id=f"AUD-cap{i}", at=now - timedelta(hours=8 - i), action=f"cap{i}"))
    record_event(repo, action="newest")
    # The login row is a security event, kept in its own pool: 5 routine rows plus that one.
    assert repo.count_audit_events() == 6
    assert "cap0" not in {e.action for e in repo.list_audit_events(limit=50)}
    summary = client.get("/api/audit-log/summary").json()
    assert summary == {"count": 6, "max_entries": 5}
