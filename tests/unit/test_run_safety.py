import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.exc import OperationalError

from kresheen.engine import run_safety as rs
from kresheen.models.threat_model_run import ThreatModelRun
from kresheen.storage.sql_repo import SQLRepository


def _run(status="ingesting", age_minutes=0.0, rid="RUN-x"):
    return ThreatModelRun(id=rid, application_id="A", triggered_by_user_id="U", data_source_config_ids=[],
                          status=status, started_at=datetime.now(UTC) - timedelta(minutes=age_minutes))


def test_database_errors_never_expose_sql_or_parameters():
    exc = OperationalError("INSERT INTO fact_nodes (id) VALUES (?)", ("FACT-N-1",), Exception("database is locked"))
    msg = rs.safe_run_error(exc)
    assert "INSERT" not in msg and "FACT-N" not in msg and "locked" not in msg


def test_paths_are_stripped_and_messages_bounded():
    assert "/tmp/kresheen-ghrepo-abc" not in rs.safe_run_error(ValueError("bad file /tmp/kresheen-ghrepo-abc/x.yaml here"))
    assert "<path>" in rs.safe_run_error(ValueError("bad file /tmp/kresheen-ghrepo-abc/x.yaml here"))
    assert "/tmp" not in rs.safe_run_error(OSError(36, "File name too long: '/tmp/x/y'"))
    assert len(rs.safe_run_error(ValueError("x" * 5000))) <= 300
    assert rs.safe_run_error(ValueError("while scanning a plain scalar\n  in line 3")) == "while scanning a plain scalar in line 3"
    assert "nested" in rs.safe_run_error(RecursionError("maximum recursion depth exceeded"))


def test_save_run_reliably_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr(rs.time, "sleep", lambda _s: None)
    calls = []

    class Repo:
        def save_run(self, run):
            calls.append(1)
            if len(calls) < 3:
                raise RuntimeError("locked")

    rs.save_run_reliably(Repo(), _run())
    assert len(calls) == 3


def test_save_run_reliably_gives_up_and_raises(monkeypatch):
    monkeypatch.setattr(rs.time, "sleep", lambda _s: None)

    class Repo:
        def save_run(self, run):
            raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        rs.save_run_reliably(Repo(), _run(), attempts=3)


def test_stale_runs_are_failed_and_fresh_or_finished_ones_are_left_alone(tmp_path):
    repo = SQLRepository(f"sqlite:///{tmp_path}/r.db")
    repo.save_run(_run("ingesting", age_minutes=60, rid="RUN-old"))
    repo.save_run(_run("reasoning", age_minutes=60, rid="RUN-old2"))
    repo.save_run(_run("ingesting", age_minutes=1, rid="RUN-fresh"))
    repo.save_run(_run("completed", age_minutes=600, rid="RUN-done"))
    assert rs.reconcile_stale_runs(repo) == 2
    assert repo.get_run("RUN-old").status == "failed" and "interrupted" in repo.get_run("RUN-old").error_message
    assert repo.get_run("RUN-old").completed_at is not None
    assert repo.get_run("RUN-fresh").status == "ingesting"
    assert repo.get_run("RUN-done").status == "completed"
    assert rs.reconcile_stale_runs(repo) == 0  # idempotent


def test_gate_bounds_concurrency_and_refuses_when_the_queue_is_full():
    gate = rs.RunGate(max_running=2, max_waiting=1)
    live = {"now": 0, "max": 0}
    lock = threading.Lock()
    release = threading.Event()
    refused = []

    def work():
        try:
            with gate.slot():
                with lock:
                    live["now"] += 1
                    live["max"] = max(live["max"], live["now"])
                release.wait(2)
                with lock:
                    live["now"] -= 1
        except rs.RunQueueFull:
            refused.append(1)

    threads = [threading.Thread(target=work) for _ in range(6)]
    for t in threads:
        t.start()
        time.sleep(0.05)
    time.sleep(0.2)
    release.set()
    for t in threads:
        t.join()
    assert live["max"] <= 2
    assert len(refused) == 3  # 2 running + 1 waiting accepted, 3 refused


def test_data_source_label_prefers_filename_or_repo_and_hides_credentials():
    from kresheen.engine.run_safety import data_source_label, source_run_error

    assert data_source_label("manifest_upload", {"filename": "a.yaml"}) == "a.yaml"
    assert data_source_label("manifest_upload", {"content": "secret"}) == "manifest upload"
    assert data_source_label("github_repository", {"repo_url": "https://tok:x@github.com/o/r"}) == "https://github.com/o/r"
    assert data_source_label("manifest_upload", {"filename": 'we"ird\nname'}) == "we'ird name"
    assert len(data_source_label("manifest_upload", {"filename": "n" * 500})) <= 80
    assert source_run_error("a.yaml", MemoryError()) == 'Could not read data source "a.yaml": The input was too large to process.'
