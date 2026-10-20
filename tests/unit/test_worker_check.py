import logging

import pytest
from click.testing import CliRunner

from kresheen.cli.main import cli
from kresheen.dashboard.workers import MultiWorkerError, check_worker_count, configured_worker_count


@pytest.mark.parametrize(
    "env, expected",
    [
        ({}, 1),
        ({"WEB_CONCURRENCY": "1"}, 1),
        ({"WEB_CONCURRENCY": "4"}, 4),
        ({"WEB_CONCURRENCY": "junk"}, 1),
        ({"UVICORN_WORKERS": "3"}, 3),
        ({"GUNICORN_CMD_ARGS": "--workers 5 --bind 0.0.0.0:8000"}, 5),
        ({"GUNICORN_CMD_ARGS": "-w 2"}, 2),
        ({"GUNICORN_CMD_ARGS": "--workers=6"}, 6),
        ({"GUNICORN_CMD_ARGS": "--worker-class gthread"}, 1),
        ({"WEB_CONCURRENCY": "2", "UVICORN_WORKERS": "3"}, 3),
    ],
)
def test_configured_worker_count(env, expected):
    assert configured_worker_count(env) == expected


def test_single_worker_starts_silently(caplog):
    with caplog.at_level(logging.WARNING):
        assert check_worker_count({"WEB_CONCURRENCY": "1"}) == 1
    assert not caplog.records


def test_multiple_workers_are_refused_with_an_explanation():
    with pytest.raises(MultiWorkerError) as exc:
        check_worker_count({"WEB_CONCURRENCY": "3"})
    assert "per process" in str(exc.value) or "each process" in str(exc.value)
    assert "KRESHEEN_ALLOW_MULTI_WORKER=1" in str(exc.value)


@pytest.mark.parametrize("value", ["0", "", "no", "2"])
def test_only_an_explicit_opt_in_allows_it(value):
    with pytest.raises(MultiWorkerError):
        check_worker_count({"WEB_CONCURRENCY": "3", "KRESHEEN_ALLOW_MULTI_WORKER": value})


def test_opt_in_logs_a_warning(caplog):
    with caplog.at_level(logging.WARNING):
        assert check_worker_count({"WEB_CONCURRENCY": "3", "KRESHEEN_ALLOW_MULTI_WORKER": "1"}) == 3
    assert any("per process" in record.getMessage() for record in caplog.records)


def test_serve_refuses_to_start_with_several_workers(tmp_path, monkeypatch):
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    monkeypatch.delenv("KRESHEEN_ALLOW_MULTI_WORKER", raising=False)
    result = CliRunner().invoke(cli, ["serve", "--db", f"sqlite:///{tmp_path}/t.db"])
    assert result.exit_code != 0
    assert "KRESHEEN_ALLOW_MULTI_WORKER=1" in result.output
