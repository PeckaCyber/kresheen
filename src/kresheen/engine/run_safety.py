"""Keeping a run's recorded outcome honest and bounded.

Three problems found by the robustness tests:
- A failed run stored `str(exc)`, which for database errors is the SQL statement and its bound
  parameters and for file errors is a server temp path, and that text is returned to the client.
- A run could be left `ingesting` forever (the failure handler's own write hit the same database lock; or
  the process was killed mid-run) and nothing ever moved it on.
- Runs execute inside the request, so any number could start at once and fight over the database.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import SQLAlchemyError

from kresheen.models.threat_model_run import ThreatModelRun
from kresheen.storage.repository import Repository

logger = logging.getLogger(__name__)

NON_TERMINAL = ("queued", "ingesting", "reasoning")
_PATH = re.compile(r"(/(?:tmp|var|home|usr|app|opt|root)/[^\s'\"):,]+)")
_MAX_LEN = 300


def safe_run_error(exc: BaseException) -> str:
    """A message safe to store and show: no SQL, parameters, or server paths. Details stay in the server log."""
    if isinstance(exc, SQLAlchemyError):
        return (
            "A database error interrupted this run. Please run it again; if it keeps happening, check the server log."
        )
    if isinstance(exc, MemoryError):
        return "The input was too large to process."
    if isinstance(exc, RecursionError):
        return "The input is nested too deeply to process."
    if isinstance(exc, OSError):
        return "A file could not be read or written while processing this source."
    text = _PATH.sub("<path>", str(exc)).strip().splitlines()[0:6]
    message = " ".join(line.strip() for line in text if line.strip()) or type(exc).__name__
    return message[:_MAX_LEN]


_TYPE_LABELS = {
    "manifest_upload": "manifest upload",
    "github_repository": "GitHub repository",
    "architecture_diagram": "architecture diagram",
    "documentation": "documentation",
}
_MAX_LABEL = 80


def data_source_label(source_type: str, details: dict) -> str:
    """A short, safe name for a data source: its file name or repository, else its type. Never content or tokens."""
    raw = details.get("repo_url") if source_type == "github_repository" else details.get("filename")
    text = raw if isinstance(raw, str) else ""
    text = re.sub(r"^(\w+://)[^/@\s]*@", r"\1", text)  # drop any credentials in a URL
    text = _PATH.sub("<path>", " ".join(text.split())).replace('"', "'")
    if len(text) > _MAX_LABEL:
        text = text[: _MAX_LABEL - 3] + "..."
    return text or _TYPE_LABELS.get(source_type, source_type.replace("_", " "))


def source_run_error(label: str, exc: BaseException) -> str:
    """The stored message when reading one data source failed: names the source, keeps the sanitised detail."""
    return f'Could not read data source "{label}": {safe_run_error(exc)}'


def save_run_reliably(repo: Repository, run: ThreatModelRun, *, attempts: int = 6) -> None:
    """Save a run's terminal state, retrying: if this write is lost the run stays non-terminal forever."""
    delay = 0.25
    for attempt in range(attempts):
        try:
            repo.save_run(run)
            return
        except Exception:
            if attempt == attempts - 1:
                logger.exception("Could not record the final state of run %s", run.id)
                raise
            time.sleep(delay)
            delay = min(delay * 2, 4.0)


def stale_run_after() -> timedelta:
    try:
        minutes = float(os.environ.get("KRESHEEN_STALE_RUN_MINUTES", "10"))
    except ValueError:
        minutes = 10.0
    return timedelta(minutes=max(minutes, 0.1))


INTERRUPTED_MESSAGE = "This run was interrupted (the server stopped or restarted while it was running). Run it again."


def reconcile_run(repo: Repository, run: ThreatModelRun, *, now: datetime | None = None) -> ThreatModelRun:
    """Mark a run that has been non-terminal for longer than any real run takes as failed. Idempotent."""
    if run.status not in NON_TERMINAL:
        return run
    now = now or datetime.now(UTC)
    started = run.started_at if run.started_at.tzinfo else run.started_at.replace(tzinfo=UTC)
    if now - started < stale_run_after():
        return run
    previous_status = run.status
    run.status = "failed"
    run.error_message = INTERRUPTED_MESSAGE
    run.completed_at = now
    try:
        repo.save_run(run)
        logger.warning("Marked run %s as failed: it was still %s after %s", run.id, previous_status, stale_run_after())
    except Exception:
        logger.exception("Could not mark stale run %s as failed", run.id)
    return run


def reconcile_stale_runs(repo: Repository) -> int:
    """Startup sweep. Returns how many runs were marked failed."""
    count = 0
    for run in repo.list_runs_with_status(NON_TERMINAL):
        if reconcile_run(repo, run).status == "failed":
            count += 1
    return count


class RunQueueFull(Exception):
    pass


class RunGate:
    """At most `max_running` runs execute at once; up to `max_waiting` more wait; beyond that the request is
    refused so a burst cannot tie up every worker thread (or the database) with queued work."""

    def __init__(self, max_running: int | None = None, max_waiting: int | None = None) -> None:
        self.max_running = max_running or _env_int("KRESHEEN_MAX_CONCURRENT_RUNS", 2)
        self.max_waiting = max_waiting if max_waiting is not None else _env_int("KRESHEEN_MAX_QUEUED_RUNS", 6)
        self._slots = threading.BoundedSemaphore(self.max_running)
        self._lock = threading.Lock()
        self._waiting = 0

    @contextmanager
    def slot(self) -> Iterator[None]:
        if not self._slots.acquire(blocking=False):
            with self._lock:
                if self._waiting >= self.max_waiting:
                    raise RunQueueFull
                self._waiting += 1
            try:
                self._slots.acquire()
            finally:
                with self._lock:
                    self._waiting -= 1
        try:
            yield
        finally:
            self._slots.release()


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default
