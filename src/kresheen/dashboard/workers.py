"""Refuse to start with several worker processes unless the operator accepts a weaker sign-in throttle.

The failed-login throttle (`login_throttle.py`) lives in process memory, so with N workers each keeps its own counts
and an attacker gets roughly N times the attempts before being slowed. Until the throttle has a shared store, running
more than one process needs `KRESHEEN_ALLOW_MULTI_WORKER=1`, which logs a warning at every start.

What is detected (`configured_worker_count`): `WEB_CONCURRENCY` (read by uvicorn and gunicorn), `UVICORN_WORKERS`, and
`-w N` / `--workers N` inside `GUNICORN_CMD_ARGS`. What is not: a worker count given only on a command line
(`gunicorn -w 4 ...`, `uvicorn --workers 4 ...`) is not visible to the application, nor are several containers or
Kubernetes replicas behind one load balancer (the Helm chart refuses `replicaCount` above 1 on its own). Anyone
launching the app with their own process manager must set `KRESHEEN_ALLOW_MULTI_WORKER` deliberately and know that the
throttle is then per process.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping

logger = logging.getLogger(__name__)

ALLOW_ENV = "KRESHEEN_ALLOW_MULTI_WORKER"
_GUNICORN_WORKERS = re.compile(r"(?:^|\s)(?:-w|--workers)(?:\s+|=)(\d+)")


class MultiWorkerError(RuntimeError):
    """More than one worker is configured and the operator has not accepted the weaker throttle."""


def _as_int(value: str | None) -> int:
    try:
        return int((value or "").strip())
    except ValueError:
        return 0


def configured_worker_count(env: Mapping[str, str] | None = None) -> int:
    """The largest worker count the environment asks for (1 when none is set)."""
    env = os.environ if env is None else env
    counts = [_as_int(env.get("WEB_CONCURRENCY")), _as_int(env.get("UVICORN_WORKERS"))]
    counts += [int(match) for match in _GUNICORN_WORKERS.findall(env.get("GUNICORN_CMD_ARGS", ""))]
    return max([1, *counts])


def check_worker_count(env: Mapping[str, str] | None = None) -> int:
    """Raise `MultiWorkerError` for more than one worker unless allowed; log a warning when allowed. Returns the count."""
    env = os.environ if env is None else env
    count = configured_worker_count(env)
    if count <= 1:
        return count
    if env.get(ALLOW_ENV, "").strip().lower() not in ("1", "true", "yes"):
        raise MultiWorkerError(
            f"{count} worker processes are configured (WEB_CONCURRENCY or similar), but the sign-in throttle is kept "
            f"in each process's memory, so every worker counts failed logins separately and the limit is weakened "
            f"about {count} times. Run one worker, or set {ALLOW_ENV}=1 to accept that."
        )
    logger.warning(
        "%d worker processes configured and %s is set: the sign-in throttle is per process, so the effective limit "
        "is about %d times the configured one.", count, ALLOW_ENV, count,
    )
    return count
