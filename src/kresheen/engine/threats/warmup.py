"""Fill the threats cache in the background after the server starts, so the first visitor to a list page does not
wait for every model to be regenerated. Sequential, with a short pause between models so it
yields to real requests, and it never raises. `KRESHEEN_WARM_THREATS=0` turns it off."""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable

from kresheen.engine.threats.service import UnknownRunError
from kresheen.engine.threats.view import build_threats_out
from kresheen.storage.repository import Repository

logger = logging.getLogger(__name__)


def warm_threats_cache(repo: Repository, *, pause: float = 0.05, extra: Callable | None = None) -> int:
    """Returns how many models were warmed. `extra(application, run, threats_out)` warms anything else a list page
    caches per model (the dashboard's completeness score and action plan)."""
    warmed = 0
    for application in repo.list_applications():
        if not application.latest_run_id:
            continue
        try:
            out = build_threats_out(application.id, application.latest_run_id, repo)
            if extra is not None:
                run = repo.get_run(application.latest_run_id)
                if run is not None:
                    extra(application, run, out)
            warmed += 1
        except UnknownRunError:
            pass
        except Exception:
            logger.exception("Could not warm the threats cache for application %s", application.id)
        time.sleep(pause)
    return warmed


def start_warmup(repo: Repository) -> threading.Thread | None:
    if os.environ.get("KRESHEEN_WARM_THREATS", "1") == "0":
        return None
    # Lazy: the dashboard package imports the engine.
    from kresheen.dashboard.routes.api_dashboard import _completeness_and_plan

    def work() -> None:
        started = time.monotonic()
        count = warm_threats_cache(
            repo,
            extra=lambda application, run, out: _completeness_and_plan(application.id, run, out, repo),
        )
        logger.info("Warmed the threats cache for %d models in %.1f s", count, time.monotonic() - started)

    thread = threading.Thread(target=work, name="threats-cache-warmup", daemon=True)
    thread.start()
    return thread
