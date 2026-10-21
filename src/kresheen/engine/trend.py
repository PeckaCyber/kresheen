"""Threat trend over time, from daily `ThreatSnapshot`s (models/snapshot.py).

Pure functions: the route decides which applications a user may see and hands
their snapshots in.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from kresheen.engine.threats.service import UnknownRunError
from kresheen.engine.threats.view import build_threats_out
from kresheen.models.snapshot import ThreatSnapshot
from kresheen.storage.repository import Repository

logger = logging.getLogger(__name__)


class TrendPoint(BaseModel):
    day: str
    open: int
    new: int
    resolved: int
    open_by_risk: dict[str, int] = Field(default_factory=dict)


def make_snapshot(application_id: str, open_keys: list[str], open_by_risk: dict[str, int]) -> ThreatSnapshot:
    now = datetime.now(UTC)
    day = now.date().isoformat()
    return ThreatSnapshot(
        id=f"{application_id}:{day}",
        application_id=application_id,
        day=day,
        taken_at=now,
        open_keys=sorted(open_keys),
        open_by_risk=open_by_risk,
    )


def record_snapshot(repo: Repository, application_id: str) -> None:
    """Upsert today's `ThreatSnapshot` for one application, so the trend has
    history from whenever the data actually changes (a completed run, a
    threat status change) and not only from a dashboard load.

    Never raises: a failure to snapshot must not fail the run or the status
    change that triggered it (D3). Skips silently if the application or its
    latest run can't be found -- nothing to snapshot yet."""
    try:
        application = repo.get_application(application_id)
        if application is None or application.latest_run_id is None:
            return
        run = repo.get_run(application.latest_run_id)
        if run is None:
            return
        out = build_threats_out(application_id, run.id, repo, use_cache=False)
        open_keys = [t.key for t in out.threats if t.status == "open"]
        repo.save_threat_snapshot(make_snapshot(application_id, open_keys, out.summary.open_by_risk))
    except UnknownRunError:
        pass
    except Exception:
        logger.exception("Could not record threat snapshot for application %r", application_id)


def compute_trend(snapshots: list[ThreatSnapshot]) -> list[TrendPoint]:
    """One point per day that has any snapshot. `open` carries each
    application's latest state forward, so a day on which one application was
    not snapshotted still counts it. `new`/`resolved` compare an application's
    snapshot with its own previous one; an application's first snapshot has
    nothing to compare against and contributes to neither."""
    by_app: dict[str, list[ThreatSnapshot]] = defaultdict(list)
    for snap in sorted(snapshots, key=lambda s: s.day):
        by_app[snap.application_id].append(snap)

    days = sorted({s.day for s in snapshots})
    points: list[TrendPoint] = []
    for day in days:
        open_total = 0
        risk_total: dict[str, int] = defaultdict(int)
        new = resolved = 0
        for snaps in by_app.values():
            current = None
            previous = None
            for snap in snaps:
                if snap.day > day:
                    break
                previous, current = current, snap
            if current is None:
                continue
            open_total += len(current.open_keys)
            for risk, count in current.open_by_risk.items():
                risk_total[risk] += count
            if current.day == day and previous is not None:
                before, after = set(previous.open_keys), set(current.open_keys)
                new += len(after - before)
                resolved += len(before - after)
        points.append(
            TrendPoint(day=day, open=open_total, new=new, resolved=resolved, open_by_risk=dict(risk_total))
        )
    return points
