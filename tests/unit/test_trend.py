from __future__ import annotations

from datetime import UTC, datetime

from kresheen.engine.trend import compute_trend
from kresheen.models.snapshot import ThreatSnapshot


def _snap(app: str, day: str, keys: list[str]) -> ThreatSnapshot:
    return ThreatSnapshot(
        id=f"{app}:{day}",
        application_id=app,
        day=day,
        taken_at=datetime.now(UTC),
        open_keys=keys,
        open_by_risk={"high": len(keys)},
    )


def test_first_snapshot_is_not_new_and_later_ones_diff_against_the_previous():
    points = compute_trend(
        [_snap("A", "2026-09-01", ["t1", "t2"]), _snap("A", "2026-09-02", ["t2", "t3", "t4"])]
    )
    assert [(p.day, p.open, p.new, p.resolved) for p in points] == [
        ("2026-09-01", 2, 0, 0),
        ("2026-09-02", 3, 2, 1),
    ]


def test_an_app_missing_from_a_day_is_carried_forward_not_dropped():
    points = compute_trend(
        [
            _snap("A", "2026-09-01", ["a1"]),
            _snap("B", "2026-09-01", ["b1", "b2"]),
            _snap("A", "2026-09-02", []),
        ]
    )
    assert points[1].open == 2  # A now 0, B still 2
    assert points[1].resolved == 1 and points[1].new == 0
    assert points[1].open_by_risk == {"high": 2}


def test_no_snapshots_is_an_empty_trend():
    assert compute_trend([]) == []
