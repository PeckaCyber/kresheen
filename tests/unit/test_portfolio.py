from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kresheen.engine.portfolio import (
    ApplicationPortfolioData,
    build_portfolio_summary,
)

_NOW = datetime(2026, 9, 26, tzinfo=UTC)


def _app(
    application_id: str,
    *,
    stale: bool = False,
    reviewed_at: datetime | None = None,
    total_threat_count: int = 0,
    addressed_count: int = 0,
    open_by_risk: dict[str, int] | None = None,
    completeness_score: int | None = None,
    open_action_count: int | None = None,
) -> ApplicationPortfolioData:
    return ApplicationPortfolioData(
        application_id=application_id,
        stale=stale,
        reviewed_at=reviewed_at,
        total_threat_count=total_threat_count,
        addressed_count=addressed_count,
        open_by_risk=open_by_risk or {},
        completeness_score=completeness_score,
        open_action_count=open_action_count,
    )


def test_summary_totals_across_applications():
    apps = [
        _app(
            "A",
            total_threat_count=10,
            addressed_count=4,
            open_by_risk={"high": 3, "low": 3},
            completeness_score=80,
            open_action_count=2,
        ),
        _app(
            "B",
            total_threat_count=5,
            addressed_count=1,
            open_by_risk={"high": 1},
            completeness_score=40,
            open_action_count=1,
            stale=True,
        ),
    ]

    summary = build_portfolio_summary(apps, _NOW)

    assert summary.application_count == 2
    assert summary.total_threat_count == 15
    assert summary.addressed_count == 5
    assert summary.addressed_pct == 33.3
    assert summary.open_by_risk == {"high": 4, "low": 3}
    assert summary.open_threat_count == 7
    assert summary.open_action_count == 3
    assert summary.avg_completeness == 60.0
    assert summary.stale_count == 1


def test_never_reviewed_and_reviewed_over_90_days():
    apps = [
        _app("A", reviewed_at=None),
        _app("B", reviewed_at=_NOW - timedelta(days=91)),
        _app("C", reviewed_at=_NOW - timedelta(days=10)),
    ]

    summary = build_portfolio_summary(apps, _NOW)

    assert summary.never_reviewed_count == 1
    assert summary.reviewed_over_90_days_count == 1


def test_summary_with_no_applications_has_no_average_completeness():
    summary = build_portfolio_summary([], _NOW)
    assert summary.application_count == 0
    assert summary.avg_completeness is None
    assert summary.addressed_pct == 0.0
