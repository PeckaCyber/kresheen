"""Portfolio-level aggregation for the executive dashboard (D2).

Pure functions over data the route (`dashboard/routes/api_dashboard.py`) has
already built per application (a `ThreatsOut`, an `ActionPlanOut`, a
completeness score) -- nothing here re-derives threats itself, so it stays
cheap and unit-testable without HTTP. `ApplicationPortfolioData` is the one
piece of input shape both the route and the tests build.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel, Field

Risk = Literal["critical", "high", "medium", "low"]
NEVER_REVIEWED_AFTER_DAYS = 90


class ApplicationPortfolioData(BaseModel):
    """One application's contribution to the portfolio-wide rollups below."""

    application_id: str
    stale: bool = False
    reviewed_at: datetime | None = None
    total_threat_count: int = 0
    addressed_count: int = 0
    open_by_risk: dict[str, int] = Field(default_factory=dict)
    open_by_category: dict[str, int] = Field(default_factory=dict)
    completeness_score: int | None = None
    open_action_count: int | None = None


class PortfolioSummary(BaseModel):
    application_count: int = 0
    open_threat_count: int = 0
    total_threat_count: int = 0
    addressed_count: int = 0
    addressed_pct: float = 0.0
    open_by_risk: dict[str, int] = Field(default_factory=dict)
    open_by_category: dict[str, int] = Field(default_factory=dict)
    open_action_count: int = 0
    avg_completeness: float | None = None
    stale_count: int = 0
    never_reviewed_count: int = 0
    reviewed_over_90_days_count: int = 0


def build_portfolio_summary(apps: list[ApplicationPortfolioData], now: datetime) -> PortfolioSummary:
    total_threat_count = sum(a.total_threat_count for a in apps)
    addressed_count = sum(a.addressed_count for a in apps)
    open_by_risk: dict[str, int] = {}
    open_by_category: dict[str, int] = {}
    for app in apps:
        for risk, count in app.open_by_risk.items():
            open_by_risk[risk] = open_by_risk.get(risk, 0) + count
        for category, count in app.open_by_category.items():
            open_by_category[category] = open_by_category.get(category, 0) + count

    completeness_scores = [a.completeness_score for a in apps if a.completeness_score is not None]
    never_reviewed = sum(1 for a in apps if a.reviewed_at is None)
    over_90_days = sum(
        1
        for a in apps
        if a.reviewed_at is not None and (now - a.reviewed_at) > timedelta(days=NEVER_REVIEWED_AFTER_DAYS)
    )

    return PortfolioSummary(
        application_count=len(apps),
        open_threat_count=sum(open_by_risk.values()),
        total_threat_count=total_threat_count,
        addressed_count=addressed_count,
        addressed_pct=round(100 * addressed_count / total_threat_count, 1) if total_threat_count else 0.0,
        open_by_risk=open_by_risk,
        open_by_category=open_by_category,
        open_action_count=sum(a.open_action_count or 0 for a in apps),
        avg_completeness=round(sum(completeness_scores) / len(completeness_scores), 1)
        if completeness_scores
        else None,
        stale_count=sum(1 for a in apps if a.stale),
        never_reviewed_count=never_reviewed,
        reviewed_over_90_days_count=over_90_days,
    )


