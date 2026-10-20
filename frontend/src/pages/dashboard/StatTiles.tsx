import { Col, Row } from "react-bootstrap";
import { Sparkline } from "./charts";
import type { DashboardApplication, PortfolioSummary, TileKey, TrendPoint } from "./types";

function StatTile({
  testId,
  label,
  value,
  sub,
  tone,
  onClick,
  spark,
  progress,
}: {
  testId: string;
  label: string;
  value: string;
  sub: string;
  tone: string;
  onClick: () => void;
  spark?: number[];
  progress?: number;
}) {
  return (
    <button type="button" className={`pc-stat pc-tone-${tone}`} data-testid={testId} onClick={onClick}>
      <div className="pc-stat-label">
        <span className="pc-dot" />
        {label}
      </div>
      <div className="pc-stat-value">{value}</div>
      <div className="pc-stat-sub">{sub}</div>
      {progress !== undefined && (
        <div className="pc-bar-track mt-2">
          <div className="pc-bar-fill" style={{ width: `${Math.max(0, Math.min(100, progress))}%`, background: "var(--tone)" }} />
        </div>
      )}
      {spark && <Sparkline values={spark} color="var(--tone)" />}
    </button>
  );
}

function toneForPct(pct: number | null): string {
  if (pct === null) return "accent";
  if (pct >= 75) return "good";
  if (pct >= 40) return "warn";
  return "critical";
}

export function StatTiles({
  summary,
  apps,
  trend,
  onOpen,
}: {
  summary: PortfolioSummary;
  apps: DashboardApplication[];
  trend: TrendPoint[];
  onOpen: (key: TileKey) => void;
}) {
  const highCritical = (summary.open_by_risk.critical ?? 0) + (summary.open_by_risk.high ?? 0);
  const openSpark = trend.map((p) => p.open);
  const highCriticalSpark = trend.map((p) => (p.open_by_risk.critical ?? 0) + (p.open_by_risk.high ?? 0));
  // Distinct models that are stale or never reviewed (a model can be both).
  const attention = apps.filter((app) => app.stale || !app.reviewed_at).length;
  const completenessLabel = summary.avg_completeness === null ? "-" : `${Math.round(summary.avg_completeness)}%`;

  const tiles: {
    key: TileKey;
    label: string;
    value: string;
    sub: string;
    tone: string;
    spark?: number[];
    progress?: number;
  }[] = [
    {
      key: "models",
      label: "Models",
      value: String(summary.application_count),
      sub: "click to list",
      tone: "accent",
    },
    {
      key: "openThreats",
      label: "Open threats",
      value: String(summary.open_threat_count),
      sub: summary.open_threat_count ? "across all models" : "nothing outstanding",
      tone: summary.open_threat_count ? "accent2" : "good",
      spark: openSpark.length >= 2 ? openSpark : undefined,
    },
    {
      key: "highCritical",
      label: "High + critical open",
      value: String(highCritical),
      sub: highCritical ? "needs the most attention" : "none open",
      tone: highCritical ? "critical" : "good",
      spark: highCriticalSpark.length >= 2 ? highCriticalSpark : undefined,
    },
    {
      key: "addressed",
      label: "Addressed",
      value: `${Math.round(summary.addressed_pct)}%`,
      sub: summary.total_threat_count ? `${summary.addressed_count} of ${summary.total_threat_count} threats` : "no threats yet",
      tone: summary.total_threat_count ? toneForPct(summary.addressed_pct) : "accent",
      progress: summary.addressed_pct,
    },
    {
      key: "completeness",
      label: "Avg completeness",
      value: completenessLabel,
      sub: summary.avg_completeness === null ? "no completed runs" : "across models with a run",
      tone: toneForPct(summary.avg_completeness),
    },
    {
      key: "attention",
      label: "Needs attention",
      value: String(attention),
      sub: attention ? "stale or never reviewed" : "all caught up",
      tone: attention ? "warn" : "good",
    },
  ];

  return (
    <Row xs={2} md={3} xl={6} className="g-3 mb-3">
      {tiles.map((tile) => (
        <Col key={tile.key}>
          <StatTile
            testId={`dash-tile-${tile.key}`}
            label={tile.label}
            value={tile.value}
            sub={tile.sub}
            tone={tile.tone}
            spark={tile.spark}
            progress={tile.progress}
            onClick={() => onOpen(tile.key)}
          />
        </Col>
      ))}
    </Row>
  );
}
