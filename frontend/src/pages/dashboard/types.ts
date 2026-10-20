// Shared types for the executive-summary dashboard. Mirrors
// `dashboard/routes/api_dashboard.py::DashboardOut` and the models it embeds
// (`engine/portfolio.py`, `engine/trend.py`) field-for-field.

export interface DashboardApplication {
  id: string;
  name: string;
  group_id: string | null;
  group_name: string | null;
  latest_run_id: string | null;
  worst_severity: string | null;
  finding_count: number;
  open_threat_count: number;
  worst_threat_risk: string | null;
  not_analysed: boolean;
  stale: boolean;
  days_since_run: number | null;
  addressed_count: number;
  total_threat_count: number;
  open_by_risk: Record<string, number>;
  // Key is "<methodology>:<category>".
  open_by_category: Record<string, number>;
  completeness_score: number | null;
  reviewed_at: string | null;
  open_action_count: number | null;
}

export interface TrendPoint {
  day: string;
  open: number;
  new: number;
  resolved: number;
  open_by_risk: Record<string, number>;
}

export interface PortfolioSummary {
  application_count: number;
  open_threat_count: number;
  total_threat_count: number;
  addressed_count: number;
  addressed_pct: number;
  open_by_risk: Record<string, number>;
  open_by_category: Record<string, number>;
  open_action_count: number;
  avg_completeness: number | null;
  stale_count: number;
  never_reviewed_count: number;
  reviewed_over_90_days_count: number;
}

export interface RecentActivityItem {
  at: string;
  actor: string | null;
  action: string;
  target: string;
}

export interface DashboardOut {
  applications: DashboardApplication[];
  trend: TrendPoint[];
  summary: PortfolioSummary;
  recent_activity: RecentActivityItem[];
  /** Extra data from plugins, keyed by plugin name. */
  extensions?: Record<string, unknown>;
}

export const EMPTY_SUMMARY: PortfolioSummary = {
  application_count: 0,
  open_threat_count: 0,
  total_threat_count: 0,
  addressed_count: 0,
  addressed_pct: 0,
  open_by_risk: {},
  open_by_category: {},
  open_action_count: 0,
  avg_completeness: null,
  stale_count: 0,
  never_reviewed_count: 0,
  reviewed_over_90_days_count: 0,
};

export type TileKey = "models" | "openThreats" | "highCritical" | "addressed" | "completeness" | "attention";

export const RANGE_OPTIONS: { label: string; days: number }[] = [
  { label: "7d", days: 7 },
  { label: "30d", days: 30 },
  { label: "90d", days: 90 },
  { label: "All", days: 365 },
];
