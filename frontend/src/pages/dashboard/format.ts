// Small, pure formatting helpers shared by the dashboard panels. Kept apart
// from the components so they're trivially unit-testable.

import { worseOf } from "../threatSignal";
import type { DashboardApplication } from "./types";

export function appLink(app: DashboardApplication): string {
  return app.latest_run_id ? `/applications/${app.id}/runs/${app.latest_run_id}` : "/applications";
}

export function worst(app: DashboardApplication): string | null {
  return worseOf(app.worst_severity, app.worst_threat_risk);
}

export function groupNameOf(app: DashboardApplication): string {
  return app.group_name ?? "Ungrouped";
}

// "today" / "3 days" -- used where the age itself is the point (stale badges).
export function ageLabel(days: number | null): string {
  if (days === null) return "never run";
  if (days === 0) return "today";
  return `${days} day${days === 1 ? "" : "s"}`;
}

// "3 days ago" -- used in the Needs attention table's "last run" column.
export function lastRunAgo(days: number | null): string {
  if (days === null) return "never run";
  if (days === 0) return "today";
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

export function reviewedLabel(reviewedAt: string | null): string {
  if (!reviewedAt) return "never";
  const parsed = new Date(reviewedAt);
  if (Number.isNaN(parsed.getTime())) return "never";
  return parsed.toLocaleDateString();
}

export function completenessLabel(score: number | null): string {
  return score === null ? "-" : `${score}%`;
}

// A count/total share as a percent, rendering "<1%" for a non-zero share
// that would otherwise round down to "0%" (so a single lonely threat never
// reads as "nothing to see here").
export function pctLabel(count: number, total: number): string {
  if (total <= 0 || count <= 0) return "0%";
  const pct = (count / total) * 100;
  const rounded = Math.round(pct);
  if (rounded === 0) return "<1%";
  return `${rounded}%`;
}

export function addressedPctLabel(app: DashboardApplication): string {
  if (app.total_threat_count <= 0) return "-";
  return pctLabel(app.addressed_count, app.total_threat_count);
}

// Relative time for the recent-activity feed. `now` is injectable for tests.
export function relativeTime(at: string, now: number = Date.now()): string {
  const then = new Date(at).getTime();
  if (Number.isNaN(then)) return at;
  const diffSec = Math.max(0, Math.round((now - then) / 1000));
  if (diffSec < 60) return "just now";
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin} minute${diffMin === 1 ? "" : "s"} ago`;
  const diffHour = Math.round(diffMin / 60);
  if (diffHour < 24) return `${diffHour} hour${diffHour === 1 ? "" : "s"} ago`;
  const diffDay = Math.round(diffHour / 24);
  if (diffDay < 30) return `${diffDay} day${diffDay === 1 ? "" : "s"} ago`;
  return new Date(at).toLocaleDateString();
}

// Splits a dashboard "<methodology>:<category>" key back into its parts.
export function splitCategoryKey(key: string): { methodology: string; category: string } {
  const index = key.indexOf(":");
  if (index === -1) return { methodology: "", category: key };
  return { methodology: key.slice(0, index), category: key.slice(index + 1) };
}
