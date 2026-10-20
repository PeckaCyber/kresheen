import { useMemo } from "react";
import { Link } from "react-router-dom";
import { appLink } from "./format";
import type { DashboardApplication, PortfolioSummary } from "./types";

export function ReviewStatusPanel({ apps, summary }: { apps: DashboardApplication[]; summary: PortfolioSummary }) {
  const neverReviewed = useMemo(() => apps.filter((a) => a.reviewed_at === null).slice(0, 5), [apps]);
  const recentlyReviewed = Math.max(
    0,
    summary.application_count - summary.never_reviewed_count - summary.reviewed_over_90_days_count,
  );

  return (
    <section className="pc-panel h-100" aria-label="Review status">
      <div className="pc-panel-head">
        <span>Review status</span>
      </div>
      <div className="pc-panel-body">
        <ul className="list-unstyled mb-3 small">
          <li className="d-flex justify-content-between py-1">
            <span>
              <span className="pc-dot pc-tone-critical" />
              Never reviewed
            </span>
            <strong>{summary.never_reviewed_count}</strong>
          </li>
          <li className="d-flex justify-content-between py-1">
            <span>
              <span className="pc-dot pc-tone-warn" />
              Reviewed over 90 days ago
            </span>
            <strong>{summary.reviewed_over_90_days_count}</strong>
          </li>
          <li className="d-flex justify-content-between py-1">
            <span>
              <span className="pc-dot pc-tone-good" />
              Recently reviewed
            </span>
            <strong>{recentlyReviewed}</strong>
          </li>
        </ul>
        {neverReviewed.length > 0 && (
          <>
            <div className="text-muted small mb-1">Never reviewed:</div>
            <ul className="list-unstyled mb-0 small">
              {neverReviewed.map((app) => (
                <li key={app.id} className="py-1">
                  <Link to={appLink(app)}>{app.name}</Link>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </section>
  );
}
