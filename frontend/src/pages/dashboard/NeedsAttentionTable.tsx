import { useMemo } from "react";
import { Badge, Table } from "react-bootstrap";
import { Link } from "react-router-dom";
import { RiskBadge } from "../../components/RiskBadge";
import { SEVERITY_ORDER } from "../../severity";
import { addressedPctLabel, appLink, completenessLabel, groupNameOf, lastRunAgo, reviewedLabel, worst } from "./format";
import type { DashboardApplication } from "./types";

function rank(s: string | null): number {
  if (s === null) return SEVERITY_ORDER.length;
  const index = SEVERITY_ORDER.indexOf(s as (typeof SEVERITY_ORDER)[number]);
  return index === -1 ? SEVERITY_ORDER.length : index;
}

export function NeedsAttentionTable({ apps }: { apps: DashboardApplication[] }) {
  const rows = useMemo(
    () => [...apps].sort((a, b) => rank(worst(a)) - rank(worst(b)) || b.open_threat_count - a.open_threat_count),
    [apps],
  );

  return (
    <section className="pc-panel" aria-label="Needs attention">
      <div className="pc-panel-head">
        <span>Needs attention</span>
        <span className="fw-normal text-lowercase">every model, worst risk first</span>
      </div>
      <div className="pc-panel-body">
        {rows.length === 0 ? (
          <p className="text-muted small mb-0">No applications yet.</p>
        ) : (
          <Table size="sm" hover responsive className="small align-middle mb-0">
            <thead>
              <tr>
                <th>Model</th>
                <th>Group</th>
                <th>Worst risk</th>
                <th>Open</th>
                <th>Addressed</th>
                <th>Completeness</th>
                <th>Last run</th>
                <th>Reviewed</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((app) => (
                <tr key={app.id}>
                  <td>
                    <Link to={appLink(app)}>{app.name}</Link>{" "}
                    {app.stale && (
                      <Badge bg="warning" text="dark">
                        stale
                      </Badge>
                    )}{" "}
                    {app.not_analysed && <Badge bg="secondary">not analysed</Badge>}
                  </td>
                  <td>{groupNameOf(app)}</td>
                  <td>{worst(app) ? <RiskBadge level={worst(app)!}>{worst(app)}</RiskBadge> : "none"}</td>
                  <td>{app.open_threat_count}</td>
                  <td>{addressedPctLabel(app)}</td>
                  <td>{completenessLabel(app.completeness_score)}</td>
                  <td>{lastRunAgo(app.days_since_run)}</td>
                  <td>{reviewedLabel(app.reviewed_at)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </div>
    </section>
  );
}
