import { useMemo } from "react";
import { Offcanvas, Table } from "react-bootstrap";
import { Link } from "react-router-dom";
import { RiskBadge } from "../../components/RiskBadge";
import { SEVERITY_ORDER } from "../../severity";
import { addressedPctLabel, appLink, completenessLabel, groupNameOf, lastRunAgo, reviewedLabel, worst } from "./format";
import type { DashboardApplication, TileKey } from "./types";

const PANEL_TITLE: Record<TileKey, string> = {
  models: "All applications",
  openThreats: "Open threats by application",
  highCritical: "High and critical open threats",
  addressed: "Addressed progress by application",
  completeness: "Completeness by application",
  attention: "Needs attention",
};

const HIGH_OR_CRITICAL = new Set(["critical", "high"]);

function rank(s: string | null): number {
  if (s === null) return SEVERITY_ORDER.length;
  const index = SEVERITY_ORDER.indexOf(s as (typeof SEVERITY_ORDER)[number]);
  return index === -1 ? SEVERITY_ORDER.length : index;
}

function rowsFor(panel: TileKey, apps: DashboardApplication[]): DashboardApplication[] {
  switch (panel) {
    case "openThreats":
      return apps.filter((a) => a.open_threat_count > 0).sort((a, b) => b.open_threat_count - a.open_threat_count);
    case "highCritical":
      return apps
        .filter((a) => worst(a) !== null && HIGH_OR_CRITICAL.has(worst(a) as string))
        .sort((a, b) => rank(worst(a)) - rank(worst(b)) || b.open_threat_count - a.open_threat_count);
    case "addressed":
      return apps
        .filter((a) => a.total_threat_count > 0)
        .sort((a, b) => a.addressed_count / a.total_threat_count - b.addressed_count / b.total_threat_count);
    case "completeness":
      return apps
        .filter((a) => a.completeness_score !== null)
        .sort((a, b) => (a.completeness_score ?? 0) - (b.completeness_score ?? 0));
    case "attention":
      return apps
        .filter((a) => a.stale || a.reviewed_at === null)
        .sort((a, b) => Number(a.reviewed_at !== null) - Number(b.reviewed_at !== null) || Number(b.stale) - Number(a.stale));
    default:
      return [...apps].sort((a, b) => a.name.localeCompare(b.name));
  }
}

// The side-panel drill-down opened by clicking any stat tile. Every tile
// shares the same column set so the "All applications" list and every
// filtered variant of it read the same way.
export function AppDrawer({
  panel,
  apps,
  onHide,
}: {
  panel: TileKey | null;
  apps: DashboardApplication[];
  onHide: () => void;
}) {
  const rows = useMemo(() => (panel ? rowsFor(panel, apps) : []), [panel, apps]);

  return (
    <Offcanvas show={panel !== null} onHide={onHide} placement="end" style={{ width: 520 }}>
      <Offcanvas.Header closeButton>
        <Offcanvas.Title>{panel ? PANEL_TITLE[panel] : ""}</Offcanvas.Title>
      </Offcanvas.Header>
      <Offcanvas.Body>
        {rows.length === 0 ? (
          <p className="text-muted">Nothing here.</p>
        ) : (
          <Table size="sm" hover responsive className="small align-middle">
            <thead>
              <tr>
                <th>Application</th>
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
                    <Link to={appLink(app)}>{app.name}</Link>
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
      </Offcanvas.Body>
    </Offcanvas>
  );
}
