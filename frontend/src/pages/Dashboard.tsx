import { extensions } from "../extensions";
import { useEffect, useState } from "react";
import { Alert, Col, Row } from "react-bootstrap";
import { PageHeader } from "../components/PageHeader";
import { apiFetch } from "../api/client";
import { AppDrawer } from "./dashboard/AppDrawer";
import { EmptyState } from "./dashboard/EmptyState";
import { ExecutiveSummaryPanel } from "./dashboard/ExecutiveSummaryPanel";
import { NeedsAttentionTable } from "./dashboard/NeedsAttentionTable";
import { RecentActivityPanel } from "./dashboard/RecentActivityPanel";
import { ReviewStatusPanel } from "./dashboard/ReviewStatusPanel";
import { RiskBreakdownPanel } from "./dashboard/RiskBreakdownPanel";
import { StatTiles } from "./dashboard/StatTiles";
import { ThreatTrendPanel } from "./dashboard/ThreatTrendPanel";
import { TriageProgressPanel } from "./dashboard/TriageProgressPanel";
import { EMPTY_SUMMARY, type DashboardOut, type TileKey } from "./dashboard/types";

const DEFAULT_DAYS = 90;

export function DashboardPage() {
  const [data, setData] = useState<DashboardOut | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState(DEFAULT_DAYS);
  const [panel, setPanel] = useState<TileKey | null>(null);

  useEffect(() => {
    let active = true;
    setError(null);
    apiFetch<DashboardOut>(`/api/dashboard?days=${days}`)
      .then((out) => {
        if (active) setData(out);
      })
      .catch(() => {
        if (active) setError("Failed to load the dashboard.");
      });
    return () => {
      active = false;
    };
  }, [days]);

  const apps = data?.applications ?? [];
  const trend = data?.trend ?? [];
  const summary = data?.summary ?? EMPTY_SUMMARY;

  return (
    <div className="pc-page">
      <PageHeader title="Overview" subtitle="Everything you can see, at a glance. Click any panel for the detail." />
      {error && <Alert variant="danger">{error}</Alert>}
      {!data && !error && <p>Loading...</p>}
      {data && (
        <>
          <ExecutiveSummaryPanel days={days} onRangeChange={setDays} />
          {apps.length === 0 ? (
            <EmptyState />
          ) : (
            <>
              <StatTiles summary={summary} apps={apps} trend={trend} onOpen={setPanel} />

              <Row className="g-3 mb-3">
                <Col lg={8}>
                  <ThreatTrendPanel points={trend} />
                </Col>
                <Col lg={4}>
                  <RiskBreakdownPanel openByRisk={summary.open_by_risk} total={summary.open_threat_count} />
                </Col>
              </Row>

              <Row className="g-3 mb-3">
                <Col xs={12}>
                  <TriageProgressPanel apps={apps} />
                </Col>
              </Row>

              {extensions.dashboardPanels.map((panel) =>
                data.extensions && panel.key in data.extensions ? (
                  <div key={panel.key} className="mb-3">
                    {panel.render({ data: data.extensions[panel.key], dashboard: data })}
                  </div>
                ) : null,
              )}

              <Row className="g-3 mb-3">
                <Col xs={12}>
                  <NeedsAttentionTable apps={apps} />
                </Col>
              </Row>

              <Row className="g-3">
                <Col lg={6}>
                  <RecentActivityPanel events={data.recent_activity} apps={apps} />
                </Col>
                <Col lg={6}>
                  <ReviewStatusPanel apps={apps} summary={summary} />
                </Col>
              </Row>
            </>
          )}
        </>
      )}

      <AppDrawer panel={panel} apps={apps} onHide={() => setPanel(null)} />
    </div>
  );
}
