import { TrendChart } from "./charts";
import type { TrendPoint } from "./types";

export function ThreatTrendPanel({ points }: { points: TrendPoint[] }) {
  return (
    <section className="pc-panel h-100" aria-label="Threat trend">
      <div className="pc-panel-head">
        <span>Threat trend</span>
        <span className="fw-normal text-lowercase">open threats over time</span>
      </div>
      <div className="pc-panel-body">
        {points.length < 2 ? (
          <div className="pc-empty-stat">
            <p className="text-muted small mb-0">Trend appears after a second day of data.</p>
            <p className="text-muted small mb-0">
              A snapshot of every model's open threats is recorded whenever this page is opened, or a run or threat
              status changes.
            </p>
          </div>
        ) : (
          <TrendChart points={points} />
        )}
      </div>
    </section>
  );
}
