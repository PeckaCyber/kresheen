import { SEVERITY_ORDER, severityColor } from "../../severity";
import { pctLabel } from "./format";

export function RiskBreakdownPanel({ openByRisk, total }: { openByRisk: Record<string, number>; total: number }) {
  return (
    <section className="pc-panel h-100" aria-label="Open threats by risk">
      <div className="pc-panel-head">
        <span>Open threats by risk</span>
      </div>
      <div className="pc-panel-body">
        {total === 0 ? (
          <p className="text-muted small mb-0">No open threats to break down yet.</p>
        ) : (
          <div>
            <div className="pc-segbar mb-3" role="img" aria-label="Open threats by risk">
              {SEVERITY_ORDER.filter((s) => (openByRisk[s] ?? 0) > 0).map((s) => (
                <span
                  key={s}
                  style={{ flexGrow: openByRisk[s], background: severityColor(s) }}
                  title={`${s}: ${openByRisk[s]}`}
                />
              ))}
            </div>
            <ul className="list-unstyled mb-0 small">
              {SEVERITY_ORDER.map((s) => (
                <li key={s} className="d-flex align-items-center py-1">
                  <span className="pc-legend-swatch" style={{ background: severityColor(s) }} />
                  <span className="text-capitalize flex-grow-1">{s}</span>
                  <strong>{openByRisk[s] ?? 0}</strong>
                  <span className="text-muted ms-2" style={{ width: 42, textAlign: "right" }}>
                    {pctLabel(openByRisk[s] ?? 0, total)}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}
