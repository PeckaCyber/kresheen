import { useMemo } from "react";
import { pctLabel } from "./format";
import type { DashboardApplication } from "./types";

interface GroupRollup {
  name: string;
  addressed: number;
  total: number;
}

export function TriageProgressPanel({ apps }: { apps: DashboardApplication[] }) {
  const groups = useMemo(() => {
    const byGroup = new Map<string, GroupRollup>();
    for (const app of apps) {
      const name = app.group_name ?? "Ungrouped";
      const entry = byGroup.get(name) ?? { name, addressed: 0, total: 0 };
      entry.addressed += app.addressed_count;
      entry.total += app.total_threat_count;
      byGroup.set(name, entry);
    }
    return [...byGroup.values()].filter((g) => g.total > 0).sort((a, b) => b.total - a.total);
  }, [apps]);

  return (
    <section className="pc-panel h-100" aria-label="Triage progress">
      <div className="pc-panel-head">
        <span>Triage progress</span>
        <span className="fw-normal text-lowercase">addressed threats by group</span>
      </div>
      <div className="pc-panel-body">
        {groups.length === 0 ? (
          <p className="text-muted small mb-0">No threats to triage yet.</p>
        ) : (
          groups.map((group) => (
            <div key={group.name} className="mb-2">
              <div className="d-flex justify-content-between small mb-1">
                <span>{group.name}</span>
                <strong>{pctLabel(group.addressed, group.total)}</strong>
              </div>
              <div className="pc-bar-track">
                <div
                  className="pc-bar-fill"
                  style={{
                    width: `${(group.addressed / group.total) * 100}%`,
                    background: "linear-gradient(90deg, var(--pc-accent-2), var(--pc-accent))",
                  }}
                />
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
