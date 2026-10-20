import type { ThreatOut } from "./ThreatsPanel";

const RISK_ORDER = ["critical", "high", "medium", "low"] as const;
export type RiskLevel = (typeof RISK_ORDER)[number];

// The worst of two severities/risks (either may be absent); they share one scale.
export function worseOf(a: string | null | undefined, b: string | null | undefined): string | null {
  const rank = (value: string | null | undefined) => {
    const index = RISK_ORDER.indexOf(value as RiskLevel);
    return index === -1 ? RISK_ORDER.length : index;
  };
  if (!a && !b) return null;
  return rank(a) <= rank(b) ? (a ?? null) : (b ?? null);
}

// Open-threat signal for one diagram component, so the canvas reflects design
// threats and not only scanner findings. Only open
// threats count: a mitigated or accepted one has been dealt with.
export function openThreatSignal(
  componentId: string,
  threats: ThreatOut[] | undefined,
): { open_threat_count: number; worst_threat_risk: string | null } {
  let count = 0;
  let worst: string | null = null;
  for (const threat of threats ?? []) {
    if (threat.element_kind !== "component" || threat.element_id !== componentId || threat.status !== "open") continue;
    count += 1;
    worst = worseOf(worst, threat.risk ?? threat.severity);
  }
  return { open_threat_count: count, worst_threat_risk: worst };
}
