import { severityColor } from "../../severity";

/**
 * Style appearance for a DFD component node: neutral fill with risk shown as ring + badge only for HIGH/CRITICAL.
 * Colour is always paired with a text label.
 */
export interface NodeAppearance {
  fill: string;
  text: string;
  ring: string;
  badge: { label: string; color: string } | null;
}

/**
 * Compute the visual appearance of a component node.
 *
 * @param worst - The worst severity/risk level among open findings/threats (null if none)
 * @param openThreatCount - Total count of open threats when worst is HIGH/CRITICAL, else 0
 * @returns Styling: neutral fill, ring + badge only for HIGH/CRITICAL threats
 */
export function nodeAppearance(worst: string | null, openThreatCount: number): NodeAppearance {
  const isHighOrCritical = worst === "critical" || worst === "high";

  return {
    fill: "var(--pc-panel-2)",
    text: "var(--bs-body-color)",
    ring: isHighOrCritical && worst ? severityColor(worst) : "var(--pc-border)",
    badge:
      isHighOrCritical && openThreatCount > 0
        ? {
            label: `${worst} · ${openThreatCount} threat${openThreatCount === 1 ? "" : "s"}`,
            color: severityColor(worst),
          }
        : null,
  };
}

/**
 * Determine the ring colour for the MiniMap, matching the node's ring colour.
 * @param worst - The worst severity/risk level among open findings/threats
 * @returns A CSS colour string for the ring, or transparent if no HIGH/CRITICAL risk
 */
export function nodeRingColor(worst: string | null): string {
  const isHighOrCritical = worst === "critical" || worst === "high";
  return isHighOrCritical && worst ? severityColor(worst) : "transparent";
}
