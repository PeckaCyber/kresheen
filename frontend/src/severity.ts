export const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;
export type SeverityLevel = (typeof SEVERITY_ORDER)[number];

/**
 * Returns a CSS variable string for the severity background color.
 * Falls back to secondary color for unknown levels.
 */
export function severityColor(level: string): string {
  switch (level) {
    case "critical":
      return "var(--pc-sev-critical)";
    case "high":
      return "var(--pc-sev-high)";
    case "medium":
      return "var(--pc-sev-medium)";
    case "low":
      return "var(--pc-sev-low)";
    default:
      return "var(--bs-secondary-color)";
  }
}

/**
 * Returns a readable text color for the given severity background.
 * Medium uses dark text (#1b1b1b), others use white (#ffffff).
 */
export function severityTextColor(level: string): string {
  return level === "medium" ? "#1b1b1b" : "#ffffff";
}

/**
 * Returns the capitalized label for a severity level.
 */
export function severityLabel(level: string): string {
  const normalized = level.toLowerCase();
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}
