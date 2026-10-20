import { describe, expect, it } from "vitest";
import { openThreatSignal, worseOf } from "./threatSignal";
import type { ThreatOut } from "./ThreatsPanel";

const threat = (overrides: Partial<ThreatOut>): ThreatOut =>
  ({ element_kind: "component", element_id: "A", status: "open", severity: "medium", risk: "medium", ...overrides }) as ThreatOut;

describe("worseOf", () => {
  it("picks the more severe of two, tolerating absent values", () => {
    expect(worseOf("low", "high")).toBe("high");
    expect(worseOf("critical", "medium")).toBe("critical");
    expect(worseOf(null, "low")).toBe("low");
    expect(worseOf(undefined, null)).toBeNull();
  });
});

describe("openThreatSignal", () => {
  it("counts only open threats on that component and reports the worst risk", () => {
    const threats = [
      threat({ risk: "high" }),
      threat({ risk: "low" }),
      threat({ risk: "critical", status: "mitigated" }),
      threat({ element_id: "B", risk: "critical" }),
      threat({ element_kind: "flow", risk: "critical" }),
    ];
    expect(openThreatSignal("A", threats)).toEqual({ open_threat_count: 2, worst_threat_risk: "high" });
  });

  it("is empty when nothing applies", () => {
    expect(openThreatSignal("A", undefined)).toEqual({ open_threat_count: 0, worst_threat_risk: null });
  });
});
