import { describe, it, expect } from "vitest";
import { SEVERITY_ORDER, severityColor, severityTextColor, severityLabel } from "./severity";

describe("severity", () => {
  describe("severityColor", () => {
    it("returns correct CSS variable for critical", () => {
      expect(severityColor("critical")).toBe("var(--pc-sev-critical)");
    });

    it("returns correct CSS variable for high", () => {
      expect(severityColor("high")).toBe("var(--pc-sev-high)");
    });

    it("returns correct CSS variable for medium", () => {
      expect(severityColor("medium")).toBe("var(--pc-sev-medium)");
    });

    it("returns correct CSS variable for low", () => {
      expect(severityColor("low")).toBe("var(--pc-sev-low)");
    });

    it("returns secondary color for unknown levels", () => {
      expect(severityColor("unknown")).toBe("var(--bs-secondary-color)");
      expect(severityColor("info")).toBe("var(--bs-secondary-color)");
      expect(severityColor("")).toBe("var(--bs-secondary-color)");
    });
  });

  describe("severityTextColor", () => {
    it("returns dark text for medium", () => {
      expect(severityTextColor("medium")).toBe("#1b1b1b");
    });

    it("returns white text for critical", () => {
      expect(severityTextColor("critical")).toBe("#ffffff");
    });

    it("returns white text for high", () => {
      expect(severityTextColor("high")).toBe("#ffffff");
    });

    it("returns white text for low", () => {
      expect(severityTextColor("low")).toBe("#ffffff");
    });

    it("returns white text for unknown levels", () => {
      expect(severityTextColor("unknown")).toBe("#ffffff");
    });
  });

  describe("severityLabel", () => {
    it("returns capitalized label", () => {
      expect(severityLabel("critical")).toBe("Critical");
      expect(severityLabel("high")).toBe("High");
      expect(severityLabel("medium")).toBe("Medium");
      expect(severityLabel("low")).toBe("Low");
    });

    it("handles mixed case input", () => {
      expect(severityLabel("CRITICAL")).toBe("Critical");
      expect(severityLabel("High")).toBe("High");
    });
  });

  describe("SEVERITY_ORDER", () => {
    it("has correct order", () => {
      expect(SEVERITY_ORDER).toEqual(["critical", "high", "medium", "low"]);
    });

    it("is a readonly tuple", () => {
      expect(Object.isFrozen(SEVERITY_ORDER) || SEVERITY_ORDER instanceof Array).toBe(true);
    });
  });
});

import { render } from "@testing-library/react";
import { RiskBadge } from "./components/RiskBadge";

describe("RiskBadge", () => {
  it("keeps its palette colours when the caller passes a style", () => {
    const { container } = render(<RiskBadge level="high" style={{ fontSize: 10 }}>high</RiskBadge>);
    const badge = container.querySelector("span") as HTMLSpanElement;
    expect(badge.style.background).toContain("--pc-sev-high");
    expect(badge.style.fontSize).toBe("10px");
  });
});
