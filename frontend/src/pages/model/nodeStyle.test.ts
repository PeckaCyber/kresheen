import { describe, it, expect } from "vitest";
import { nodeAppearance, nodeRingColor } from "./nodeStyle";

describe("nodeAppearance", () => {
  it("high severity with threats shows ring + badge", () => {
    const appearance = nodeAppearance("high", 2);
    expect(appearance.fill).toBe("var(--pc-panel-2)");
    expect(appearance.text).toBe("var(--bs-body-color)");
    expect(appearance.ring).toBe("var(--pc-sev-high)");
    expect(appearance.badge).toEqual({
      label: "high · 2 threats",
      color: "var(--pc-sev-high)",
    });
  });

  it("critical severity with threat shows ring + badge (singular)", () => {
    const appearance = nodeAppearance("critical", 1);
    expect(appearance.ring).toBe("var(--pc-sev-critical)");
    expect(appearance.badge).toEqual({
      label: "critical · 1 threat",
      color: "var(--pc-sev-critical)",
    });
  });

  it("medium severity shows neutral ring, no badge", () => {
    const appearance = nodeAppearance("medium", 5);
    expect(appearance.fill).toBe("var(--pc-panel-2)");
    expect(appearance.ring).toBe("var(--pc-border)");
    expect(appearance.badge).toBeNull();
  });

  it("low severity shows neutral ring, no badge", () => {
    const appearance = nodeAppearance("low", 3);
    expect(appearance.ring).toBe("var(--pc-border)");
    expect(appearance.badge).toBeNull();
  });

  it("null severity shows neutral appearance", () => {
    const appearance = nodeAppearance(null, 0);
    expect(appearance.fill).toBe("var(--pc-panel-2)");
    expect(appearance.ring).toBe("var(--pc-border)");
    expect(appearance.badge).toBeNull();
  });

  it("high severity with zero threats shows no badge", () => {
    const appearance = nodeAppearance("high", 0);
    expect(appearance.ring).toBe("var(--pc-sev-high)");
    expect(appearance.badge).toBeNull();
  });
});

describe("nodeRingColor", () => {
  it("high severity returns high colour", () => {
    expect(nodeRingColor("high")).toBe("var(--pc-sev-high)");
  });

  it("critical severity returns critical colour", () => {
    expect(nodeRingColor("critical")).toBe("var(--pc-sev-critical)");
  });

  it("medium severity returns transparent", () => {
    expect(nodeRingColor("medium")).toBe("transparent");
  });

  it("null returns transparent", () => {
    expect(nodeRingColor(null)).toBe("transparent");
  });
});
