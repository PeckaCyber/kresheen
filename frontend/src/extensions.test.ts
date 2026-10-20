import { describe, expect, it } from "vitest";
import { applyCapabilities, extensions, hasExtensions } from "./extensions";

describe("applyCapabilities", () => {
  const noop = () => null;
  function fill() {
    extensions.settingsSections.push({ id: "x", render: noop });
    extensions.runTabs.push({ key: "x", label: "X", render: noop });
    extensions.loginButtons.push({ id: "x", render: noop });
  }
  function clear() {
    for (const entries of Object.values(extensions)) entries.length = 0;
  }

  it("keeps the plugin frontend when the backend reports features", () => {
    fill();
    applyCapabilities({ features: ["jira"] });
    expect(hasExtensions()).toBe(true);
    clear();
  });

  it("empties every slot when the backend reports no features (no or unlicensed plugin)", () => {
    fill();
    applyCapabilities({ features: [] });
    expect(hasExtensions()).toBe(false);
    expect(extensions.runTabs).toHaveLength(0);
  });

  it("keeps only a settings section that asks to stay when the backend reports no features", () => {
    fill();
    extensions.settingsSections.push({ id: "licence", render: noop, showWhenDisabled: true });
    applyCapabilities({ features: [] });
    expect(extensions.settingsSections.map((s) => s.id)).toEqual(["licence"]);
    expect(extensions.runTabs).toHaveLength(0);
    expect(extensions.loginButtons).toHaveLength(0);
    clear();
  });

  it("keeps every section when the backend reports features", () => {
    fill();
    extensions.settingsSections.push({ id: "licence", render: noop, showWhenDisabled: true });
    applyCapabilities({ features: ["jira"] });
    expect(extensions.settingsSections.map((s) => s.id)).toEqual(["x", "licence"]);
    clear();
  });

  it("empties every slot when capabilities could not be read", () => {
    fill();
    applyCapabilities(null);
    expect(hasExtensions()).toBe(false);
  });
});
