import { beforeEach, describe, expect, it } from "vitest";
import { applyTheme, getThemePreference, setThemePreference } from "./theme";

describe("theme", () => {
  beforeEach(() => {
    window.localStorage.clear();
    document.documentElement.removeAttribute("data-bs-theme");
  });

  it("defaults to following the system", () => {
    expect(getThemePreference()).toBe("system");
  });

  it("applies and remembers an explicit choice", () => {
    setThemePreference("dark");
    expect(document.documentElement.getAttribute("data-bs-theme")).toBe("dark");
    expect(getThemePreference()).toBe("dark");
    setThemePreference("light");
    expect(document.documentElement.getAttribute("data-bs-theme")).toBe("light");
  });

  it("ignores a junk stored value", () => {
    window.localStorage.setItem("kresheen-theme", "purple");
    expect(getThemePreference()).toBe("system");
    applyTheme("system");
    expect(["light", "dark"]).toContain(document.documentElement.getAttribute("data-bs-theme"));
  });
});
