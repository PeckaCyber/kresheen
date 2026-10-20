// Light / dark / follow-the-system. Stored per browser (a display preference, not account data).
// Bootstrap 5.3 themes itself from the `data-bs-theme` attribute on <html>.
export type ThemePreference = "light" | "dark" | "system";

const KEY = "kresheen-theme";

export function getThemePreference(): ThemePreference {
  try {
    const stored = window.localStorage.getItem(KEY);
    if (stored === "light" || stored === "dark" || stored === "system") return stored;
  } catch {
    // Storage can be blocked; fall through to the default.
  }
  return "system";
}

export function resolveTheme(preference: ThemePreference): "light" | "dark" {
  if (preference !== "system") return preference;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function applyTheme(preference: ThemePreference): void {
  document.documentElement.setAttribute("data-bs-theme", resolveTheme(preference));
}

export function setThemePreference(preference: ThemePreference): void {
  try {
    window.localStorage.setItem(KEY, preference);
  } catch {
    // Not persisted, but still applied for this session.
  }
  applyTheme(preference);
}

// Call once before the first render so there is no flash of the wrong theme, and keep "system"
// in step with the OS setting.
export function initTheme(): void {
  applyTheme(getThemePreference());
  window.matchMedia?.("(prefers-color-scheme: dark)").addEventListener?.("change", () => {
    if (getThemePreference() === "system") applyTheme("system");
  });
}
