import { defineConfig, devices } from "@playwright/test";

// e2e config: spins up the built SPA (via `vite preview`) against a real
// FastAPI backend. See e2e/README.md for the backend half of the setup --
// Playwright starts the frontend only; the backend is started separately
// (globalSetup would need to shell out to `kresheen create-user` +
// `kresheen serve`, which needs the Python venv activated -- left as an
// explicit prerequisite rather than baked into this config, so this file
// doesn't silently depend on a sibling Python project's exact layout).
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npm run preview",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
  },
});
