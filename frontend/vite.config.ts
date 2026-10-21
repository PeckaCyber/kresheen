/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

// `@kresheen/pro` is the plugin frontend. The core build uses an empty stub; set KRESHEEN_PRO_FRONTEND to the
// plugin frontend's entry file at build time to include it.
const here = path.dirname(fileURLToPath(import.meta.url));
const proFrontend = process.env.KRESHEEN_PRO_FRONTEND
  ? path.resolve(process.env.KRESHEEN_PRO_FRONTEND)
  : path.resolve(here, "src/extensions/empty.ts");
// The dev server may read the plugin frontend's folder. Vitest runs the plugin's own tests only when
// KRESHEEN_PRO_TESTS names that folder, so the core suite still checks the empty stub when the alias is set.
const proDir = process.env.KRESHEEN_PRO_FRONTEND ? path.dirname(proFrontend) : null;
const proTests = process.env.KRESHEEN_PRO_TESTS ? path.resolve(process.env.KRESHEEN_PRO_TESTS) : null;

// Dev proxy forwards /api to the FastAPI backend (kresheen serve, default
// 127.0.0.1:8000) so the SPA and API are same-origin in dev too -- keeps
// cookie-based sessions and CSRF working the same way as in production,
// where FastAPI serves the built SPA itself.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@kresheen/pro": proFrontend, "@core": path.resolve(here, "src") },
    // Plugin frontend files live outside this directory; make them use this project's copy of each library.
    dedupe: ["react", "react-dom", "react-router-dom", "react-bootstrap", "@xyflow/react", "bootstrap-icons", "@testing-library/react", "@testing-library/jest-dom"],
  },
  server: {
    fs: { allow: [here, ...(proDir ? [proDir] : []), ...(proTests ? [proTests] : [])] },
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
  // `vite preview` (what Playwright's webServer runs, and what e2e/README.md
  // documents for manual smoke testing) doesn't share `server.proxy` --
  // needs its own, same target. Bind IPv4 explicitly: `localhost` can resolve to ::1 only (CI runners), and
  // Playwright waits on 127.0.0.1.
  preview: {
    host: "127.0.0.1",
    port: 4173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/setupTests.ts"],
    include: ["src/**/*.test.{ts,tsx}", ...(proTests ? [`${path.relative(here, proTests)}/**/*.test.{ts,tsx}`] : [])],
    exclude: ["e2e/**", "node_modules/**"],
  },
});
