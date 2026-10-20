# Kresheen web interface

The web interface is a React single-page app (Vite, TypeScript, React Router, Bootstrap) that talks to the
FastAPI backend's `/api/*` JSON API. `kresheen serve` serves the production build from `frontend/dist` next to the API.

## Prerequisites

Node.js 22.12 or newer (see `engines` in `package.json`) and a Python environment with Kresheen installed
(`pip install -e ".[dev]"` from the repository root).

## Develop

```bash
cd frontend
npm ci
npm run dev        # http://localhost:5173, proxies /api to 127.0.0.1:8000
```

The dev server needs a backend on port 8000. From the repository root, in the Python environment:

```bash
kresheen create-user --email you@example.com
kresheen serve
```

## Build and test

| Command | What it does |
|---|---|
| `npm run build` | Type-check, then build to `dist/` |
| `npm run preview` | Serve the built `dist/` (used by the end-to-end tests) |
| `npm test` | Unit and component tests (Vitest), once |
| `npm run test:watch` | The same, in watch mode |
| `npx tsc -b --noEmit` | Type-check only (`npm run lint` does the same) |
| `npm run e2e` | End-to-end tests (Playwright); they need a running backend, see [e2e/README.md](e2e/README.md) |

Dependencies are pinned to exact versions. Bump them deliberately, then re-run the build, the tests and the
end-to-end tests.

For the full contributor workflow (checks to run before a pull request, code style, database changes) see
[CONTRIBUTING.md](../CONTRIBUTING.md).
