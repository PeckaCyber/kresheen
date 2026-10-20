# Running the e2e suite

`playwright.config.ts` starts the frontend (`npm run preview`, a built
static server) automatically, but deliberately does **not** start the
Python backend -- these tests need a real `kresheen serve` process, and
scripting that from a Node config would mean hardcoding assumptions about
a sibling project's venv/`.db` layout. Start it yourself first:

```bash
# from the repo root, with the kresheen venv activated
kresheen create-user --db sqlite:///e2e-test.db --email test@example.com --password <a-test-password>
kresheen serve --db sqlite:///e2e-test.db &

# from frontend/
export KRESHEEN_E2E_ADMIN_EMAIL=test@example.com
export KRESHEEN_E2E_ADMIN_PASSWORD=<a-test-password>
npm run build
npm run e2e
```

Tests skip cleanly (not fail) if `KRESHEEN_E2E_ADMIN_EMAIL`/
`KRESHEEN_E2E_ADMIN_PASSWORD` aren't set, so `npm run e2e` alone won't
produce a false pass/fail without the backend running -- see
login.spec.ts's `test.skip(...)`.

## Notes

- Models are created through the API by `createModel`/`openRun` (see `create-application.spec.ts`); one test drives the
  real creation wizard. Use unique names (`Date.now()`): the e2e database accumulates rows across runs.
- Edit mode is off on load. The element inspector is docked (`data-testid="element-inspector"`) with tabs
  `inspector-tab-threats` / `inspector-tab-properties`; run-page tabs are `model-tab-<key>`. The first-run tour is
  silenced with `localStorage["kresheen-tour-done"] = "1"`.
- Check stability after changing a test: `npx playwright test --project=chromium --repeat-each=4 --workers=1`.

## AI-on run (experimental AI assist, 4A.6)

`e2e-ai/ai-assist.spec.ts` covers the experimental AI assist end to end: it turns the instance switch on, adds a key,
drafts the guided setup, explains a threat, and turns the switch off. The core suite above stays AI-off and does not
run it. Its own config is `playwright.ai.config.ts` (`testDir: ./e2e-ai`, serial).

The AI calls go to a stub Anthropic API, `tests/support/anthropic_stub.py`, so no real key or network is used. Use a
scratch database for each run. The spec starts with the switch off, and re-running it on a database where the switch is
already on fails at the first check. From the repo root, with the venv activated:

```bash
# 1. the stub (port 8765)
python tests/support/anthropic_stub.py --port 8765 &

# 2. a fresh scratch database and a Fernet key (needed to store the key)
kresheen create-user --db sqlite:///<scratch>/e2e-ai.db --email test@example.com --password <a-test-password>
export KRESHEEN_SECRET_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')

# 3. the server, pointed at the stub
KRESHEEN_AI_BASE_URL=http://127.0.0.1:8765 kresheen serve --host 127.0.0.1 --port 8000 --db sqlite:///<scratch>/e2e-ai.db &

# 4. the spec, from frontend/
export KRESHEEN_E2E_ADMIN_EMAIL=test@example.com
export KRESHEEN_E2E_ADMIN_PASSWORD=<a-test-password>
npm run build
npx playwright test -c playwright.ai.config.ts
```

Stop the server and the stub by PID when done. The core suite is written for an AI-off server, so run it against a separate one.

Kresheen Pro has its own end-to-end specs and instructions.
