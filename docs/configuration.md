# Configuration

Kresheen is configured with environment variables. You can leave almost all of them alone. The ones to look at first are `KRESHEEN_DB_URL`, `KRESHEEN_SECRET_KEY`, and, behind a TLS proxy, `KRESHEEN_FORWARDED_ALLOW_IPS`.

Notes that apply to every variable:

- A number that is missing, not a number, or (where the text says so) zero or negative falls back to the default.
- "On" values for yes/no switches are `1`, `true` and `yes` in any case, unless the text says otherwise.
- Kresheen Pro (coming soon) has its own settings, described in its own documentation. They are not listed here.
- Command-line options override environment variables where both exist (`--db`, `--frontend-dist`, `--forwarded-allow-ips`).

Some settings are not `KRESHEEN_*` variables and are read by other software: `WEB_CONCURRENCY` and `UVICORN_WORKERS` (see `KRESHEEN_ALLOW_MULTI_WORKER`), `GRYPE_DB_CACHE_DIR` (where Grype keeps its vulnerability database; the image sets `/var/cache/grype`), and `REQUESTS_CA_BUNDLE` (extra certificate authorities for outbound HTTPS).

## Server

| Variable | Default | What it does and when to set it |
|---|---|---|
| `KRESHEEN_FRONTEND_DIST` | `frontend/dist` next to the source; `/app/frontend/dist` in the image | Folder holding the built web interface. Set it if you install the package and keep the build somewhere else. Same as `kresheen serve --frontend-dist`. |
| `KRESHEEN_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Comma-separated addresses of reverse proxies whose `X-Forwarded-Proto` and `X-Forwarded-For` headers are trusted, or `*` for any. Set it when a TLS-terminating proxy sits in front, so the session cookie gets the `Secure` flag, HSTS is sent, and the sign-in throttle and audit log see real client addresses. Only trust a proxy that overwrites those headers. Same as `kresheen serve --forwarded-allow-ips`. In the Helm chart, set the `forwardedAllowIps` value. |
| `KRESHEEN_API_DOCS` | off | Set to `1` to serve the interactive API pages (`/docs`, `/redoc`) and `/openapi.json`. Off by default because a route map helps an attacker. Turn it on only while developing against the API. |
| `KRESHEEN_ALLOW_MULTI_WORKER` | off | Kresheen refuses to start when `WEB_CONCURRENCY`, `UVICORN_WORKERS` or `GUNICORN_CMD_ARGS` ask for more than one worker process, because the sign-in throttle is kept in each process's memory and every extra worker multiplies the attempts an attacker gets. Set to `1` to accept that. A warning is logged at every start. Worker counts given only on a command line, or several containers behind one load balancer, cannot be detected. |
| `KRESHEEN_WARM_THREATS` | on | After start, the server fills its in-memory threat cache in the background so the first visit to a list page is fast. Set to `0` (only that exact value) to turn it off, for example on a very small machine. |
| `KRESHEEN_THREATS_CACHE_TTL` | `60` | Seconds a cached threat result may be reused. Threats are derived from the model on request, and the cache is cleared when anything is written through the app. The time limit only covers changes made another way, such as the CLI. `0` turns the cache off. |

## Database and migrations

| Variable | Default | What it does and when to set it |
|---|---|---|
| `KRESHEEN_DB_URL` | `sqlite:///kresheen.db` (`sqlite:////data/kresheen.db` in the image) | SQLAlchemy URL of the database: `sqlite:///path/to/file.db` or `postgresql+psycopg://user:password@host:5432/dbname`. Read by `serve`, `create-user`, `audit-prune` and the `db` commands. Set it for PostgreSQL. |
| `KRESHEEN_AUTO_MIGRATE` | `1` | At start, bring the database schema up to date by itself (SQLite is copied first). Set to `0`, `false`, `no` or `off` to make the app only check, and refuse to start if the schema is behind. Use that when migrations run as a separate step, as the Helm chart does with an external database. See [upgrading.md](upgrading.md). |

## Security and sessions

| Variable | Default | What it does and when to set it |
|---|---|---|
| `KRESHEEN_SECRET_KEY` | none | A Fernet key (32 random bytes, URL-safe base64) that encrypts the Anthropic API keys people store for AI assist. Without it the app runs but refuses to store a key. Set it before anyone adds a key, keep a backup, and never change it afterwards: stored keys can no longer be read. Generate one with `openssl rand -base64 32 \| tr '+/' '-_'`. |
| `KRESHEEN_COOKIE_SECURE` | `auto` | Whether the session cookie carries the `Secure` flag. `always` (also `true`, `1`), `never` (also `false`, `0`), or `auto`, which follows the scheme the app sees. Behind a TLS proxy the app sees `http` unless it trusts the proxy, so set `KRESHEEN_FORWARDED_ALLOW_IPS` or set `always`. In the Helm chart, set the `cookieSecure` value. |
| `KRESHEEN_HSTS_MAX_AGE` | `31536000` (one year) | Seconds for the `Strict-Transport-Security` header. It is sent only on requests that arrived over TLS as the app sees it. `0` turns it off. |
| `KRESHEEN_SESSION_MAX_HOURS` | `12` | Longest a browser session lasts, however active. Whole number above zero. |
| `KRESHEEN_SESSION_IDLE_MINUTES` | `60` | A session with no requests for this long ends. Whole number above zero. |
| `KRESHEEN_MAX_CONCURRENT_HASHES` | `2` | Password checks use about 64 MiB of memory each while they run, so only this many run at once (minimum 1). Raise it on a large machine with many users signing in at once. |
| `KRESHEEN_MAX_QUEUED_HASHES` | `12` | How many more password checks may wait for a slot. Beyond that the server answers 503 with `Retry-After` at once, so a burst of sign-ins cannot tie up every thread. `0` means nobody waits. |

## Sign-in throttle

Failed sign-ins are slowed and then blocked. The counts are kept in memory in each process and are cleared on restart. Unknown email addresses are counted like known ones, so the response does not reveal which accounts exist. All values are whole numbers above zero.

| Variable | Default | What it does |
|---|---|---|
| `KRESHEEN_LOGIN_WINDOW_SECONDS` | `900` | How long a failure is remembered. |
| `KRESHEEN_LOGIN_MAX_FAILURES_PER_ACCOUNT` | `10` | Failures within the window, from any address, that lock one account until the window passes. |
| `KRESHEEN_LOGIN_FREE_FAILURES` | `3` | Failures per (address, account) pair before waiting times start. |
| `KRESHEEN_LOGIN_DELAY_BASE_SECONDS` | `1` | First wait after the free failures. It doubles with each further failure. |
| `KRESHEEN_LOGIN_DELAY_MAX_SECONDS` | `300` | Longest wait for one (address, account) pair. |
| `KRESHEEN_LOGIN_MAX_FAILURES_PER_IP` | `50` | Failures from one address across all accounts before that address is slowed. |
| `KRESHEEN_LOGIN_IP_DELAY_MAX_SECONDS` | `30` | Longest wait for a whole address, so many users behind one proxy are slowed, never locked out. |

## Limits

| Variable | Default | What it does and when to set it |
|---|---|---|
| `KRESHEEN_MAX_REQUEST_BYTES` | `26214400` (25 MiB) | Largest request body accepted. Uploads such as manifests and diagrams arrive as one JSON body, so this is also the upload limit. Larger bodies get 413. Raise it only if you need to upload bigger files and have memory for it. |
| `KRESHEEN_MAX_CONCURRENT_RUNS` | `2` | Model runs that execute at the same time. |
| `KRESHEEN_MAX_QUEUED_RUNS` | `6` | Runs allowed to wait for a slot. More than that are refused with 429 and `Retry-After`. |
| `KRESHEEN_STALE_RUN_MINUTES` | `10` | A run still in progress after this many minutes is marked failed ("interrupted"), for example after a restart. Also swept at startup. Raise it only if your repository scans legitimately take longer. |

## Outbound URL guard

Kresheen has a guard for URLs that an administrator can configure: it allows only `http` and `https`, refuses credentials in the URL, refuses loopback, private and link-local addresses (including cloud metadata addresses), connects to the address it checked, and never follows redirects. In the open-source edition every outbound request goes to a fixed host (`api.github.com`, `api.anthropic.com`, and the host Grype uses to fetch its database), so these two variables change nothing there. They apply to features of Kresheen Pro that call addresses you configure.

| Variable | Default | What it does |
|---|---|---|
| `KRESHEEN_OUTBOUND_ALLOW_PRIVATE` | off | Set to `1` to allow loopback and private addresses for configured URLs. Link-local and metadata addresses stay blocked. |
| `KRESHEEN_OUTBOUND_ALLOW_HOSTS` | empty | Comma-separated host names that may resolve to loopback or private addresses, for one internal server without opening everything. |

## Audit

| Variable | Default | What it does and when to set it |
|---|---|---|
| `KRESHEEN_AUDIT_RETENTION_DAYS` | `0` (keep until the size limit drops them) | Delete audit entries older than this many days, checked at most once a day. `0`, empty or a bad value turns it off. You can also run `kresheen audit-prune --days N` once. |

The audit log also has fixed size caps in the open-source edition: 2,000 routine entries, 10,000 security entries, and 500 failed sign-ins. The oldest entries go first.

## AI assist (experimental)

See [ai.md](ai.md).

| Variable | Default | What it does and when to set it |
|---|---|---|
| `KRESHEEN_AI_DISABLED` | off | Set to `1`, `true`, `yes` or `on` to force AI assist off for the whole server, whatever the owner chose in Settings. The Settings switch then shows as locked. Use it when policy says no data may go to an AI provider. |
| `KRESHEEN_AI_BASE_URL` | Anthropic's API | **For testing only.** Points the Anthropic client at another server, such as a local stub in end-to-end tests. Environment only, never settable from the web interface. Do not set it in a real deployment: your users' API keys would be sent to that server. |

## CLI client

Used by `kresheen ci`, which talks to a running server. See [ci-integration.md](ci-integration.md).

| Variable | Default | What it does |
|---|---|---|
| `KRESHEEN_URL` | none (required, or `--server`) | Base URL of the Kresheen server. |
| `KRESHEEN_TOKEN` | none (required, or `--token`) | API token created under Settings, API tokens. Keep it in your CI system's secret store. |

`kresheen create-user` prints lines named `KRESHEEN_USER_EMAIL` and `KRESHEEN_USER_PASSWORD`. They are output for you to read, not settings.
