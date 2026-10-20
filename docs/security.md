# Security guide for operators

This page is for the person who runs a Kresheen server. It lists what to set up, what Kresheen already does for you, and what is left to you. To report a vulnerability, see `SECURITY.md` in the repository.

## A short checklist

1. Put a TLS-terminating reverse proxy in front, and tell Kresheen about it (`KRESHEEN_FORWARDED_ALLOW_IPS`).
2. Set `KRESHEEN_SECRET_KEY` and back it up.
3. Keep it to one process.
4. Use PostgreSQL or an encrypted volume, and back up the database.
5. Restrict outbound network access to what you use.
6. Use short-lived API tokens.
7. Keep the image and its base up to date.

## TLS and the reverse proxy

Kresheen speaks plain HTTP. Anything beyond your own machine should reach it through a proxy that terminates TLS (nginx, Caddy, a cloud load balancer, a Kubernetes ingress).

The container's compose file publishes the port on `127.0.0.1` only. Keep it that way, and let the proxy connect to it.

Tell Kresheen which proxy to trust, so that it knows the original request used HTTPS and who the real client is:

- Set `KRESHEEN_FORWARDED_ALLOW_IPS` to the proxy's address (comma-separated for several), or `*` only if the proxy is the only thing that can reach the container. The default is `127.0.0.1`.
- Only trust a proxy that **overwrites** `X-Forwarded-Proto` and `X-Forwarded-For` rather than passing along what the client sent.

Why it matters. Without it, the session cookie is not marked `Secure` (the app thinks the request was plain HTTP), the HSTS header is not sent, and the sign-in throttle and audit log see only the proxy's address, so one attacker can slow sign-ins for everyone behind the proxy. If you cannot set the address, `KRESHEEN_COOKIE_SECURE=always` at least fixes the cookie.

With the Helm chart, set `forwardedAllowIps` (this sets `KRESHEEN_FORWARDED_ALLOW_IPS`) to the address range your ingress controller's pods use, and optionally `cookieSecure: always` (this sets `KRESHEEN_COOKIE_SECURE`). `*` is easier but trusts forwarded headers from anything that can reach the pod, so if you use it, keep the network policy on and allow only your ingress controller in `networkPolicy.ingressFrom`. See [installation.md](installation.md).

Kresheen sets security headers on every response: a strict Content-Security-Policy that allows only same-origin scripts, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, a no-referrer policy and a restrictive permissions policy. HSTS (`KRESHEEN_HSTS_MAX_AGE`, one year by default) is sent on requests that arrived over TLS. The interactive API pages (`/docs`) are off unless you set `KRESHEEN_API_DOCS=1`.

## The secret key

`KRESHEEN_SECRET_KEY` is a Fernet key that encrypts the Anthropic API keys people store for AI assist.

- Generate it once: `openssl rand -base64 32 | tr '+/' '-_'`.
- Store a copy somewhere safe, apart from the database backups. If it is lost or changed, stored keys can no longer be read.
- Provide it as an environment variable from a secret store, not on a command line. In Compose put it in `.env` (the installer writes it with mode 600). In Kubernetes the chart keeps it in a `Secret` and keeps it across upgrades.
- The encryption protects those keys only. The rest of the database is not encrypted by Kresheen (see Backups and storage).

## Sign-in, sessions and API tokens

- Passwords are hashed with Argon2. New passwords need at least 12 characters in the web interface.
- Failed sign-ins are throttled per account, per address and per pair, with growing delays and a temporary account lock. The thresholds are in [configuration.md](configuration.md). A determined person can lock a known account for the window (15 minutes by default) by failing its sign-ins. That is a deliberate trade for not allowing unlimited guessing.
- Sessions last at most 12 hours and end after 60 minutes of no use (`KRESHEEN_SESSION_MAX_HOURS`, `KRESHEEN_SESSION_IDLE_MINUTES`). The cookie is `HttpOnly` and `SameSite=Lax`. Changing the password ends the other sessions and revokes the person's API tokens. Requests that change data need a CSRF token.
- API tokens act as the user who created them but can only list models and start and read runs. They expire after 90 days by default, and the picker offers 30 days, 1 year and "never". Prefer an expiry and rotate the CI secret. A token cannot create or revoke tokens. Revoke tokens of people who leave, and deactivate their accounts.
- Give the owner role to as few people as you can. Owners manage users, see the audit log and control AI assist.
- Make the first account with `kresheen create-user`, and keep its password out of shell history by letting it generate one.

## One process only

The sign-in throttle and the AI rate limit are kept in each process's memory. With several worker processes or replicas, every one counts separately and an attacker gets that many times more attempts. Kresheen therefore:

- refuses to start if `WEB_CONCURRENCY`, `UVICORN_WORKERS` or `GUNICORN_CMD_ARGS` ask for more than one worker, unless you set `KRESHEEN_ALLOW_MULTI_WORKER=1` (a warning is then logged at every start), and
- makes the Helm chart refuse `replicaCount` above 1 unless `allowMultipleReplicas=true`.

Several containers behind a load balancer cannot be detected, so do not do that without accepting the weaker throttle.

## Outbound access

In this edition Kresheen makes outbound requests to a small fixed set of hosts:

- `api.github.com`, when a model has a GitHub repository source,
- the host Grype downloads its vulnerability database from (over 1 GB, downloaded on first use),
- `api.anthropic.com`, only if AI assist is on and someone added a key.

Allow only those in your egress rules. The Helm chart's network policy limits egress to DNS, the bundled database and HTTPS (port 443) to `networkPolicy.egressCidrs`. Narrow that list to what you use. See the notes in [installation.md](installation.md). For an air-gapped install, fill the Grype cache volume from another machine and block everything else.

Kresheen also contains a guard for URLs that an administrator can configure, which allows only `http` and `https`, refuses credentials in the URL, refuses loopback, private and link-local (cloud metadata) addresses, pins the connection to the address it checked and never follows redirects. `KRESHEEN_OUTBOUND_ALLOW_PRIVATE` and `KRESHEEN_OUTBOUND_ALLOW_HOSTS` loosen it for private servers. This edition has no features that call a configured address, so those settings change nothing here. See [configuration.md](configuration.md).

## What Kresheen stores that is sensitive

- **Source files and models.** Uploaded manifests and diagrams are stored in the database. Secret-looking values in Kubernetes and Terraform input are replaced with `<redacted>` before being stored, but the model itself describes your architecture, so protect the database like any internal design document.
- **GitHub tokens.** An optional token for a private repository is encrypted with `KRESHEEN_SECRET_KEY` (the same key as AI keys and connector credentials) and the data source keeps only a reference and the last four characters. The API, reports and exports never return the token, not even to owners, and deleting the data source or application deletes it. Anyone with the database and `KRESHEEN_SECRET_KEY` can still decrypt it, so use a read-only token limited to the one repository, and rotate it.
- **Anthropic API keys.** Encrypted with the secret key, as above.
- **Passwords and API tokens.** Only hashes are stored.

## The image and the container

The runtime image is built on a Google "distroless" Python base. It has no shell, no package manager and no compiler, runs as the numeric user `65532`, and works with a read-only root filesystem. Every base image in the build is pinned by digest.

Run it that way:

```
docker run -d --name kresheen -p 127.0.0.1:8000:8000 \
  --read-only --tmpfs /tmp:rw,mode=1777 \
  -v kresheen-data:/data -v grype-cache:/var/cache/grype \
  --cap-drop ALL --security-opt no-new-privileges \
  -e KRESHEEN_SECRET_KEY=... ghcr.io/peckacyber/kresheen:1.0.0
```

The Compose file and the Helm chart already do this: read-only root filesystem, a writable `/tmp` only (tmpfs or `emptyDir`), all capabilities dropped, no privilege escalation, a default seccomp profile in Kubernetes, and no Kubernetes API token mounted into the pod.

- `/var/cache/grype` must be a writable volume, not a tmpfs, because the vulnerability database is large and would count against the container's memory.
- `/data` holds the SQLite database if you use SQLite. With PostgreSQL it is not used.
- The bundled PostgreSQL in the Compose file and chart is for trials. It uses the default credentials in those files and is not hardened for production. Use your own database for anything real.
- For debugging, attach a throwaway container instead of adding a shell: `docker debug <container>` or `kubectl debug -it <pod> --image=busybox --target=kresheen`.
- Scan the image you run (for example with Grype or Trivy) and rebuild on new base image releases.

Requests larger than 25 MiB are refused (`KRESHEEN_MAX_REQUEST_BYTES`), password checks and model runs are limited in how many run at once, and uploaded archives and diagrams are checked for size, path traversal, unsafe links and decompression bombs. These limits protect a small server from one heavy request. See [configuration.md](configuration.md).

## What is audited

The audit log (owners: **Settings**, **Audit log**) records, newest first:

- every change made through the dashboard or an API token (who, what, which object, the result and the client address),
- sign-ins, sign-outs, failed and throttled sign-ins, and password changes,
- every report and data export,
- creating and revoking API tokens, and adding or changing users,
- AI assist events: each request (feature, model, token counts, outcome), keys added or removed, the instance switch, and prompt-injection warnings.

It never records request contents, passwords, tokens, keys or AI text. Security events are kept in a separate pool from routine changes, so a flood of ordinary edits cannot push them out. In this edition the caps are fixed (2,000 routine entries, 10,000 security entries, 500 failed sign-ins), and `KRESHEEN_AUDIT_RETENTION_DAYS` or `kresheen audit-prune` removes entries by age. The log lives in the database, so it is only as safe as the database. If you need it elsewhere, copy it out on a schedule.

## Backups and storage

- **Back up the database** and the secret key, separately. SQLite: stop Kresheen and copy the file, or use `sqlite3 kresheen.db ".backup kresheen.bak"`. PostgreSQL: `pg_dump`. Kresheen copies SQLite before a schema upgrade but never backs up PostgreSQL. Take your own backup before every upgrade. See [upgrading.md](upgrading.md).
- **The database is not encrypted at rest** by Kresheen. Use an encrypted disk or volume, or encryption in your managed database. For SQLite the file is created with owner-only permissions.
- **Restoring** an older backup is the only way back from a schema upgrade, because migrations only go forward.
- Test a restore from time to time.

## Known limits

- Kresheen reads declared configuration only. A clean result does not prove a system is secure.
- The web interface needs `style-src 'unsafe-inline'` because the diagram and charts set inline styles.
- Prompt-injection detection for AI assist is a heuristic. It raises a warning. It is not a guarantee. AI cannot change your threats, but its text can be wrong or misleading, so review it.
