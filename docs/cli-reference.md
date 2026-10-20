# CLI reference

```
kresheen [OPTIONS] COMMAND [ARGS]...
```

| Command | What it does |
|---|---|
| [`serve`](#kresheen-serve) | Run the web dashboard and API |
| [`create-user`](#kresheen-create-user) | Create a login |
| [`ci`](#kresheen-ci) | Run a model from CI and gate on what is new |
| [`db`](#kresheen-db) | Inspect and upgrade the database schema |
| [`audit-prune`](#kresheen-audit-prune) | Delete old audit-log entries |

Every command that touches the database takes `--db URL` (a SQLAlchemy URL such as `sqlite:///kresheen.db` or `postgresql+psycopg://user:pass@host:5432/kresheen`) and reads `KRESHEEN_DB_URL` when `--db` is not given. The default is `sqlite:///kresheen.db`. All environment variables are in [configuration.md](configuration.md).

In the container image the entry point is the `kresheen` command, so arguments after the image name are the sub-command: `docker run --rm IMAGE create-user --email you@example.com`. With Compose, use `docker compose run --rm app create-user ...`.

If the database cannot be used (it needs a migration, or it is newer than this version), commands stop with a plain error message that says what to do.

## kresheen serve

Run the web dashboard and the API from one process.

```
kresheen serve [--host TEXT] [--port INTEGER] [--frontend-dist TEXT]
               [--forwarded-allow-ips TEXT] [--db TEXT]
```

| Option | Default | Meaning |
|---|---|---|
| `--host` | `127.0.0.1` | Interface to bind. The container image uses `0.0.0.0`. |
| `--port` | `8000` | Port to bind. |
| `--frontend-dist` | `frontend/dist` next to the source | Folder with the built web interface. Env: `KRESHEEN_FRONTEND_DIST`. |
| `--forwarded-allow-ips` | `127.0.0.1` | Reverse proxies whose `X-Forwarded-*` headers are trusted (comma-separated addresses, or `*`). Env: `KRESHEEN_FORWARDED_ALLOW_IPS`. Set it behind a TLS proxy. |
| `--db` | `sqlite:///kresheen.db` | Database URL. Env: `KRESHEEN_DB_URL`. |

On start the server brings the database schema up to date (unless `KRESHEEN_AUTO_MIGRATE=0`), marks runs left over from a previous process as failed, and warms its threat cache in the background. It runs as a single process.

## kresheen create-user

Create a login. The first account in a deployment is always an owner.

```
kresheen create-user --email TEXT [--password TEXT] [--role owner|member] [--db TEXT]
```

| Option | Default | Meaning |
|---|---|---|
| `--email` | required | Login email. A duplicate email is refused. |
| `--password` | generated | The password to set. If you do not give one, a random password is generated and printed once. A password you give must be at least 12 characters, the same rule as the web interface. Passing a password on the command line leaves it in your shell history. |
| `--role` | `member` | `owner` or `member`. Ignored for the first account. |

The command prints `KRESHEEN_USER_EMAIL=...`, `KRESHEEN_USER_PASSWORD=...` and `role=...`. Save the password: it is not shown again.

## kresheen ci

Run a model on a Kresheen server, compare it with the last completed run, and gate on what is new. Details and exit codes are in [ci-integration.md](ci-integration.md).

```
kresheen ci --server URL --token TOKEN --application NAME_OR_ID
            [--ref REF] [--fail-on LEVEL]
            [--fail-on-boundary-crossing | --no-fail-on-boundary-crossing]
            [--output FILE] [--github-comment]
```

| Option | Default | Meaning |
|---|---|---|
| `--server` | required (env `KRESHEEN_URL`) | Base URL of the server. |
| `--token` | required (env `KRESHEEN_TOKEN`) | API token from Settings, API tokens. |
| `--application` | required | Application id or exact name. |
| `--ref` | the source's own ref | Git ref or commit to scan instead. The saved source is not changed. |
| `--fail-on` | `critical` | Fail on a new finding or threat at or above `info`, `low`, `medium`, `high` or `critical`. `none` never fails on severity. |
| `--fail-on-boundary-crossing` / `--no-fail-on-boundary-crossing` | on | Fail when a new flow crosses a trust boundary. |
| `--output` | none | Also write the Markdown report to this file. |
| `--github-comment` | off | Post or update the report as a pull request comment. Needs `GITHUB_REPOSITORY`, `GITHUB_TOKEN` and `GITHUB_EVENT_PATH`. |

Exit codes: `0` the gate passed, `1` the gate failed, `2` an error such as an unreachable server, a rejected token or a failed run.

## kresheen db

Database schema commands. See [upgrading.md](upgrading.md) for when to use them.

```
kresheen db upgrade [--db TEXT]
kresheen db current [--db TEXT]
kresheen db history
kresheen db stamp-baseline [--db TEXT]
```

| Command | What it does |
|---|---|
| `upgrade` | Bring the schema to the latest revision. SQLite is copied to `<database>.pre-<revision>.bak` first. Safe to run repeatedly. It prints each schema's change, or says the schema is already up to date. This is what the Helm migration Job runs. |
| `current` | Show each schema's recorded revision and whether it is the latest, behind (run `upgrade`), newer than this version, empty, or present without a recorded revision. |
| `history` | List the revisions this version knows, newest first. Needs no database. |
| `stamp-baseline` | For your own development or demo database created before schemas were versioned. It checks that the live tables, columns and indexes match the v1.0.0 baseline exactly, and only then records the baseline revision. If anything differs it stops and lists the differences. Back up first. It is not a general repair tool. |

## kresheen audit-prune

Delete audit-log entries older than a number of days. To prune on a schedule without cron, set `KRESHEEN_AUDIT_RETENTION_DAYS` instead.

```
kresheen audit-prune --days INTEGER [--db TEXT]
```

`--days` is required and at least 1. It prints how many entries were deleted.
