# CI/CD integration

`kresheen ci` runs your threat model from a CI job, diffs it against the
last completed run, fails the job on what the change **newly introduced**,
and reports the diff (stdout, `$GITHUB_STEP_SUMMARY`, and optionally a PR
comment). It is a client of your running Kresheen server: the model a PR is
checked against includes your manual DFD edits and owner-stated properties.

## Setup

1. Settings -> **API tokens** -> create a token; store it as a CI secret
   (`KRESHEEN_TOKEN`). A token acts as the user who created it and can be
   revoked at any time. Tokens cannot create or revoke other tokens.
   Tokens expire after 90 days by default; the picker also offers 30 days,
   1 year and "never expires" (not recommended: rotate CI secrets on a
   schedule instead). Through the API, `POST /api/tokens` with no
   `expires_in_days` gives 90 days, an integer from 1 to 730 sets the lifetime,
   and an explicit `"expires_in_days": null` creates a token that never
   expires. An expired token is refused with 401; create a new one and update
   the CI secret. A token can only list models and start and read runs, and
   it is revoked when its owner changes their password.
2. For `--ref` to have an effect, the Application needs a `github_repository`
   data source. `--ref` makes the
   run scan the PR's commit instead of the source's configured ref (the
   configured source is not modified).

## Gate rules (only *new* vs the baseline run)

| Flag | Default | Fails when |
|---|---|---|
| `--fail-on <severity>` | `critical` | a new finding or threat at or above the severity (`none` disables) |
| `--fail-on-boundary-crossing` | on | a new flow crosses a trust boundary |

Exit codes: `0` passed, `1` gate failed, `2` error (unreachable server, bad
token, run failed). With no earlier completed run the job passes and the run
becomes the baseline.

## GitHub Actions

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: PeckaCyber/kresheen/ci/github-action@v1.0.0
        with:
          server: https://kresheen.example.com
          token: ${{ secrets.KRESHEEN_TOKEN }}
          application: Payments API
```

Inputs: `server`, `token` and `application` are required. `ref` defaults to the pull request's head commit. `fail-on` (default `critical`), `fail-on-boundary-crossing` (`"true"` or `"false"`, default `"true"`) and `package` (the pip requirement that provides the CLI, default `kresheen`) are optional. The action always posts or updates one comment on the pull request, which needs `pull-requests: write`.

The action installs the CLI with `pip install kresheen`. Set `package` to a different requirement, such as a Git URL, if you install it another way. The server must be reachable from the runner.

## Any other CI

Install the CLI (`pip install kresheen`) and run it directly. Put the server and token in your CI system's secrets and pass them as the environment variables `KRESHEEN_URL` and `KRESHEEN_TOKEN`:

```bash
kresheen ci --application "Payments API" --ref "$COMMIT_SHA" --fail-on high --output threat-model.md
```

Options (also in [cli-reference.md](cli-reference.md)): `--server` and `--token` (or the variables above), `--application` (id or exact name), `--ref`, `--fail-on info|low|medium|high|critical|none`, `--fail-on-boundary-crossing` or `--no-fail-on-boundary-crossing`, `--output FILE`, and `--github-comment` (GitHub only; needs `GITHUB_REPOSITORY`, `GITHUB_TOKEN` and `GITHUB_EVENT_PATH`, and a pull request event). Under GitHub Actions the report is also appended to the job summary.

A run is scanned by the server synchronously, and the client waits up to 5 minutes for each request.

## Known limits

- The baseline is the application's last completed run, and CI runs are
  saved in its run history like any other run (so a later PR compares against
  the previous PR's run unless you re-run on the default branch).
- "New trust-boundary crossing" covers newly appearing *flows* and a component
  present in both runs whose trust boundary changed (both fail the same
  `--fail-on-boundary-crossing` rule). Manual (owner-drawn) components
  and flows exist in every run, so only scan-derived changes appear as new.
- The server, not the CI runner, fetches the repository, so the data source
  needs its own GitHub token for private repos.
