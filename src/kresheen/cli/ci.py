"""`kresheen ci`: run the threat model against a running Kresheen server
from a CI job, gate on what the change newly introduced, and report it.

A remote client on purpose: the model a PR is checked against includes the
owner's manual DFD edits and stated properties, which live in the server's
database. Authenticates with an API token
(Settings -> API tokens). Exit codes: 0 gate passed, 1 gate failed, 2 error.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click
import requests

from kresheen.engine.ci_gate import COMMENT_MARKER, SEVERITY_ORDER, GateOptions, evaluate_gate
from kresheen.models.run_diff import RunDiffOut

_TIMEOUT = 300  # a run scans synchronously server-side


class CiError(Exception):
    pass


def _request(method: str, url: str, token: str, **kwargs):
    try:
        response = requests.request(
            method, url, headers={"Authorization": f"Bearer {token}"}, timeout=_TIMEOUT, **kwargs
        )
    except requests.RequestException as exc:
        raise CiError(f"Could not reach {url}: {exc}") from exc
    if response.status_code == 401:
        raise CiError("The server rejected the API token (401); it may have expired or been revoked.")
    if response.status_code >= 400:
        raise CiError(f"{method} {url} failed: {response.status_code} {response.text[:200]}")
    return response


def _resolve_application(server: str, token: str, application: str) -> dict:
    apps = _request("GET", f"{server}/api/applications", token).json()
    matches = [a for a in apps if a["id"] == application or a["name"] == application]
    if not matches:
        raise CiError(f"No application with id or name {application!r}.")
    if len(matches) > 1:
        raise CiError(f"{application!r} matches {len(matches)} applications; use the id.")
    return matches[0]


def run_ci(
    *, server: str, token: str, application: str, source_ref: str | None, options: GateOptions
) -> tuple[bool, str, RunDiffOut]:
    server = server.rstrip("/")
    app = _resolve_application(server, token, application)
    app_url = f"{server}/api/applications/{app['id']}"

    # The baseline is the last completed run *before* this one, fixed up front
    # so that repeated CI runs on a branch each compare against the same model.
    runs = _request("GET", f"{app_url}/runs", token).json()
    completed = [r for r in runs if r["status"] == "completed"]
    completed.sort(key=lambda r: r["started_at"])
    baseline_id = completed[-1]["id"] if completed else None

    body = {"source_ref": source_ref} if source_ref else {}
    run = _request("POST", f"{app_url}/runs", token, json=body).json()
    if run["status"] != "completed":
        raise CiError(f"Run {run['id']} ended as {run['status']}: {run.get('error_message') or 'no detail'}")

    params = {"against": baseline_id} if baseline_id else None
    diff = RunDiffOut.model_validate(_request("GET", f"{app_url}/runs/{run['id']}/diff", token, params=params).json())
    run_url = f"{server}/applications/{app['id']}/runs/{run['id']}"
    result = evaluate_gate(diff, options, run_url=run_url)
    return result.passed, result.markdown, diff


def _post_github_comment(markdown: str) -> None:
    """Upserts one Kresheen comment on the PR (found by its marker) so a
    push doesn't stack a new comment each time."""
    repo = os.environ.get("GITHUB_REPOSITORY")
    gh_token = os.environ.get("GITHUB_TOKEN")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not (repo and gh_token and event_path):
        raise CiError("--github-comment needs GITHUB_REPOSITORY, GITHUB_TOKEN and GITHUB_EVENT_PATH.")
    event = json.loads(Path(event_path).read_text())
    number = (event.get("pull_request") or {}).get("number") or event.get("number")
    if not number:
        raise CiError("--github-comment only works on pull_request events.")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    base = f"{api}/repos/{repo}/issues/{number}/comments"
    headers = {"Authorization": f"Bearer {gh_token}", "Accept": "application/vnd.github+json"}
    try:
        existing = requests.get(base, headers=headers, params={"per_page": 100}, timeout=30)
        existing.raise_for_status()
        mine = next((c for c in existing.json() if COMMENT_MARKER in (c.get("body") or "")), None)
        if mine:
            requests.patch(mine["url"], headers=headers, json={"body": markdown}, timeout=30).raise_for_status()
        else:
            requests.post(base, headers=headers, json={"body": markdown}, timeout=30).raise_for_status()
    except requests.RequestException as exc:
        raise CiError(f"Could not post the PR comment: {exc}") from exc


@click.command("ci")
@click.option("--server", envvar="KRESHEEN_URL", required=True, help="Kresheen base URL.")
@click.option("--token", envvar="KRESHEEN_TOKEN", required=True, help="API token (Settings -> API tokens).")
@click.option("--application", required=True, help="Application id or exact name.")
@click.option("--ref", "source_ref", default=None, help="Git ref/SHA to scan instead of the source's configured one.")
@click.option(
    "--fail-on",
    type=click.Choice([*SEVERITY_ORDER, "none"]),
    default="critical",
    show_default=True,
    help="Fail on a NEW finding or threat at or above this severity.",
)
@click.option(
    "--fail-on-boundary-crossing/--no-fail-on-boundary-crossing",
    default=True,
    show_default=True,
    help="Fail when a new flow crosses a trust boundary.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Also write the markdown report here.",
)
@click.option("--github-comment", is_flag=True, help="Post/update the report as a PR comment (GitHub Actions).")
def ci(
    server: str,
    token: str,
    application: str,
    source_ref: str | None,
    fail_on: str,
    fail_on_boundary_crossing: bool,
    output_path: Path | None,
    github_comment: bool,
) -> None:
    """Run the model, diff against the last completed run, and gate."""
    options = GateOptions(
        fail_on=None if fail_on == "none" else fail_on, fail_on_boundary_crossing=fail_on_boundary_crossing
    )
    try:
        passed, markdown, _ = run_ci(
            server=server, token=token, application=application, source_ref=source_ref, options=options
        )
        click.echo(markdown)
        if output_path:
            output_path.write_text(markdown)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as fh:
                fh.write(markdown)
        if github_comment:
            _post_github_comment(markdown)
    except CiError as exc:
        click.echo(f"kresheen ci: {exc}", err=True)
        sys.exit(2)
    sys.exit(0 if passed else 1)
