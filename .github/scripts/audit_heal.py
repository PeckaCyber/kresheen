#!/usr/bin/env python3
"""Helpers for audit-heal.yml.

audit_heal.py classify <run id>
      Print kind= for $GITHUB_OUTPUT: `vuln` when only audit jobs failed and their logs report vulnerabilities,
      `transient` when only audit jobs failed without such a report (advisory service down, network), `other` when
      anything else failed.
audit_heal.py wait-fix <since, ISO 8601 UTC> [--timeout-minutes 90]
      Wait for the security-lock fix started at <since>. Exit 0 when a security/ PR by the App merged after <since>
      and none is open, 2 when the security-nightly runs since <since> finished without one (nothing fixable), 1 on
      timeout or when the PR was closed without merging.

Needs GH_TOKEN and GH_REPO in the environment; wait-fix also BOT_LOGIN (the App's bot login).
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

FAILED = {"failure", "timed_out", "cancelled"}
# pip-audit: "Found 1 known vulnerability in 1 package". npm audit: "# npm audit report" and "2 vulnerabilities (1 high,
# 1 critical)". An outage prints neither: pip-audit raises a connection error, npm says the audit endpoint failed.
VULN = re.compile(
    r"Found [1-9]\d* known vulnerabilit|# npm audit report|\b[1-9]\d* vulnerabilit(?:y|ies) \(",
)


def gh_lines(*args: str) -> list[dict]:
    out = subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def is_audit(name: str) -> bool:
    return name == "audit" or name.endswith("/ audit")


def classify(run_id: str) -> str:
    repo = os.environ["GH_REPO"]
    jobs = gh_lines(
        "api",
        "--paginate",
        f"repos/{repo}/actions/runs/{run_id}/jobs?filter=latest&per_page=100",
        "--jq",
        ".jobs[]",
    )
    failed = [j for j in jobs if j.get("conclusion") in FAILED]
    print(f"failed={','.join(j['name'] for j in failed)}", file=sys.stderr)
    if not failed or not all(is_audit(j["name"]) for j in failed):
        return "other"
    for j in failed:
        log = subprocess.run(
            ["gh", "api", f"repos/{repo}/actions/jobs/{j['id']}/logs"],
            check=False,
            capture_output=True,
            text=True,
        ).stdout
        if VULN.search(log):
            return "vuln"
    return "transient"


def wait_fix(since: str, timeout_minutes: int) -> int:
    repo, bot = os.environ["GH_REPO"], os.environ["BOT_LOGIN"]
    deadline = time.time() + timeout_minutes * 60
    while True:
        prs = [
            p
            for p in gh_lines(
                "api",
                f"repos/{repo}/pulls?state=all&sort=updated&direction=desc&per_page=30",
                "--jq",
                ".[]",
            )
            if p["user"]["login"] == bot
            and p["head"]["ref"].startswith("security/")
            and p["head"]["repo"]
            and p["head"]["repo"]["full_name"] == repo
            and p["updated_at"] >= since
        ]
        open_prs = [p for p in prs if p["state"] == "open"]
        merged = [p for p in prs if p.get("merged_at") and p["merged_at"] >= since]
        closed = [p for p in prs if p["state"] == "closed" and not p.get("merged_at")]
        if open_prs:
            print("Waiting for:", ", ".join(p["html_url"] for p in open_prs), flush=True)
        elif merged:
            print("Fix merged:", ", ".join(p["html_url"] for p in merged))
            return 0
        elif closed:
            print("Fix PR closed without merging:", ", ".join(p["html_url"] for p in closed))
            return 1
        else:
            runs = gh_lines(
                "api",
                f"repos/{repo}/actions/workflows/security-nightly.yml/runs?created=>={since}&per_page=20",
                "--jq",
                ".workflow_runs[]",
            )
            if runs and all(r["status"] == "completed" for r in runs):
                print(
                    "security-nightly finished without a fix PR: nothing fixable (no fixed version, or blocked)."
                )
                return 2
            print("Waiting for security-nightly to open the fix PR", flush=True)
        if time.time() > deadline:
            print(f"Timed out after {timeout_minutes} minutes.")
            return 1
        time.sleep(60)


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["classify"] and len(a) == 2:
        print(f"kind={classify(a[1])}")
    elif a[:1] == ["wait-fix"]:
        ap = argparse.ArgumentParser(prog="audit_heal.py wait-fix")
        ap.add_argument("since")
        ap.add_argument("--timeout-minutes", type=int, default=90)
        o = ap.parse_args(a[1:])
        sys.exit(wait_fix(o.since, o.timeout_minutes))
    else:
        raise SystemExit(__doc__)
