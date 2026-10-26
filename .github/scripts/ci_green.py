#!/usr/bin/env python3
"""Wait until the required workflows have finished successfully for a commit.

Usage: ci_green.py <sha> [--workflows "ci codeql"] [--timeout-minutes 45] [--dispatch-missing]

Exit 0: every required workflow has a completed, successful latest run for the commit.
Exit 1: a required workflow failed, was cancelled, or did not finish (or never started) before the timeout.
Needs GH_TOKEN and GH_REPO in the environment. With --dispatch-missing, a required workflow that has no run at all
for the commit after a grace period is started on main (only meaningful when the commit is the head of main).
"""

import argparse
import json
import os
import subprocess
import sys
import time

GOOD = {"success"}


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def latest_runs(repo: str, sha: str) -> dict[str, dict]:
    out = gh(
        "api",
        "--paginate",
        f"repos/{repo}/actions/runs?head_sha={sha}&per_page=100",
        "--jq",
        ".workflow_runs[]",
    )
    runs = [json.loads(line) for line in out.splitlines() if line.strip()]
    latest: dict[str, dict] = {}
    for r in sorted(runs, key=lambda r: r["created_at"]):
        latest[r["name"]] = r
    return latest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sha")
    ap.add_argument("--workflows", default="ci codeql")
    ap.add_argument("--timeout-minutes", type=int, default=45)
    ap.add_argument("--dispatch-missing", action="store_true")
    a = ap.parse_args()
    repo = os.environ["GH_REPO"]
    required = a.workflows.split()
    deadline = time.time() + a.timeout_minutes * 60
    started = time.time()
    dispatched: set[str] = set()
    while True:
        runs = latest_runs(repo, a.sha)
        pending, bad = [], []
        for name in required:
            r = runs.get(name)
            if r is None:
                pending.append(f"{name} (no run yet)")
            elif r["status"] != "completed":
                pending.append(f"{name} ({r['status']})")
            elif r["conclusion"] not in GOOD:
                bad.append(f"{name}: {r['conclusion']} {r['html_url']}")
        if bad:
            print("Not green:", *bad, sep="\n  ")
            return 1
        if not pending:
            print(f"All required workflows are green for {a.sha}: {', '.join(required)}")
            return 0
        if a.dispatch_missing and time.time() - started > 180:
            for name in required:
                if name not in runs and name not in dispatched:
                    print(f"No {name} run for {a.sha} after 3 minutes; dispatching it on main")
                    subprocess.run(["gh", "workflow", "run", f"{name}.yml", "--ref", "main"], check=True)
                    dispatched.add(name)
        if time.time() > deadline:
            print("Timed out waiting for:", *pending, sep="\n  ")
            return 1
        print("Waiting for:", ", ".join(pending), flush=True)
        time.sleep(60)


if __name__ == "__main__":
    sys.exit(main())
