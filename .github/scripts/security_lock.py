#!/usr/bin/env python3
"""Helpers for the security-lock job (security-nightly.yml). Reads pip-audit JSON.

security_lock.py fixable <audit.json>            print one package name per line that has a fixed version available
security_lock.py body <before.json> <after.json>  print the pull request body (Markdown)
"""

import json
import sys


def load(path: str) -> list[dict]:
    with open(path) as f:
        data = json.load(f)
    return [d for d in data.get("dependencies", []) if d.get("vulns")]


def fixable(path: str) -> list[str]:
    return sorted({d["name"] for d in load(path) if any(v.get("fix_versions") for v in d["vulns"])})


def clean(text: str, limit: int = 200) -> str:
    one = " ".join(str(text).split())
    return (one[: limit - 1] + "...") if len(one) > limit else one


def body(before: str, after: str) -> str:
    remaining = {(d["name"], v["id"]) for d in load(after) for v in d["vulns"]}
    lines = [
        "Automated security update of `uv.lock`, opened by the nightly security workflow.",
        "",
        "pip-audit reported these advisories against `main` with a fixed version available.",
        "The lock was updated with `uv lock --upgrade-package` (pyproject constraints still apply).",
        "",
        "| Package | Installed | Advisory | Fixed in | After this PR |",
        "| --- | --- | --- | --- | --- |",
    ]
    for d in load(before):
        for v in d["vulns"]:
            if not v.get("fix_versions"):
                continue
            state = "still affected" if (d["name"], v["id"]) in remaining else "fixed"
            fixed = ", ".join(v["fix_versions"])
            lines.append(f"| {d['name']} | {d['version']} | {v['id']} | {fixed} | {state} |")
    left = [f"- {n}: {i}" for n, i in sorted(remaining)]
    if left:
        lines += [
            "",
            "Advisories still reported after the update (no fix released, or blocked by a constraint):",
            *left,
        ]
    lines += [
        "",
        "Merging waits for the required checks. After the merge, `security-release.yml` decides whether a patch release is due.",
    ]
    return "\n".join(clean(l, 400) if l.startswith("- ") else l for l in lines) + "\n"


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "fixable" and len(sys.argv) == 3:
        # No output at all when nothing is fixable: the workflow tests the file for emptiness.
        for name in fixable(sys.argv[2]):
            print(name)
    elif cmd == "body" and len(sys.argv) == 4:
        sys.stdout.write(body(sys.argv[2], sys.argv[3]))
    else:
        raise SystemExit(__doc__)
