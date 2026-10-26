#!/usr/bin/env python3
"""Helpers for the security-lock job (security-nightly.yml). Reads pip-audit JSON.

security_lock.py fixable <audit.json>            print one package name per line that has a fixed version available
security_lock.py cutoffs <audit.json> <uv.lock> <min age days> <kev.json>
                                                 print "<package> <cutoff>" per fixable package: only versions uploaded
                                                 before the cutoff may be picked ("none" for a CISA KEV advisory)
security_lock.py strip-options <uv.lock>         remove the exclude-newer-package table `uv lock` records
security_lock.py npm-kev <npm-audit.json> <kev.json>
                                                 print "yes" when an npm advisory is in CISA KEV
security_lock.py body <before.json> <after.json>  print the pull request body (Markdown)

The minimum age keeps the nightly fix from picking a version published hours ago: most malicious releases are
found and pulled within a day or two. An advisory in CISA's Known Exploited Vulnerabilities catalog skips the wait.
"""

import json
import os
import re
import sys
import tomllib
import urllib.request
from datetime import UTC, datetime, timedelta


def load(path: str) -> list[dict]:
    with open(path) as f:
        data = json.load(f)
    return [d for d in data.get("dependencies", []) if d.get("vulns")]


def fixable(path: str) -> list[str]:
    return sorted({d["name"] for d in load(path) if any(v.get("fix_versions") for v in d["vulns"])})


def load_kev(path: str) -> set[str]:
    """CVE ids in the CISA KEV feed; empty (so the wait applies) when the feed could not be read."""
    try:
        with open(path) as f:
            return {v["cveID"] for v in json.load(f)["vulnerabilities"]}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(
            f"::warning::CISA KEV feed unreadable ({exc}); the minimum age applies to every package.", file=sys.stderr
        )
        return set()


def locked_upload_times(lock_path: str) -> dict[str, datetime]:
    """Latest upload time of each package's locked files (uv records it per wheel and sdist)."""
    with open(lock_path, "rb") as f:
        lock = tomllib.load(f)
    times: dict[str, datetime] = {}
    for pkg in lock.get("package", []):
        files = [pkg.get("sdist", {}), *pkg.get("wheels", [])]
        stamps = [datetime.fromisoformat(x["upload-time"]) for x in files if x.get("upload-time")]
        if stamps:
            times[pkg["name"]] = max(stamps)
    return times


def cutoffs(audit: str, lock_path: str, min_age_days: int, kev_path: str) -> list[tuple[str, str]]:
    kev = load_kev(kev_path)
    uploaded = locked_upload_times(lock_path)
    oldest_allowed = datetime.now(UTC) - timedelta(days=min_age_days)
    out = []
    for d in load(audit):
        if not any(v.get("fix_versions") for v in d["vulns"]):
            continue
        ids = {i for v in d["vulns"] for i in [v["id"], *v.get("aliases", [])]}
        if min_age_days <= 0 or ids & kev:
            out.append((d["name"], "none"))
            continue
        # Never earlier than the locked version's upload: that would downgrade a package locked recently.
        cut = max(oldest_allowed, uploaded.get(d["name"], oldest_allowed))
        out.append((d["name"], cut.strftime("%Y-%m-%dT%H:%M:%SZ")))
    return sorted(set(out))


def strip_options(lock_path: str) -> None:
    """Drop what `--exclude-newer-package` records in uv.lock, or `uv sync --locked` without the flag fails."""
    with open(lock_path) as f:
        text = f.read()
    text = re.sub(r"\[options\.exclude-newer-package\]\n(?:[^\[\n].*\n)*\n?", "", text)
    text = re.sub(r"\[options\]\n\n(?=\[|$)", "", text)
    if "exclude-newer" in text:
        raise SystemExit(f"{lock_path} still records an exclude-newer option; not stripping by hand")
    with open(lock_path, "w") as f:
        f.write(text)


def npm_kev(audit_path: str, kev_path: str) -> bool:
    kev = load_kev(kev_path)
    with open(audit_path) as f:
        report = json.load(f)
    ghsas = {
        m.group(0)
        for v in report.get("vulnerabilities", {}).values()
        for via in v.get("via", [])
        if isinstance(via, dict) and (m := re.search(r"GHSA(-[0-9a-z]{4}){3}", via.get("url", "")))
    }
    token = os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})}
    for ghsa in sorted(ghsas):
        req = urllib.request.Request(f"https://api.github.com/advisories/{ghsa}", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                cve = json.load(r).get("cve_id")
        except (OSError, ValueError) as exc:
            print(f"::warning::could not look up {ghsa} ({exc})", file=sys.stderr)
            continue
        if cve in kev:
            return True
    return False


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
    elif cmd == "cutoffs" and len(sys.argv) == 6:
        for name, cut in cutoffs(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]):
            print(name, cut)
    elif cmd == "strip-options" and len(sys.argv) == 3:
        strip_options(sys.argv[2])
    elif cmd == "npm-kev" and len(sys.argv) == 4:
        print("yes" if npm_kev(sys.argv[2], sys.argv[3]) else "no")
    elif cmd == "body" and len(sys.argv) == 4:
        sys.stdout.write(body(sys.argv[2], sys.argv[3]))
    else:
        raise SystemExit(__doc__)
