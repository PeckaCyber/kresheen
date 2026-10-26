#!/usr/bin/env python3
"""Helpers for security-release.yml.

security_release.py plan                      print latest=, next=, commits_since=, pending= (for $GITHUB_OUTPUT)
security_release.py diff <released.json> <main.json> <fixed.json>
      Grype JSON of the released image and of an image built from main. Writes the High/Critical findings with a
      fix that the released image has and main no longer has, and prints count=N.
security_release.py advisories <tag pip.json> <tag npm.json> <main pip.json> <main npm.json> <fixed.json>
      pip-audit JSON and `npm audit --json` of a superseded tag and of main. Writes the advisories the tag has and main
      no longer has, in the format of `diff`, and prints count=N.
security_release.py bump <next version> <fixed.json> <YYYY-MM-DD> [<superseded tag>]
      Set the version in pyproject.toml, uv.lock, deploy/helm/kresheen/Chart.yaml and add a CHANGELOG entry. With a
      superseded tag (tagged, never published), the entry says this release carries that tag's changes.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STABLE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def version_key(v: str) -> tuple[int, int, int]:
    m = STABLE.match(v if v.startswith("v") else f"v{v}")
    return (int(m[1]), int(m[2]), int(m[3])) if m else (-1, -1, -1)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True, cwd=ROOT).stdout.strip()


def project_version() -> str:
    m = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.MULTILINE)
    assert m, "no version in pyproject.toml"
    return m[1]


def plan() -> None:
    tags = [t for t in git("tag", "-l", "v*").split() if STABLE.match(t)]
    if not tags:
        print("latest=")
        return
    latest = max(tags, key=version_key)
    major, minor, patch = version_key(latest)
    nxt = f"{major}.{minor}.{patch + 1}"
    print(f"latest={latest}")
    print(f"next={nxt}")
    print(f"commits_since={git('rev-list', '--count', f'{latest}..HEAD')}")
    # A version above the latest tag at HEAD means a release bump is merged and only waits for its tag.
    print(f"pending={'true' if version_key(project_version()) > version_key(latest) else 'false'}")
    print(f"tag_exists={'true' if f'v{nxt}' in tags else 'false'}")


def findings(path: str) -> dict[tuple[str, str], dict]:
    out = {}
    for m in json.loads(Path(path).read_text()).get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        fix = v.get("fix", {})
        if v.get("severity") in ("High", "Critical") and fix.get("state") == "fixed":
            out[(v["id"], a["name"])] = {
                "id": v["id"],
                "severity": v["severity"],
                "package": a["name"],
                "installed": a["version"],
                "fixed_in": fix.get("versions", []),
            }
    return out


def diff(released: str, main: str, outfile: str) -> None:
    before, after = findings(released), findings(main)
    fixed = [before[k] for k in sorted(before) if k not in after]
    Path(outfile).write_text(json.dumps(fixed, indent=2))
    print(f"count={len(fixed)}")


def audit_findings(pip_path: str, npm_path: str) -> dict[tuple[str, str], dict]:
    out = {}
    pip = json.loads(Path(pip_path).read_text() or "{}")
    for d in pip.get("dependencies", []):
        for v in d.get("vulns", []):
            out[(v["id"], d["name"])] = {
                "id": v["id"],
                "severity": None,
                "package": d["name"],
                "installed": d["version"],
                "fixed_in": v.get("fix_versions", []),
            }
    npm = json.loads(Path(npm_path).read_text() or "{}")
    for name, v in npm.get("vulnerabilities", {}).items():
        for via in v.get("via", []):
            if isinstance(via, dict):  # a string means "vulnerable through that package", reported under its own name
                adv = via.get("url", "").rsplit("/", 1)[-1] or str(via.get("source"))
                out[(adv, name)] = {
                    "id": adv,
                    "severity": str(via.get("severity", "")).capitalize() or None,
                    "package": name,
                    "installed": v.get("range", ""),
                    "fixed_in": [],
                }
    return out


def advisories(tag_pip: str, tag_npm: str, main_pip: str, main_npm: str, outfile: str) -> None:
    before, after = audit_findings(tag_pip, tag_npm), audit_findings(main_pip, main_npm)
    fixed = [before[k] for k in sorted(before) if k not in after]
    Path(outfile).write_text(json.dumps(fixed, indent=2))
    print(f"count={len(fixed)}")


def bump(version: str, fixed_path: str, date: str, superseded: str = "") -> None:
    fixed = json.loads(Path(fixed_path).read_text())
    old = project_version()
    py = ROOT / "pyproject.toml"
    py.write_text(
        re.sub(
            r'^version = "[^"]+"',
            f'version = "{version}"',
            py.read_text(),
            count=1,
            flags=re.MULTILINE,
        )
    )
    lock = ROOT / "uv.lock"
    text, n = re.subn(
        r'(\[\[package\]\]\nname = "kresheen"\nversion = ")[^"]+(")',
        rf"\g<1>{version}\2",
        lock.read_text(),
    )
    assert n == 1, "kresheen entry not found in uv.lock"
    lock.write_text(text)
    chart = ROOT / "deploy/helm/kresheen/Chart.yaml"
    t = chart.read_text()
    t = re.sub(r"^version: .*$", f"version: {version}", t, flags=re.MULTILINE)
    t = re.sub(r"^appVersion: .*$", f'appVersion: "{version}"', t, flags=re.MULTILINE)
    chart.write_text(t)
    lines = [f"## [{version}] - {date}", "", "### Security", ""]
    seen = set()
    for f in fixed:
        sev = f" ({f['severity']})" if f.get("severity") else ""
        fix = f", fixed in {', '.join(f['fixed_in'])}" if f.get("fixed_in") else ""
        line = f"- {f['id']}{sev}: {f['package']} {f['installed']}{fix}."
        if line not in seen:
            seen.add(line)
            lines.append(line)
    if superseded:
        lines += [
            "",
            f"{superseded} was tagged but never published: these advisories appeared before its release finished.",
            f"This release carries the changes listed under {old} below.",
            "",
        ]
    else:
        lines += ["", f"No other changes since {old}.", ""]
    cl = ROOT / "CHANGELOG.md"
    c = cl.read_text()
    m = re.search(r"^## \[Unreleased\][^\n]*\n", c, re.MULTILINE)
    assert m, "no [Unreleased] heading in CHANGELOG.md"
    cl.write_text(c[: m.end()] + "\n" + "\n".join(lines) + "\n" + c[m.end() :].lstrip("\n"))


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["plan"]:
        plan()
    elif a[:1] == ["diff"] and len(a) == 4:
        diff(*a[1:])
    elif a[:1] == ["advisories"] and len(a) == 6:
        advisories(*a[1:])
    elif a[:1] == ["bump"] and len(a) in (4, 5):
        bump(*a[1:])
    else:
        raise SystemExit(__doc__)
