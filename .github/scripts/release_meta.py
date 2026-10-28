#!/usr/bin/env python3
"""Release helpers used by release.yml and security-release.yml.

release_meta.py check <tag-or-empty>   verify pyproject.toml, Chart.yaml and CHANGELOG.md agree (and with the tag),
                                       then print version=..., prerelease=... lines for $GITHUB_OUTPUT
release_meta.py notes <version>        print the CHANGELOG.md section for that version (exit 1 if there is none)
release_meta.py provenance <tag> <previous tag or empty> <actor> <bot login> <sha> <run url> <changelog file>
                                       print the release notes: a provenance block, then the CHANGELOG section

The provenance block says why the release exists (who pushed the tag; for the security bot, the advisories it
names, or that it tagged a merged release pull request), the commit, and every commit since the previous release, flagging any that did not come through a pull
request. The maintainer reads it in the release email and follows the compromise runbook when it does not match.
"""

import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")


def project_version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def chart_fields() -> dict[str, str]:
    fields = {}
    for line in (ROOT / "deploy/helm/kresheen/Chart.yaml").read_text().splitlines():
        m = re.match(r"^(version|appVersion):\s*\"?([^\"\s#]+)\"?", line)
        if m:
            fields[m.group(1)] = m.group(2)
    return fields


def changelog_section(version: str) -> str | None:
    text = (ROOT / "CHANGELOG.md").read_text()
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.DOTALL | re.MULTILINE)
    return m.group(1).strip() if m else None


def check(tag: str) -> int:
    version = project_version()
    problems = []
    if not SEMVER.match(version):
        problems.append(f"pyproject.toml version {version!r} is not a semantic version")
    chart = chart_fields()
    for key in ("version", "appVersion"):
        if chart.get(key) != version:
            problems.append(f"Chart.yaml {key} is {chart.get(key)!r}, pyproject.toml is {version!r}")
    if tag:
        if tag != f"v{version}":
            problems.append(f"tag {tag!r} does not match pyproject.toml version {version!r}")
        if changelog_section(version) is None:
            problems.append(f"CHANGELOG.md has no '## [{version}]' section")
        elif re.search(
            rf"^## \[{re.escape(version)}\][^\n]*unreleased",
            (ROOT / "CHANGELOG.md").read_text(),
            re.MULTILINE | re.IGNORECASE,
        ):
            problems.append(f"CHANGELOG.md still marks {version} as unreleased: put the release date in the heading")
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"version={version}")
    print(f"prerelease={'true' if '-' in version else 'false'}")
    return 0


ADVISORY = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})\b")
PR_REF = re.compile(r"\(#\d+\)$")
SECURITY_PR = re.compile(r"^Release v\S+ \(security\)")


def provenance(tag: str, prev: str, actor: str, bot: str, sha: str, run_url: str, changelog: str) -> str:
    notes = Path(changelog).read_text().strip() if Path(changelog).exists() else ""
    subject = subprocess.run(
        ["git", "log", "-1", "--format=%s", sha], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    if bot and actor == bot and SECURITY_PR.match(subject):
        ids = sorted(set(ADVISORY.findall(notes)))
        started = f"automatic security patch release by `{actor}`" + (f" for {', '.join(ids)}" if ids else "")
    elif bot and actor == bot:
        # security-release.yml also tags a maintainer's merged release bump once the required checks pass.
        started = f"release pull request merged to main, tag `{tag}` created by `{actor}` after the required checks"
    else:
        started = f"tag `{tag}` pushed by `{actor}`"
    lines = [
        "**Provenance**",
        "",
        f"- Started by: {started}",
        f"- Commit: `{sha}`",
        f"- Build: {run_url}",
    ]
    if prev:
        out = subprocess.run(
            ["git", "log", "--first-parent", "--format=%s", f"{prev}..{sha}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        # "@" would notify whoever it names; commit subjects come from the repository, not from this script.
        subjects = [s.replace("@", "(at)") for s in out.splitlines() if s.strip()]
        direct = [s for s in subjects if not PR_REF.search(s)]
        lines.append(f"- Changes since {prev}: {len(subjects)} commits")
        lines += [f"  - {s}" for s in subjects[:40]]
        if len(subjects) > 40:
            lines.append(f"  - ... and {len(subjects) - 40} more")
        lines.append(f"- Commits without a pull request: {len(direct)}" + (" (check these)" if direct else ""))
    else:
        lines.append("- Changes: first release (no earlier release to compare with)")
    repo_url = run_url.split("/actions/")[0]
    lines += ["", f"How to verify this release: {repo_url}/blob/{sha}/docs/releases.md", "", "---", ""]
    return "\n".join(lines) + "\n" + (notes or "No CHANGELOG section for this version.") + "\n"


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "check" and len(sys.argv) == 3:
        raise SystemExit(check(sys.argv[2]))
    if cmd == "notes" and len(sys.argv) == 3:
        section = changelog_section(sys.argv[2])
        if section is None:
            raise SystemExit(1)
        print(section)
    elif cmd == "provenance" and len(sys.argv) == 9:
        sys.stdout.write(provenance(*sys.argv[2:9]))
    else:
        raise SystemExit(__doc__)
