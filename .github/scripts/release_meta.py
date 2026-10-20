#!/usr/bin/env python3
"""Release helpers used by release.yml and security-release.yml.

release_meta.py check <tag-or-empty>   verify pyproject.toml, Chart.yaml and CHANGELOG.md agree (and with the tag),
                                       then print version=..., prerelease=... lines for $GITHUB_OUTPUT
release_meta.py notes <version>        print the CHANGELOG.md section for that version (exit 1 if there is none)
"""

import re
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
    m = re.search(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.DOTALL | re.MULTILINE
    )
    return m.group(1).strip() if m else None


def check(tag: str) -> int:
    version = project_version()
    problems = []
    if not SEMVER.match(version):
        problems.append(f"pyproject.toml version {version!r} is not a semantic version")
    chart = chart_fields()
    for key in ("version", "appVersion"):
        if chart.get(key) != version:
            problems.append(
                f"Chart.yaml {key} is {chart.get(key)!r}, pyproject.toml is {version!r}"
            )
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
            problems.append(
                f"CHANGELOG.md still marks {version} as unreleased: put the release date in the heading"
            )
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"version={version}")
    print(f"prerelease={'true' if '-' in version else 'false'}")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "check" and len(sys.argv) == 3:
        raise SystemExit(check(sys.argv[2]))
    if cmd == "notes" and len(sys.argv) == 3:
        section = changelog_section(sys.argv[2])
        if section is None:
            raise SystemExit(1)
        print(section)
    else:
        raise SystemExit(__doc__)
