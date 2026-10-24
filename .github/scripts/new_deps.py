#!/usr/bin/env python3
"""Check packages that a change adds to uv.lock or frontend/package-lock.json for the first time.

new_deps.py <base git ref>

AI coding tools sometimes name packages that do not exist, and attackers register those names ("slopsquatting");
a hijacked or typo-squatted name is new to the lockfile too. Each package whose name is not in the base ref's
lockfile must be a project at least MIN_PROJECT_DAYS old on its registry, at a version published at least
MIN_VERSION_DAYS ago. Version updates of packages already locked are not checked here: Dependabot waits 7 days and
the nightly security fix 3. A deliberate exception goes in .github/new-dependency-allow.txt, one `pypi:<name>` or
`npm:<name>` per line with a comment saying why.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

MIN_PROJECT_DAYS = 90
MIN_VERSION_DAYS = 3
ROOT = Path(__file__).resolve().parents[2]
ALLOW_FILE = ROOT / ".github" / "new-dependency-allow.txt"


def at_ref(ref: str, path: str) -> str | None:
    result = subprocess.run(["git", "-C", str(ROOT), "show", f"{ref}:{path}"], capture_output=True, text=True, check=False)
    return result.stdout if result.returncode == 0 else None


def uv_packages(text: str | None) -> dict[str, str]:
    if not text:
        return {}
    lock = tomllib.loads(text)
    # Registry packages only: the project itself and path or git sources have no registry history to check.
    return {
        p["name"]: p["version"]
        for p in lock.get("package", [])
        if "registry" in (p.get("source") or {})
    }


def npm_packages(text: str | None) -> dict[str, str]:
    if not text:
        return {}
    found = {}
    for path, entry in json.loads(text).get("packages", {}).items():
        if not path or entry.get("link") or "node_modules/" not in path:
            continue
        name = entry.get("name") or path.rsplit("node_modules/", 1)[1]
        found[name] = entry.get("version", "")
    return found


# Package names come from the change being checked, so they are validated before they become part of a URL.
_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$")
_REGISTRIES = ("https://pypi.org/pypi/", "https://registry.npmjs.org/")


def fetch(url: str) -> dict:
    if not url.startswith(_REGISTRIES):
        raise ValueError(f"not a registry URL: {url}")
    with urllib.request.urlopen(url, timeout=30) as response:  # nosemgrep: dynamic-urllib-use-detected (https prefix checked above)
        return json.load(response)


def checked(name: str) -> str:
    if not _NAME.match(name):
        raise ValueError(f"unexpected package name {name!r}")
    return quote(name, safe="@")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value)  # Python 3.11+ reads a trailing Z


def pypi_dates(name: str, version: str) -> tuple[datetime, datetime]:
    data = fetch(f"https://pypi.org/pypi/{checked(name)}/json")
    uploads = [parse_time(f["upload_time_iso_8601"]) for files in data["releases"].values() for f in files]
    version_uploads = [parse_time(f["upload_time_iso_8601"]) for f in data["releases"].get(version, [])]
    if not uploads or not version_uploads:
        raise LookupError(f"no uploads found for {name} {version}")
    return min(uploads), min(version_uploads)


def npm_dates(name: str, version: str) -> tuple[datetime, datetime]:
    times = fetch(f"https://registry.npmjs.org/{checked(name)}")["time"]
    return parse_time(times["created"]), parse_time(times[version])


def main(base: str) -> int:
    allowed = set()
    if ALLOW_FILE.exists():
        allowed = {line.split("#", 1)[0].strip() for line in ALLOW_FILE.read_text().splitlines()} - {""}
    added = []
    for ecosystem, path, reader in (
        ("pypi", "uv.lock", uv_packages),
        ("npm", "frontend/package-lock.json", npm_packages),
    ):
        before, after = reader(at_ref(base, path)), reader((ROOT / path).read_text())
        added += [(ecosystem, name, version) for name, version in sorted(after.items()) if name not in before]
    if not added:
        print("No packages new to the lockfiles.")
        return 0
    now = datetime.now(UTC)
    problems = []
    for ecosystem, name, version in added:
        label = f"{ecosystem}:{name}"
        try:
            created, published = (pypi_dates if ecosystem == "pypi" else npm_dates)(name, version)
        except (OSError, ValueError, KeyError, LookupError) as exc:
            problems.append(f"{label} {version}: could not check the registry ({exc})")
            continue
        project_days, version_days = (now - created).days, (now - published).days
        line = f"{label} {version}: project {project_days} days old, version {version_days} days old"
        young = now - created < timedelta(days=MIN_PROJECT_DAYS) or now - published < timedelta(days=MIN_VERSION_DAYS)
        if young and label not in allowed:
            problems.append(line)
        print(("ok      " if not young else "ALLOWED " if label in allowed else "TOO NEW ") + line)
    if problems:
        print(f"\nNew packages younger than {MIN_PROJECT_DAYS} days (project) or {MIN_VERSION_DAYS} days (version):")
        for problem in problems:
            print(f"  {problem}")
        print(f"Check each is the package you meant (not a look-alike or a name an AI tool made up). If it is, add it "
              f"to {ALLOW_FILE.relative_to(ROOT)} with a comment saying why.")
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    sys.exit(main(sys.argv[1]))
