#!/usr/bin/env python3
"""Licence policy for the application's own dependencies (Python packages in the image, npm packages in the
frontend lock file), read from syft JSON. OS packages and the bundled Grype binary's Go modules are left out:
they are system components shipped as separate programs, not libraries Kresheen links.

Strong copyleft or source-available licences fail; weak copyleft (LGPL, MPL, EPL) is allowed and listed for the
record; a package with no licence metadata is a warning unless KNOWN below says what it is.

Usage: licence_check.py <syft.json>...
"""

from __future__ import annotations

import json
import os
import re
import sys

DENY = re.compile(r"(?<!L)\bA?GPL|SSPL|BUSL|Business Source|Commons-Clause|CC-BY-NC|Elastic-2\.0|EUPL", re.IGNORECASE)
WEAK = re.compile(r"\bLGPL|MPL|EPL-", re.IGNORECASE)
CHECKED_TYPES = {"python", "npm"}
# Packages whose metadata carries no licence field, checked by hand against the upstream repository.
KNOWN = {
    ("python", "jinja2"): "BSD-3-Clause",
    ("python", "kresheen"): "Apache-2.0 (this project)",
    ("python", "reportlab"): "BSD-3-Clause (ReportLab's own wording)",
    ("npm", "kresheen-dashboard"): "Apache-2.0 (this project's frontend)",
}


def acceptable(expression: str) -> bool:
    """True when at least one alternative of an `A OR B` expression is not a denied licence."""
    return any(not DENY.search(option) for option in re.split(r"\s+OR\s+", expression))


def licences(artifact: dict) -> list[str]:
    return sorted(
        {entry.get("spdxExpression") or entry.get("value") or "" for entry in artifact.get("licenses", [])} - {""}
    )


def main(paths: list[str]) -> int:
    denied, weak, unknown, seen = [], [], [], set()
    for path in paths:
        with open(path) as f:
            artifacts = json.load(f).get("artifacts", [])
        for artifact in artifacts:
            kind, name = artifact.get("type"), artifact.get("name", "")
            key = (kind, name.lower())
            if kind not in CHECKED_TYPES or key in seen:
                continue
            seen.add(key)
            found = licences(artifact)
            text = " | ".join(found)
            row = f"{kind} {name} {artifact.get('version', '')}: {text or KNOWN.get(key, 'no licence metadata')}"
            if not found:
                if key not in KNOWN:
                    unknown.append(row)
            elif not any(acceptable(expression) for expression in found):
                denied.append(row)
            elif WEAK.search(text):
                weak.append(row)
    lines = [f"Checked {len(seen)} Python and npm packages."]
    for title, rows in (("Not allowed", denied), ("Weak copyleft (allowed)", weak), ("No licence metadata", unknown)):
        if rows:
            lines += ["", f"{title}:", *(f"- {r}" for r in sorted(rows))]
    report = "\n".join(lines)
    print(report)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as f:
            f.write("## Licence check\n\n" + report + "\n")
    for row in unknown:
        print(f"::warning title=Licence unknown::{row}")
    return 1 if denied else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    sys.exit(main(sys.argv[1:]))
