#!/usr/bin/env python3
"""Fail when a tracked text file contains invisible or direction-changing characters.

unicode_check.py [<repository dir>]   (default: the current directory)

Bidirectional controls can make code read differently from how it runs ("Trojan Source", CVE-2021-42574), and
zero-width or tag characters can hide text from a reviewer, human or AI. The check flags every format character
(Unicode category Cf: bidi controls, zero-width characters, the byte order mark, tag characters), control characters
other than tab, newline, carriage return and form feed, line and paragraph separators, and the variation selectors
supplement. Files that are not UTF-8 or contain a NUL byte are treated as binary and skipped. Write a character that
is needed on purpose as an escape (for example "\\ufeff"), never as the character itself.
"""

import subprocess
import sys
import unicodedata
from pathlib import Path

ALLOWED_CONTROLS = "\t\n\r\f"


def suspicious(ch: str) -> bool:
    category = unicodedata.category(ch)
    if category == "Cc":
        return ch not in ALLOWED_CONTROLS
    return category in ("Cf", "Zl", "Zp") or 0xE0100 <= ord(ch) <= 0xE01EF


def scan(root: Path) -> list[str]:
    names = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout.split(b"\0")
    found = []
    for name in filter(None, names):
        path = root / name.decode()
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.split("\n"), 1):
            for col, ch in enumerate(line, 1):
                if suspicious(ch):
                    label = unicodedata.name(ch, "unnamed")
                    found.append(f"{name.decode()}:{lineno}:{col}: U+{ord(ch):04X} {label}")
    return found


if __name__ == "__main__":
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    hits = scan(Path(sys.argv[1] if len(sys.argv) == 2 else "."))
    for hit in hits:
        print(hit)
    if hits:
        print(f"{len(hits)} invisible or direction-changing characters; write them as escapes.", file=sys.stderr)
        raise SystemExit(1)
    print("No invisible or direction-changing characters in tracked text files.")
