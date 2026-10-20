"""Text hygiene shared by the report renderers."""

from __future__ import annotations

import re

# Characters XML 1.0 forbids (most C0 controls, lone surrogates, U+FFFE/U+FFFF).
# python-docx raises on them and an SVG containing one is not well formed, so
# user-typed text is cleaned before it reaches either.
_XML_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")


def clean_text(value: object) -> str:
    return _XML_ILLEGAL.sub("", "" if value is None else str(value))
