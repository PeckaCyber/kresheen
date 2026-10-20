"""Request-time checks that a methodology named by a client is one this installation offers."""

from __future__ import annotations

from collections.abc import Iterable

from fastapi import HTTPException

from kresheen.engine.threats.methodology import CUSTOM, available_methodology_names


def require_available_methodologies(names: Iterable[str], *, allow_custom: bool = True, keep: Iterable[str] = ()) -> None:
    """422 naming every methodology in `names` that is not available. `keep` lists names the record already holds
    (a saved selection that has since become unavailable may stay as it is; only adding one is refused)."""
    allowed = available_methodology_names() | frozenset(keep)
    if allow_custom:
        allowed |= {CUSTOM}
    missing = [n for n in dict.fromkeys(names) if n not in allowed]
    if missing:
        offered = ", ".join(sorted(available_methodology_names()))
        raise HTTPException(
            status_code=422,
            detail=f"Methodology not available in this installation: {', '.join(missing)}. Available: {offered}.",
        )
