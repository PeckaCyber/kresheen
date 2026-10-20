"""API response shapes for `engine/attack_paths.py`. Mirrors
`models/run_diff.py`'s split: the engine module has its own dataclasses,
these are the Pydantic projections the route returns."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AttackPathHopOut(BaseModel):
    from_name: str
    to_name: str
    flow_label: str | None
    crosses_boundary: bool
    authenticated: bool | None
    encrypted: bool | None


class AttackPathOut(BaseModel):
    source_name: str
    target_name: str
    target_type: str
    is_crown_jewel: bool
    risk: str
    risk_factors: list[str]
    boundary_crossings: int
    hops: list[AttackPathHopOut]


class AttackPathsOut(BaseModel):
    paths: list[AttackPathOut] = Field(default_factory=list)
