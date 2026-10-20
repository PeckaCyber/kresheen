"""API response shapes for `engine/diff.py`'s run-to-run diff. Mirrors
`models/threat.py`'s `Threat`/`ThreatOut` split: the engine module has its
own dataclasses, these are the Pydantic projections the route returns."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ComponentDiffOut(BaseModel):
    key: str
    type: str
    name: str


class FlowDiffOut(BaseModel):
    key: str
    source_name: str
    target_name: str
    crosses_boundary: bool = False


class ThreatDiffOut(BaseModel):
    key: str
    title: str
    severity: str


class FindingDiffOut(BaseModel):
    title: str
    severity: str
    domain: str


class BoundaryChangeOut(BaseModel):
    name: str
    type: str
    from_boundary: str | None = None
    to_boundary: str | None = None


class RunDiffOut(BaseModel):
    current_run_id: str
    # None when there is no completed run to compare against (this is the
    # application's first run) -- every list below is empty in that case.
    previous_run_id: str | None = None
    new_components: list[ComponentDiffOut] = Field(default_factory=list)
    removed_components: list[ComponentDiffOut] = Field(default_factory=list)
    new_flows: list[FlowDiffOut] = Field(default_factory=list)
    removed_flows: list[FlowDiffOut] = Field(default_factory=list)
    new_threats: list[ThreatDiffOut] = Field(default_factory=list)
    resolved_threats: list[ThreatDiffOut] = Field(default_factory=list)
    new_findings: list[FindingDiffOut] = Field(default_factory=list)
    resolved_findings: list[FindingDiffOut] = Field(default_factory=list)
    boundary_changes: list[BoundaryChangeOut] = Field(default_factory=list)
