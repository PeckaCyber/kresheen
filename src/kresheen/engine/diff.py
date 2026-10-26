"""Run-to-run diff: new/removed components, flows, threats and findings
between two ThreatModelRuns of the same Application.

Pure/derive-fresh, like the rest of the threat-generation stack (threats are
derived, never stored): nothing here is persisted, every call
recomputes from each run's already-existing assets/flows/threats/findings.

Assets and Findings have no stable id across runs (only `source="manual"`
Assets, which are Application-scoped rather than run-scoped, keep a stable
id -- see `models/asset.py`) -- both are matched by name here, the same
`<type>:<name>` / `flow:<source>-><target>` convention
`engine/threats/generate.py` and `engine/dfd/merge.py` already use for the
DFD overlay. Threats already carry a stable, name-based `Threat.key`
(`engine/threats/generate.py::component_key`/`flow_key`) -- diffed directly
by that key, no new matching logic needed there.

Findings: `finding_identity_key` below keys on the component's stable
(type, name), because a run's `Finding.asset_id` is that run's ephemeral
`Asset.id`, not an id that survives to the next run.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from kresheen.engine.dfd.merge import MergedDfd, merge_run_dfd
from kresheen.models.asset import Asset
from kresheen.models.finding import Finding
from kresheen.models.threat import Threat
from kresheen.storage.repository import Repository


def component_key(asset: Asset) -> str:
    return f"{asset.type.value}:{asset.name}"


@dataclass(frozen=True)
class ComponentDiffEntry:
    key: str
    type: str
    name: str


@dataclass(frozen=True)
class FlowDiffEntry:
    key: str
    source_name: str
    target_name: str
    # Only populated for `new_flows` (by `build_run_diff`, against the current
    # run's merged DFD): a *new* flow that crosses a trust boundary is what a
    # CI gate cares about (`engine/ci_gate.py`).
    crosses_boundary: bool = False


@dataclass(frozen=True)
class BoundaryChangeEntry:
    """A component present in both runs whose trust boundary differs."""

    name: str
    type: str
    from_boundary: str | None
    to_boundary: str | None


@dataclass(frozen=True)
class ThreatDiffEntry:
    key: str
    title: str
    severity: str


@dataclass(frozen=True)
class FindingDiffEntry:
    key: tuple[str, str]
    title: str
    severity: str
    domain: str


@dataclass(frozen=True)
class RunDiff:
    new_components: list[ComponentDiffEntry] = field(default_factory=list)
    removed_components: list[ComponentDiffEntry] = field(default_factory=list)
    new_flows: list[FlowDiffEntry] = field(default_factory=list)
    removed_flows: list[FlowDiffEntry] = field(default_factory=list)
    new_threats: list[ThreatDiffEntry] = field(default_factory=list)
    resolved_threats: list[ThreatDiffEntry] = field(default_factory=list)
    new_findings: list[FindingDiffEntry] = field(default_factory=list)
    resolved_findings: list[FindingDiffEntry] = field(default_factory=list)
    boundary_changes: list[BoundaryChangeEntry] = field(default_factory=list)


def diff_components(
    previous: MergedDfd, current: MergedDfd
) -> tuple[list[ComponentDiffEntry], list[ComponentDiffEntry]]:
    """New/removed by (type, name) -- an asset's id is this run's ephemeral
    id, never a cross-run identity (see module docstring)."""
    previous_by_key = {component_key(a): a for a in previous.assets}
    current_by_key = {component_key(a): a for a in current.assets}
    new = [
        ComponentDiffEntry(key=k, type=a.type.value, name=a.name)
        for k, a in current_by_key.items()
        if k not in previous_by_key
    ]
    removed = [
        ComponentDiffEntry(key=k, type=a.type.value, name=a.name)
        for k, a in previous_by_key.items()
        if k not in current_by_key
    ]
    return new, removed


def _flow_entries(merged: MergedDfd) -> dict[str, FlowDiffEntry]:
    name_by_id = {asset.id: asset.name for asset in merged.assets}
    entries: dict[str, FlowDiffEntry] = {}
    for edge in merged.edges:
        source_name = name_by_id.get(edge["source"])
        target_name = name_by_id.get(edge["target"])
        if source_name is None or target_name is None:
            continue
        key = f"flow:{source_name}->{target_name}"
        entries.setdefault(key, FlowDiffEntry(key=key, source_name=source_name, target_name=target_name))
    return entries


def diff_flows(previous: MergedDfd, current: MergedDfd) -> tuple[list[FlowDiffEntry], list[FlowDiffEntry]]:
    previous_by_key = _flow_entries(previous)
    current_by_key = _flow_entries(current)
    new = [entry for k, entry in current_by_key.items() if k not in previous_by_key]
    removed = [entry for k, entry in previous_by_key.items() if k not in current_by_key]
    return new, removed


def diff_threats(previous: list[Threat], current: list[Threat]) -> tuple[list[ThreatDiffEntry], list[ThreatDiffEntry]]:
    """Diffed directly by the already-stable `Threat.key` -- no new matching
    logic, unlike components/flows/findings."""
    previous_by_key = {t.key: t for t in previous}
    current_by_key = {t.key: t for t in current}
    new = [
        ThreatDiffEntry(key=k, title=t.title, severity=t.severity)
        for k, t in current_by_key.items()
        if k not in previous_by_key
    ]
    resolved = [
        ThreatDiffEntry(key=k, title=t.title, severity=t.severity)
        for k, t in previous_by_key.items()
        if k not in current_by_key
    ]
    return new, resolved


def finding_identity_key(finding: Finding, assets_by_id: dict[str, Asset]) -> tuple[str, str]:
    """Identity of a finding across runs, from its evidence in priority order
    (first CVE -> stride_category:title -> title), keyed on the finding's
    component's stable (type, name) instead of the run-scoped
    `asset_id`. Falls back to the raw `asset_id` only if it doesn't
    resolve against this run's assets (shouldn't happen for a well-formed
    run, but a dangling reference must still key to *something* rather than
    crash the diff)."""
    evidence = finding.evidence
    if evidence.cve_refs:
        detail = evidence.cve_refs[0]
    elif evidence.stride_category:
        detail = f"{evidence.stride_category}:{finding.title}"
    else:
        detail = finding.title
    asset = assets_by_id.get(finding.asset_id)
    identity = component_key(asset) if asset is not None else finding.asset_id
    return (identity, detail)


def diff_findings(
    previous: list[Finding],
    previous_assets: dict[str, Asset],
    current: list[Finding],
    current_assets: dict[str, Asset],
) -> tuple[list[FindingDiffEntry], list[FindingDiffEntry]]:
    previous_by_key = {finding_identity_key(f, previous_assets): f for f in previous}
    current_by_key = {finding_identity_key(f, current_assets): f for f in current}
    new = [
        FindingDiffEntry(key=k, title=f.title, severity=f.severity.value, domain=f.domain.value)
        for k, f in current_by_key.items()
        if k not in previous_by_key
    ]
    resolved = [
        FindingDiffEntry(key=k, title=f.title, severity=f.severity.value, domain=f.domain.value)
        for k, f in previous_by_key.items()
        if k not in current_by_key
    ]
    return new, resolved


def _mark_boundary_crossings(
    flows: list[FlowDiffEntry], application_id: str, run_id: str, repo: Repository
) -> list[FlowDiffEntry]:
    if not flows:
        return flows
    # Imported here: the threat-generation stack imports this module's siblings,
    # and only flows that actually changed need the (heavier) merged element model.
    from kresheen.engine.threats.generate import crosses_boundary
    from kresheen.engine.threats.service import load_dfd_model

    elements, _ = load_dfd_model(application_id, run_id, repo)
    by_name = {e.name: e for e in elements}
    marked = []
    for flow in flows:
        source, target = by_name.get(flow.source_name), by_name.get(flow.target_name)
        crossing = source is not None and target is not None and crosses_boundary(source, target)
        marked.append(replace(flow, crosses_boundary=crossing))
    return marked


def diff_boundaries(
    application_id: str, previous_run_id: str, current_run_id: str, repo: Repository
) -> list[BoundaryChangeEntry]:
    from kresheen.engine.threats.service import load_dfd_model

    previous, _ = load_dfd_model(application_id, previous_run_id, repo)
    current, _ = load_dfd_model(application_id, current_run_id, repo)
    before = {(e.type, e.name): e.trust_boundary for e in previous}
    changes = [
        BoundaryChangeEntry(
            name=e.name, type=e.type, from_boundary=before[(e.type, e.name)], to_boundary=e.trust_boundary
        )
        for e in current
        if (e.type, e.name) in before and before[(e.type, e.name)] != e.trust_boundary
    ]
    return sorted(changes, key=lambda c: c.name)


def build_run_diff(
    application_id: str,
    previous_run_id: str,
    current_run_id: str,
    repo: Repository,
    *,
    previous_threats: list[Threat],
    current_threats: list[Threat],
) -> RunDiff:
    """Composes the merged DFD (assets/flows) and already-generated threat
    lists for both runs -- the caller supplies `previous_threats`/
    `current_threats` since generating them (`generate_run_threats`) needs
    the application/run context the route layer already has, and doing it
    here too would mean generating threats twice per run on every diff."""
    previous_dfd = merge_run_dfd(application_id, previous_run_id, repo)
    current_dfd = merge_run_dfd(application_id, current_run_id, repo)

    new_components, removed_components = diff_components(previous_dfd, current_dfd)
    new_flows, removed_flows = diff_flows(previous_dfd, current_dfd)
    new_flows = _mark_boundary_crossings(new_flows, application_id, current_run_id, repo)
    new_threats, resolved_threats = diff_threats(previous_threats, current_threats)

    previous_assets_by_id = {a.id: a for a in previous_dfd.assets}
    current_assets_by_id = {a.id: a for a in current_dfd.assets}
    new_findings, resolved_findings = diff_findings(
        repo.list_findings(run_id=previous_run_id),
        previous_assets_by_id,
        repo.list_findings(run_id=current_run_id),
        current_assets_by_id,
    )

    return RunDiff(
        new_components=new_components,
        removed_components=removed_components,
        new_flows=new_flows,
        removed_flows=removed_flows,
        new_threats=new_threats,
        resolved_threats=resolved_threats,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        boundary_changes=diff_boundaries(application_id, previous_run_id, current_run_id, repo),
    )
