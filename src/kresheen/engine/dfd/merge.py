"""Resolves one run's DFD the way the user sees it, shared by the DFD route,
threat generation, and the validation harness so they always agree on what
the diagram contains."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from kresheen.models.asset import Asset
from kresheen.models.diagram_layout import DiagramElementLayout
from kresheen.storage.repository import Repository

logger = logging.getLogger(__name__)


def _hidden(layout_by_key: dict[str, DiagramElementLayout], key: str) -> bool:
    layout = layout_by_key.get(key)
    return layout is not None and layout.hidden


@dataclass
class MergedDfd:
    assets: list[Asset]
    manual_asset_ids: set[str]
    boundary_by_name: dict[str, str]
    edges: list[dict]
    # Owner-stated properties by element key (`<type>:<name>`, `flow:<a>-><b>`).
    properties_by_key: dict[str, dict]
    # Diagram-scoped visual state (position overrides, boundary-group
    # positions); empty unless `diagram_id` was given. Never affects which
    # threats get generated -- only `assets`/`edges` do, and those are only
    # filtered (never added to) by a diagram's hidden elements.
    layout_by_key: dict[str, DiagramElementLayout] = field(default_factory=dict)


def _layer_properties(file_stated: dict[str, dict], owner_stated: dict[str, dict]) -> dict[str, dict]:
    """File-stated facts underneath, owner-stated on top: the owner's word always wins, per key."""
    keys = file_stated.keys() | owner_stated.keys()
    return {key: {**file_stated.get(key, {}), **owner_stated.get(key, {})} for key in keys}


def merge_run_dfd(application_id: str, run_id: str, repo: Repository, diagram_id: str | None = None) -> MergedDfd:
    """Resolves one run's DFD the way the user sees it: this run's
    auto-generated assets and flows, plus the Application's manual assets,
    manual flows, and trust-boundary overrides, matched by component *name*.
    Shared by the DFD route and threat generation so both always agree on
    what the diagram contains.

    `diagram_id=None` (the default, and always what threat generation and
    the validation harness pass) means "no diagram filtering" -- every
    element is included, exactly as before diagrams existed. Callers that
    render one diagram's canvas (engine/dfd/view.py, always with a resolved
    diagram, never None) get hidden components/flows dropped and manual/
    boundary positions taken from that diagram's `DiagramElementLayout`
    rows instead of the legacy Application-wide fields."""
    run_assets = repo.list_assets_for_run(run_id)
    manual_assets = repo.list_manual_assets_for_application(application_id)
    all_assets = run_assets + manual_assets
    flows = repo.list_asset_flows_for_run(run_id)

    boundary_by_name = {
        assignment.component_name: assignment.trust_boundary
        for assignment in repo.list_trust_boundary_assignments(application_id)
    }

    layout_by_key: dict[str, DiagramElementLayout] = {}
    if diagram_id is not None:
        layout_by_key = {layout.element_key: layout for layout in repo.list_diagram_element_layouts(diagram_id)}
        all_assets = [asset for asset in all_assets if not _hidden(layout_by_key, f"{asset.type.value}:{asset.name}")]

    manual_asset_ids = {asset.id for asset in all_assets if asset.source == "manual"}
    name_to_id: dict[str, str] = {}
    for asset in all_assets:
        name_to_id.setdefault(asset.name, asset.id)
    name_by_id = {asset.id: asset.name for asset in all_assets}
    valid_ids = set(name_by_id)

    def _flow_key(source_id: str, target_id: str) -> str:
        return f"flow:{name_by_id.get(source_id)}->{name_by_id.get(target_id)}"

    def _flow_hidden(source_id: str, target_id: str) -> bool:
        return _hidden(layout_by_key, _flow_key(source_id, target_id))

    edges = [
        {
            "id": flow.id,
            "source": flow.source_asset_id,
            "target": flow.target_asset_id,
            "label": flow.label,
            "is_manual": False,
        }
        for flow in flows
        if flow.source_asset_id in valid_ids
        and flow.target_asset_id in valid_ids
        and not _flow_hidden(flow.source_asset_id, flow.target_asset_id)
    ]

    def _resolve_ref(ref: str) -> str | None:
        if ref.startswith("asset:"):
            candidate = ref.removeprefix("asset:")
            return candidate if candidate in manual_asset_ids else None
        if ref.startswith("name:"):
            return name_to_id.get(ref.removeprefix("name:"))
        return None

    for manual_flow in repo.list_manual_flows(application_id):
        source_id = _resolve_ref(manual_flow.source_ref)
        target_id = _resolve_ref(manual_flow.target_ref)
        if source_id is None or target_id is None:
            logger.warning(
                "Skipping manual flow %r for run %r -- could not resolve %r -> %r against this run's assets "
                "(or its endpoint is hidden on this diagram)",
                manual_flow.id,
                run_id,
                manual_flow.source_ref,
                manual_flow.target_ref,
            )
            continue
        if _flow_hidden(source_id, target_id):
            continue
        edges.append(
            {
                "id": manual_flow.id,
                "source": source_id,
                "target": target_id,
                "label": manual_flow.label,
                "is_manual": True,
            }
        )

    # Facts an ingested file states about its own elements and flows (a Threat Dragon "encrypted" tick,
    # a Threagile protocol). Asset and flow ids are their facts' ids, so this is a direct lookup.
    file_stated: dict[str, dict] = {}
    node_stated: dict[str, dict] = {
        n.id: n.attributes["stated_properties"]
        for n in repo.list_fact_nodes_for_run(run_id)
        if n.attributes.get("stated_properties")
    }
    for asset in run_assets:
        if asset.id in node_stated:
            file_stated[f"{asset.type.value}:{asset.name}"] = dict(node_stated[asset.id])
    edge_stated: dict[str, dict] = {
        e.id: e.attributes["stated_properties"]
        for e in repo.list_fact_edges_for_run(run_id)
        if e.attributes.get("stated_properties")
    }
    for flow in flows:
        if flow.id in edge_stated and flow.source_asset_id in valid_ids and flow.target_asset_id in valid_ids:
            file_stated[_flow_key(flow.source_asset_id, flow.target_asset_id)] = dict(edge_stated[flow.id])

    return MergedDfd(
        assets=all_assets,
        manual_asset_ids=manual_asset_ids,
        boundary_by_name=boundary_by_name,
        edges=edges,
        properties_by_key=_layer_properties(
            file_stated,
            {record.element_key: dict(record.properties) for record in repo.list_element_properties(application_id)},
        ),
        layout_by_key=layout_by_key,
    )
