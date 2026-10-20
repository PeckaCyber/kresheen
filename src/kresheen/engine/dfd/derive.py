"""Derives a run's DFD by walking its FactNode/FactEdge graph and writing
`Asset`/`AssetFlow` rows tagged `source="threat_model_run"` -- a mechanical
re-projection of that run's already-computed facts, never a catalog icon
picked by matching `node_type` against a stored component library. This
reuses `Asset`/`AssetFlow` (rather than a parallel DFD model) specifically
so the existing Map page's React Flow rendering, severity rollup, and
click-through panel work unchanged for engine-produced runs.

Only *diagram-worthy* facts become nodes. A `vulnerability` fact would
render as its own box (colored by its severity) and a `sbom_document` fact as
a meaningless extra box, so metadata-only fact types must be excluded rather
than coerced into a generic component. `_DIAGRAM_WORTHY_NODE_TYPES` is an
explicit allowlist: a fact whose type isn't on it is skipped, not coerced.
`reference_document` (uploaded architecture-diagram/documentation facts
that weren't parseable) is deliberately excluded too, for the same reason
`vulnerability`/`sbom_document` are -- it's a data carrier about the run's
inputs, not a system component, exactly like the other two.
"""

from __future__ import annotations

from kresheen.models.asset import Asset, AssetFlow, AssetType
from kresheen.models.facts import FactEdge, FactNode

_DIAGRAM_WORTHY_NODE_TYPES = frozenset({"process", "data_store", "external_entity", "code_artifact"})
DIAGRAM_WORTHY_NODE_TYPES = _DIAGRAM_WORTHY_NODE_TYPES  # public alias for engine/source_status.py
"""Facts that represent a real system component and should render as a DFD
box. Everything else (`vulnerability`, `sbom_document`, `reference_document`,
and any future metadata-only fact type) is excluded by construction --
adding a new enrichment-only fact type must never require touching this
file to keep it off the diagram, since it's simply not on the allowlist."""


def _asset_type_for(node_type: str) -> AssetType:
    if node_type == "code_artifact":
        return AssetType.PROCESS
    return AssetType(node_type)  # process/data_store/external_entity map directly


def derive_dfd(nodes: list[FactNode], edges: list[FactEdge]) -> tuple[list[Asset], list[AssetFlow]]:
    diagram_nodes = [node for node in nodes if node.node_type in _DIAGRAM_WORTHY_NODE_TYPES]
    diagram_node_ids = {node.id for node in diagram_nodes}
    assets = [
        Asset(
            # Reuses the FactNode's own id directly -- one-to-one, no
            # separate id-mapping table between "fact" and "diagram node."
            id=node.id,
            name=node.name,
            type=_asset_type_for(node.node_type),
            trust_boundary=node.attributes.get("trust_boundary"),
            source="threat_model_run",
            application_id=node.application_id,
            run_id=node.run_id,
            created_at=node.discovered_at,
        )
        for node in diagram_nodes
    ]
    flows = [
        AssetFlow(
            id=edge.id,
            source_asset_id=edge.source_node_id,
            target_asset_id=edge.target_node_id,
            label=edge.label or edge.edge_type,
            application_id=edge.application_id,
            run_id=edge.run_id,
        )
        for edge in edges
        # An edge to/from an excluded (non-diagram-worthy) node would be a
        # dangling reference on the rendered DFD -- skip it rather than
        # pointing at an Asset that was never created.
        if edge.source_node_id in diagram_node_ids and edge.target_node_id in diagram_node_ids
    ]
    return assets, flows
