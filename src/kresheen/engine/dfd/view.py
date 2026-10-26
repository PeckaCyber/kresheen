"""One run's DFD as the user sees it, shaped for the API and the report.

Shared by the DFD route and the report exporters (reporting/) so they always
agree on what the diagram contains. Everything is resolved fresh on every call,
never persisted pre-joined (see merge_run_dfd)."""

from __future__ import annotations

from kresheen.engine.dfd.merge import merge_run_dfd
from kresheen.storage.repository import Repository

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _position(layout_position: float | None, legacy_position: float | None) -> float | None:
    return layout_position if layout_position is not None else legacy_position


def build_run_dfd(
    application_id: str, run_id: str, repo: Repository, diagram_id: str | None = None
) -> tuple[list[dict], list[dict], list[dict]]:
    """Returns (nodes, edges, boundaries).

    Merges three things: (1) this run's auto-generated Assets/AssetFlows,
    regenerated from scratch every execution; (2) this Application's manual
    Assets (source="manual", run_id=None -- never touched by a run's
    regenerate-in-place delete, so they appear on every run's diagram); (3) this
    Application's ManualFlows, TrustBoundaryAssignments and stated element
    properties, resolved by component *name* against whichever nodes ended up
    in (1)+(2) for this specific request -- see models/trust_boundary.py and
    models/manual_flow.py for why name-based resolution is required (Asset ids
    aren't stable across runs, by design).

    `diagram_id`, when given, additionally drops elements hidden on that
    diagram and prefers its saved positions -- see merge_run_dfd's
    docstring. Callers rendering a canvas always resolve and pass one
    (dashboard/routes/api_applications.py's `get_run_dfd`); threat
    generation and the validation harness never do."""
    merged = merge_run_dfd(application_id, run_id, repo, diagram_id)

    nodes = []
    for asset in merged.assets:
        is_manual = asset.id in merged.manual_asset_ids
        # Manual assets are user-authored, never produced by a rule check --
        # no Finding's asset_id can ever equal one, so skip the lookup
        # rather than run a query guaranteed to return nothing.
        open_findings = [] if is_manual else repo.list_findings(run_id=run_id, asset_id=asset.id, status="open")
        worst = min((f.severity.value for f in open_findings), key=SEVERITY_ORDER.index, default=None)
        layout = merged.layout_by_key.get(f"{asset.type.value}:{asset.name}") if is_manual else None
        legacy_x = asset.position_x if is_manual else None
        legacy_y = asset.position_y if is_manual else None
        position_x = _position(layout.position_x if layout else None, legacy_x)
        position_y = _position(layout.position_y if layout else None, legacy_y)
        nodes.append(
            {
                "id": asset.id,
                "name": asset.name,
                "type": asset.type.value,
                "trust_boundary": merged.boundary_by_name.get(asset.name, asset.trust_boundary),
                # True when the label comes from a user TrustBoundaryAssignment
                # (vs. auto-derived); lets undo restore "no override" exactly.
                "boundary_overridden": asset.name in merged.boundary_by_name,
                "worst_severity": worst,
                "open_finding_count": len(open_findings),
                "is_manual": is_manual,
                # Only meaningful for a manual asset -- see Asset.position_x/y's
                # docstring for why an auto-generated (ephemeral-id) node never
                # carries one. A diagram's own saved position (DiagramElementLayout)
                # takes precedence over the legacy Application-wide value.
                "position_x": position_x,
                "position_y": position_y,
                "properties": merged.properties_by_key.get(f"{asset.type.value}:{asset.name}", {}),
            }
        )

    name_by_id = {asset.id: asset.name for asset in merged.assets}
    edges = [
        {
            **edge,
            "properties": merged.properties_by_key.get(
                f"flow:{name_by_id.get(edge['source'])}->{name_by_id.get(edge['target'])}", {}
            ),
        }
        for edge in merged.edges
    ]

    boundaries = []
    if diagram_id is not None:
        # Every saved boundary-position row on this diagram, regardless of
        # whether a component currently uses that boundary name (a boundary
        # can be positioned ahead of, or after losing, its last member).
        boundaries = [
            {"name": key.removeprefix("boundary:"), "position_x": layout.position_x, "position_y": layout.position_y}
            for key, layout in merged.layout_by_key.items()
            if key.startswith("boundary:") and layout.position_x is not None and layout.position_y is not None
        ]
    return nodes, edges, boundaries
