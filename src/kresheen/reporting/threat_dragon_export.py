"""The DFD as an OWASP Threat Dragon v2 model file, for round-tripping a scanned
or hand-built model into the standalone Threat Dragon app.

Export-only / one-directional: `engine/ingest/architecture_diagram_ingestor.py`
still treats every non-flow cell as a generic `process` on import and drops
trust boundaries and element properties entirely (see that module's
docstring) -- that asymmetry is pre-existing and not addressed here. This
module only needs to produce a well-formed Threat Dragon file; it never has
to read one back.

Cell geometry reuses `dfd_svg.layout()` (the same box positions the SVG/print
report render) so the shapes land in the same place a Threat Dragon user
would see on our own diagram -- one geometry source, three renderers.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from kresheen.models.application import Application
from kresheen.reporting.dfd_svg import layout
from kresheen.reporting.model import ReportBoundary, ReportComponent, ReportFlow
from kresheen.reporting.text import clean_text

_SHAPE_BY_TYPE = {"process": "process", "data_store": "store", "external_entity": "actor"}


def _component_cell(component: ReportComponent, box) -> dict[str, Any]:
    return {
        "id": component.id,
        "shape": _SHAPE_BY_TYPE.get(component.type, "process"),
        "position": {"x": box.x, "y": box.y},
        "size": {"width": box.w, "height": box.h},
        "attrs": {"text": {"text": clean_text(component.name)}},
        "data": {
            "name": clean_text(component.name),
            "description": "; ".join(clean_text(s) for s in component.statements),
            "outOfScope": component.out_of_scope,
            "reasonOutOfScope": clean_text(component.out_of_scope_reason),
        },
    }


def _boundary_cell(name: str, box) -> dict[str, Any]:
    return {
        "id": f"boundary:{name}",
        "shape": "trust-boundary-box",
        "position": {"x": box.x, "y": box.y},
        "size": {"width": box.w, "height": box.h},
        "attrs": {"text": {"text": clean_text(name)}},
        "data": {"name": clean_text(name)},
    }


def _flow_cell(flow: ReportFlow) -> dict[str, Any]:
    return {
        "id": flow.id,
        "shape": "flow",
        "source": {"cell": flow.source_id},
        "target": {"cell": flow.target_id},
        "attrs": {"text": {"text": clean_text(flow.label or "")}},
        "data": {
            "name": clean_text(flow.label or ""),
            "description": "; ".join(clean_text(s) for s in flow.statements),
            "outOfScope": flow.out_of_scope,
            "reasonOutOfScope": clean_text(flow.out_of_scope_reason),
        },
    }


def build_threat_dragon_model(
    application: Application,
    components: Sequence[ReportComponent],
    flows: Sequence[ReportFlow],
    boundaries: Sequence[ReportBoundary],
) -> dict[str, Any]:
    nodes, group_boxes = layout(components, boundaries)
    cells: list[dict[str, Any]] = [_boundary_cell(name, box) for name, box in group_boxes]
    cells.extend(_component_cell(c, nodes[c.id]) for c in components if c.id in nodes)
    cells.extend(_flow_cell(f) for f in flows if f.source_id in nodes and f.target_id in nodes)

    return {
        "version": "2.4.0",
        "summary": {
            "title": clean_text(application.name),
            "owner": clean_text(application.owner),
            "description": clean_text(application.description),
        },
        "detail": {
            "contributors": [{"name": clean_text(c)} for c in application.contributors],
            "diagrams": [
                {
                    "id": 0,
                    "title": clean_text(application.name) or "Main Diagram",
                    "diagramType": "STRIDE",
                    "cells": cells,
                }
            ],
        },
    }
