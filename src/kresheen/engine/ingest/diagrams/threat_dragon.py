"""OWASP Threat Dragon JSON (v2 `detail.diagrams[].cells`, and the older `diagramJson.cells`).

Beyond the boxes and arrows this reads what Threat Dragon knows and the earlier importer threw
away: the element type (actor, process, store), trust-boundary boxes (a component sits in the
smallest box that contains its centre) and the properties ticked on an element or flow. Trust
boundary *curves* have no area to contain anything and are not imported, and threats already
listed in the file are not imported: they are re-derived from the model like any other.
"""

from __future__ import annotations

from typing import Any

from kresheen.engine.ingest.diagrams.model import (
    DiagramComponent,
    DiagramFlow,
    ParsedDiagram,
    clean_name,
    finish,
)

_TYPE_BY_SHAPE = {"actor": "external_entity", "process": "process", "store": "data_store"}
_TYPE_BY_TM = {"tm.Actor": "external_entity", "tm.Process": "process", "tm.Store": "data_store"}
_BOUNDARY_SHAPES = {"trust-boundary-box"}
_BOUNDARY_TM = {"tm.BoundaryBox"}
_IGNORED_SHAPES = {"td-text-block", "trust-boundary-curve"}
_IGNORED_TM = {"tm.Text", "tm.Boundary"}

# Threat Dragon field -> this platform's property key, per element kind.
_COMPONENT_PROPERTIES = {
    "data_store": {"isEncrypted": "is_encrypted", "storesCredentials": "stores_credentials", "isALog": "is_a_log", "isSigned": "is_signed"},
    "process": {"isWebApplication": "is_web_application"},
    "external_entity": {},
}
_FLOW_PROPERTIES = {"isEncrypted": "is_encrypted", "isPublicNetwork": "crosses_public_network"}


def looks_like_threat_dragon(parsed: Any) -> bool:
    if not isinstance(parsed, dict):
        return False
    detail = parsed.get("detail")
    return isinstance(detail, dict) and isinstance(detail.get("diagrams"), list)


def _cells(parsed: dict) -> list[dict]:
    cells: list[dict] = []
    for diagram in parsed["detail"]["diagrams"]:
        if not isinstance(diagram, dict):
            continue
        found = diagram.get("cells")
        if found is None and isinstance(diagram.get("diagramJson"), dict):
            found = diagram["diagramJson"].get("cells")
        cells.extend(c for c in found or [] if isinstance(c, dict))
    return cells


def _kind(cell: dict) -> str:
    """component | boundary | flow | ignore"""
    data = _data(cell)
    shape = cell.get("shape") or ""
    tm_type = data.get("type") or cell.get("type") or ""
    if isinstance(cell.get("source"), (dict, str)) and isinstance(cell.get("target"), (dict, str)):
        return "flow"
    if shape in _BOUNDARY_SHAPES or tm_type in _BOUNDARY_TM:
        return "boundary"
    if shape in _IGNORED_SHAPES or tm_type in _IGNORED_TM:
        return "ignore"
    return "component"


def _data(cell: dict) -> dict:
    data = cell.get("data")
    return data if isinstance(data, dict) else {}


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _rect(cell: dict) -> tuple[float, float, float, float] | None:
    position, size = cell.get("position"), cell.get("size")
    if not isinstance(position, dict) or not isinstance(size, dict):
        return None
    x, y, w, h = _number(position.get("x")), _number(position.get("y")), _number(size.get("width")), _number(size.get("height"))
    if None in (x, y, w, h):
        return None
    return x, y, w, h  # type: ignore[return-value]


def _ref(value: Any) -> str | None:
    if isinstance(value, dict):
        cell = value.get("cell")
        return cell if isinstance(cell, str) else None
    return value if isinstance(value, str) else None


def parse_threat_dragon(parsed: dict) -> ParsedDiagram | None:
    cells = _cells(parsed)
    boundaries: list[tuple[str, float, tuple[float, float, float, float]]] = []
    for cell in cells:
        if _kind(cell) != "boundary":
            continue
        rect = _rect(cell)
        data = _data(cell)
        if rect is not None:
            boundaries.append((clean_name(data.get("name") or "Trust boundary"), rect[2] * rect[3], rect))

    diagram = ParsedDiagram(format="threat_dragon")
    for cell in cells:
        if _kind(cell) != "component" or not isinstance(cell.get("id"), str):
            continue
        data = _data(cell)
        shape = cell.get("shape") or ""
        tm_type = data.get("type") or cell.get("type") or ""
        # An unknown shape is still a component (this importer's original behaviour); a process is the safe guess.
        node_type = _TYPE_BY_SHAPE.get(shape) or _TYPE_BY_TM.get(tm_type) or "process"
        boundary = None
        rect = _rect(cell)
        if rect is not None:
            cx, cy = rect[0] + rect[2] / 2, rect[1] + rect[3] / 2
            containing = [b for b in boundaries if b[2][0] <= cx <= b[2][0] + b[2][2] and b[2][1] <= cy <= b[2][1] + b[2][3]]
            if containing:
                boundary = min(containing, key=lambda b: b[1])[0]
        stated: dict[str, bool | str] = {
            ours: True for theirs, ours in _COMPONENT_PROPERTIES[node_type].items() if data.get(theirs) is True
        }
        diagram.components.append(
            DiagramComponent(key=cell["id"], name=clean_name(data.get("name") or "unknown-component"), type=node_type, boundary=boundary, properties=stated)
        )

    for cell in cells:
        if _kind(cell) != "flow":
            continue
        source, target = _ref(cell.get("source")), _ref(cell.get("target"))
        if source is None or target is None:
            continue
        data = _data(cell)
        properties: dict[str, bool | str] = {ours: True for theirs, ours in _FLOW_PROPERTIES.items() if data.get(theirs) is True}
        protocol = data.get("protocol")
        if isinstance(protocol, str) and protocol.strip():
            properties["protocol"] = clean_name(protocol)
        label = data.get("name")
        diagram.flows.append(
            DiagramFlow(source=source, target=target, label=clean_name(label) if isinstance(label, str) and label.strip() else None, properties=properties)
        )
    return finish(diagram)
