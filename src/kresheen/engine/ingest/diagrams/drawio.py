"""draw.io / diagrams.net files (`.drawio`, `.xml`), uncompressed or compressed.

Vertices become components (typed from the shape style: cylinders and database shapes are data
stores, actor and user shapes are external entities, everything else a process); edges with both
ends on a component become flows. A zone is a swimlane or container shape, or a dashed rectangle
that geometrically contains other shapes; a component sits in the smallest zone containing its
centre. Free text, images without a label, and edges that dangle are ignored.

XML is parsed with defusedxml, and compressed pages are inflated with a hard output cap so a small
file cannot expand into memory (a decompression bomb).
"""

from __future__ import annotations

import base64
import html
import re
import zlib
from urllib.parse import unquote
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from kresheen.engine.ingest.diagrams.model import (
    MAX_CONTENT_CHARS,
    DiagramComponent,
    DiagramFlow,
    ParsedDiagram,
    clean_name,
    finish,
)

_MAX_INFLATED_BYTES = 10_000_000
_TAG = re.compile(r"<[^>]*>")
_DATA_STORE = re.compile(r"cylinder|database|datastore|data_store|mxgraph\.flowchart\.database|rds|bucket|dynamodb", re.IGNORECASE)
_EXTERNAL = re.compile(r"actor|umlactor|mxgraph\.[a-z0-9_.]*users?\b|shape=mxgraph\.[a-z0-9_.]*\.user", re.IGNORECASE)


def looks_like_drawio(content: str) -> bool:
    head = content.lstrip()[:2000].lower()
    return head.startswith("<") and ("<mxfile" in head or "<mxgraphmodel" in head)


def _label(value: str | None) -> str:
    if not value:
        return ""
    text = _TAG.sub(" ", value.replace("<br>", " ").replace("<br/>", " ").replace("</div>", " "))
    return clean_name(html.unescape(text))


def _inflate(payload: str) -> str | None:
    """draw.io's compressed page: base64 of raw-deflate of the URL-encoded XML."""
    try:
        raw = base64.b64decode(payload.strip(), validate=False)
        inflater = zlib.decompressobj(-15)
        data = inflater.decompress(raw, _MAX_INFLATED_BYTES)
        if inflater.unconsumed_tail:  # more output than the cap allows
            return None
        return unquote(data.decode("utf-8", errors="replace"))
    except (ValueError, zlib.error):
        return None


def _models(root: Element) -> list[Element]:
    if root.tag == "mxGraphModel":
        return [root]
    models: list[Element] = []
    for page in root.iter("diagram"):
        inner = page.find("mxGraphModel")
        if inner is not None:
            models.append(inner)
        elif page.text and page.text.strip():
            xml = _inflate(page.text)
            if xml:
                try:
                    parsed = SafeET.fromstring(xml)
                except (SafeET.ParseError, DefusedXmlException):
                    continue
                if parsed.tag == "mxGraphModel":
                    models.append(parsed)
    return models


def _cells(model: Element) -> list[dict]:
    """Flattens mxCell (and the object/UserObject wrappers that carry a label and id) into dicts."""
    cells: list[dict] = []
    for element in model.iter():
        if element.tag == "mxCell":
            cell = element
            wrapper = None
        elif element.tag in ("object", "UserObject"):
            cell = element.find("mxCell")  # type: ignore[assignment]
            wrapper = element
            if cell is None:
                continue
        else:
            continue
        if element.tag == "mxCell" and element.get("id") is None:
            continue
        source = wrapper if wrapper is not None else cell
        geometry = cell.find("mxGeometry")
        cells.append(
            {
                "id": source.get("id"),
                "label": _label(source.get("label") if wrapper is not None else source.get("value")),
                "style": (cell.get("style") or "").lower(),
                "vertex": cell.get("vertex") == "1",
                "edge": cell.get("edge") == "1",
                "source": cell.get("source"),
                "target": cell.get("target"),
                "parent": cell.get("parent"),
                "geometry": None
                if geometry is None
                else tuple(_num(geometry.get(k)) for k in ("x", "y", "width", "height")),
            }
        )
    return cells


def _num(value: str | None) -> float:
    try:
        return float(value) if value is not None else 0.0
    except ValueError:
        return 0.0


def _absolute(cell: dict, by_id: dict[str, dict]) -> tuple[float, float, float, float] | None:
    """Geometry is relative to the parent container, so add the parent chain up."""
    if cell["geometry"] is None:
        return None
    x, y, w, h = cell["geometry"]
    seen: set[str] = set()
    parent = by_id.get(cell["parent"] or "")
    while parent is not None and parent["id"] not in seen:
        seen.add(parent["id"])
        if parent["geometry"] is not None and parent["vertex"]:
            x += parent["geometry"][0]
            y += parent["geometry"][1]
        parent = by_id.get(parent["parent"] or "")
    return x, y, w, h


def _component_type(style: str) -> str:
    if _DATA_STORE.search(style):
        return "data_store"
    if _EXTERNAL.search(style):
        return "external_entity"
    return "process"


def _parse_model(model: Element, page: int) -> ParsedDiagram:
    cells = _cells(model)
    by_id = {c["id"]: c for c in cells if c["id"]}
    vertices = [c for c in cells if c["vertex"] and c["id"]]
    rects = {c["id"]: _absolute(c, by_id) for c in vertices}
    has_children = {c["parent"] for c in vertices if c["parent"] in by_id and by_id[c["parent"]]["vertex"]}

    def contains(outer: tuple[float, float, float, float], inner: tuple[float, float, float, float]) -> bool:
        cx, cy = inner[0] + inner[2] / 2, inner[1] + inner[3] / 2
        return outer[0] <= cx <= outer[0] + outer[2] and outer[1] <= cy <= outer[1] + outer[3]

    boundary_ids: set[str] = set()
    for cell in vertices:
        style, rect = cell["style"], rects[cell["id"]]
        if "swimlane" in style or "container=1" in style or cell["id"] in has_children:
            boundary_ids.add(cell["id"])
        elif "dashed=1" in style and rect is not None and rect[2] * rect[3] > 0:
            # A dashed rectangle drawn behind other shapes is the usual way to draw a zone.
            others = [r for i, r in rects.items() if i != cell["id"] and r is not None]
            if any(contains(rect, other) for other in others):
                boundary_ids.add(cell["id"])

    diagram = ParsedDiagram(format="drawio")
    zone_rects: list[tuple[str, tuple[float, float, float, float]]] = []
    for zone_id in boundary_ids:
        zone_rect = rects[zone_id]
        if zone_rect is not None and by_id[zone_id]["label"]:
            zone_rects.append((by_id[zone_id]["label"], zone_rect))
    connected = {c["source"] for c in cells if c["edge"]} | {c["target"] for c in cells if c["edge"]}
    for cell in vertices:
        if cell["id"] in boundary_ids or not cell["label"]:
            continue
        # Free-text annotations are not components unless something is connected to them.
        if cell["style"].startswith("text;") and cell["id"] not in connected:
            continue
        rect = rects[cell["id"]]
        zone = None
        if rect is not None and zone_rects:
            inside = [(name, r) for name, r in zone_rects if contains(r, rect)]
            if inside:
                zone = min(inside, key=lambda z: z[1][2] * z[1][3])[0]
        diagram.components.append(
            DiagramComponent(key=f"{page}:{cell['id']}", name=cell["label"], type=_component_type(cell["style"]), boundary=zone)
        )

    for cell in cells:
        if cell["edge"] and cell["source"] and cell["target"]:
            diagram.flows.append(
                DiagramFlow(source=f"{page}:{cell['source']}", target=f"{page}:{cell['target']}", label=cell["label"] or None)
            )
    return diagram


def parse_drawio(content: str) -> ParsedDiagram | None:
    if len(content) > MAX_CONTENT_CHARS:
        return None
    try:
        root = SafeET.fromstring(content)
    except (SafeET.ParseError, DefusedXmlException):
        return None
    combined = ParsedDiagram(format="drawio")
    for page, model in enumerate(_models(root)):
        parsed = _parse_model(model, page)
        combined.components.extend(parsed.components)
        combined.flows.extend(parsed.flows)
    return finish(combined)
