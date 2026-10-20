"""The data flow diagram as a standalone SVG, for the HTML report and `dfd.svg`.

Pure Python (no cairo, no browser): the layout mirrors the on-screen diagram
(`layoutNodes` in frontend/src/pages/ApplicationDetail.tsx) so a report looks
like what the user built: trust-boundary boxes stacked (or where the user
dragged them), members in a 3-column grid inside them, hand-placed components
where they were dropped, everything else in a 4-column grid below.

Every piece of text is user-controlled (component names, boundary labels, flow
labels), so it goes through `clean_text` and XML escaping; nothing is ever
interpolated into markup unescaped.

Known limit: edges are straight lines, so on a dense diagram one can pass
through a node it is not connected to.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from xml.sax.saxutils import escape

from kresheen.reporting.model import ReportBoundary, ReportComponent, ReportFlow
from kresheen.reporting.text import clean_text

# Same numbers as the frontend layout.
NODE_CELL_W = 200
NODE_CELL_H = 70
NODE_W = 180
NODE_H = 50
GROUP_PADDING = 40
GROUP_HEADER = 30
GROUP_COLUMNS = 3
UNGROUPED_COLUMNS = 4
UNGROUPED_STEP_X = 220
UNGROUPED_STEP_Y = 140
MARGIN = 30

_SEVERITY_FILL = {
    "critical": ("#dc3545", "#ffffff"),
    "high": ("#fd7e14", "#000000"),
    "medium": ("#ffc107", "#000000"),
    "low": ("#0dcaf0", "#000000"),
    "info": ("#6c757d", "#ffffff"),
}
_CLEAR_FILL = ("#198754", "#ffffff")
_LINE_CHARS = 24


@dataclass(frozen=True)
class _Box:
    x: float
    y: float
    w: float
    h: float

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def cy(self) -> float:
        return self.y + self.h / 2


def _e(text: object) -> str:
    return escape(clean_text(text), {'"': "&quot;", "'": "&apos;"})


def layout(
    components: Sequence[ReportComponent], boundaries: Sequence[ReportBoundary]
) -> tuple[dict[str, _Box], list[tuple[str, _Box]]]:
    """Returns (node boxes by component id, [(boundary label, box)])."""
    saved = {b.name: b for b in boundaries}
    groups: dict[str, list[ReportComponent]] = {}
    ungrouped: list[ReportComponent] = []
    for component in components:
        if component.trust_boundary:
            groups.setdefault(component.trust_boundary, []).append(component)
        else:
            ungrouped.append(component)

    nodes: dict[str, _Box] = {}
    group_boxes: list[tuple[str, _Box]] = []
    top = 0.0
    for name, members in groups.items():
        cols = min(GROUP_COLUMNS, len(members))
        rows = math.ceil(len(members) / cols)
        width = cols * NODE_CELL_W + GROUP_PADDING * 2
        height = rows * NODE_CELL_H + GROUP_PADDING * 2 + GROUP_HEADER
        origin = saved.get(name)
        gx, gy = (origin.position_x, origin.position_y) if origin else (0.0, top)
        group_boxes.append((name, _Box(gx, gy, width, height)))
        for index, member in enumerate(members):
            nodes[member.id] = _Box(
                gx + GROUP_PADDING + (index % cols) * NODE_CELL_W,
                gy + GROUP_PADDING + GROUP_HEADER + (index // cols) * NODE_CELL_H,
                NODE_W,
                NODE_H,
            )
        top += height + GROUP_PADDING

    placed = [c for c in ungrouped if c.is_manual and c.position_x is not None and c.position_y is not None]
    gridded = [c for c in ungrouped if c not in placed]
    for component in placed:
        nodes[component.id] = _Box(component.position_x or 0.0, component.position_y or 0.0, NODE_W, NODE_H)
    for index, component in enumerate(gridded):
        nodes[component.id] = _Box(
            (index % UNGROUPED_COLUMNS) * UNGROUPED_STEP_X,
            top + (index // UNGROUPED_COLUMNS) * UNGROUPED_STEP_Y,
            NODE_W,
            NODE_H,
        )
    return nodes, group_boxes


def _wrap(name: str) -> list[str]:
    """At most two lines, breaking at spaces and after `/`, `-` and `_` (so
    `PersistentVolumeClaim/app-data` splits at the slash, not mid-word); the
    second line is truncated with an ellipsis."""
    tokens = [t for t in re.split(r"(?<=[/\-_])|\s+", clean_text(name)) if t]
    lines: list[str] = []
    current = ""
    for token in tokens:
        while len(token) > _LINE_CHARS:
            if current:
                lines.append(current)
                current = ""
            lines.append(token[:_LINE_CHARS])
            token = token[_LINE_CHARS:]
        joiner = "" if current.endswith(("/", "-", "_")) else " "
        if current and len(current) + len(joiner) + len(token) > _LINE_CHARS:
            lines.append(current)
            current = token
        else:
            current = f"{current}{joiner}{token}" if current else token
    if current:
        lines.append(current)
    if len(lines) > 2:
        lines = [lines[0], lines[1][: _LINE_CHARS - 1] + "…"]
    return lines or [""]


def _edge_point(box: _Box, toward: tuple[float, float]) -> tuple[float, float]:
    """Where the line from the box's centre toward `toward` leaves the box."""
    dx, dy = toward[0] - box.cx, toward[1] - box.cy
    if dx == 0 and dy == 0:
        return box.cx, box.cy
    scale = min((box.w / 2) / abs(dx) if dx else math.inf, (box.h / 2) / abs(dy) if dy else math.inf)
    return box.cx + dx * scale, box.cy + dy * scale


def _node_svg(component: ReportComponent, box: _Box) -> str:
    fill, text_color = _SEVERITY_FILL.get(component.worst_severity or "", _CLEAR_FILL)
    dim = ' opacity="0.45"' if component.out_of_scope else ""
    stroke = "#6c757d" if component.is_manual or component.out_of_scope else "none"
    dash = ' stroke-dasharray="5 3"' if component.out_of_scope else ""
    rx = {"process": 22, "data_store": 3, "external_entity": 0}.get(component.type, 6)
    parts = [
        f'<g class="node"{dim}>',
        (
            f'<rect x="{box.x:.1f}" y="{box.y:.1f}" width="{box.w}" height="{box.h}" rx="{rx}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2"{dash}/>'
        ),
    ]
    if component.type == "data_store":
        for y in (box.y + 7, box.y + box.h - 7):
            parts.append(
                f'<line x1="{box.x:.1f}" y1="{y:.1f}" x2="{box.x + box.w:.1f}" y2="{y:.1f}" '
                f'stroke="{text_color}" stroke-width="1.5" opacity="0.8"/>'
            )
    if component.type == "external_entity":
        parts.append(
            f'<rect x="{box.x + 4:.1f}" y="{box.y + 4:.1f}" width="{box.w - 8}" height="{box.h - 8}" '
            f'fill="none" stroke="{text_color}" stroke-width="1" opacity="0.7"/>'
        )
    lines = _wrap(component.name)
    if component.open_finding_count:
        lines[-1] = f"{lines[-1]} ({component.open_finding_count})"
    if component.out_of_scope:
        lines.append("out of scope")
    line_height = 15
    first = box.cy - (len(lines) - 1) * line_height / 2 + 4
    for index, line in enumerate(lines[:3]):
        parts.append(
            f'<text x="{box.cx:.1f}" y="{first + index * line_height:.1f}" text-anchor="middle" '
            f'font-size="13" fill="{text_color}">{_e(line)}</text>'
        )
    parts.append("</g>")
    return "".join(parts)


def render_svg(
    components: Sequence[ReportComponent],
    flows: Sequence[ReportFlow],
    boundaries: Sequence[ReportBoundary],
    *,
    standalone: bool = True,
) -> str:
    nodes, group_boxes = layout(components, boundaries)
    boxes = [*nodes.values(), *(box for _, box in group_boxes)]
    if not boxes:
        min_x = min_y = 0.0
        width, height = 320.0, 80.0
    else:
        min_x = min(b.x for b in boxes) - MARGIN
        min_y = min(b.y for b in boxes) - MARGIN
        width = max(b.x + b.w for b in boxes) + MARGIN - min_x
        height = max(b.y + b.h for b in boxes) + MARGIN - min_y

    body: list[str] = []
    if not boxes:
        body.append(
            '<text x="160" y="45" text-anchor="middle" font-size="14" fill="#6c757d">'
            "No components in this model.</text>"
        )
    for name, box in group_boxes:
        body.append(
            f'<g class="boundary"><rect x="{box.x:.1f}" y="{box.y:.1f}" width="{box.w}" height="{box.h}" '
            f'rx="8" fill="#f8f9fa" stroke="#6c757d" stroke-width="1.5" stroke-dasharray="8 5"/>'
            f'<text x="{box.x + 12:.1f}" y="{box.y + 21:.1f}" font-size="13" font-weight="bold" '
            f'fill="#495057">{_e(name)}</text></g>'
        )

    edges: list[str] = []
    labels: list[str] = []
    for flow in flows:
        source, target = nodes.get(flow.source_id), nodes.get(flow.target_id)
        if source is None or target is None:
            continue
        x1, y1 = _edge_point(source, (target.cx, target.cy))
        x2, y2 = _edge_point(target, (source.cx, source.cy))
        dim = ' opacity="0.4"' if flow.out_of_scope else ""
        if not flow.is_data_flow:
            # A mount or config reference: shown so the diagram matches the
            # screen, but muted and unlabelled since it is not a data flow.
            edges.append(
                f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#adb5bd" '
                f'stroke-width="1" stroke-dasharray="2 3"{dim}/>'
            )
            continue
        dash = ' stroke-dasharray="4 3"' if flow.is_manual or flow.out_of_scope else ""
        edges.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#495057" '
            f'stroke-width="1.6"{dash}{dim} marker-end="url(#arrow)"/>'
        )
        if flow.label:
            labels.append(
                f'<text x="{(x1 + x2) / 2:.1f}" y="{(y1 + y2) / 2 - 5:.1f}" text-anchor="middle" font-size="11" '
                f'fill="#212529" stroke="#ffffff" stroke-width="3" paint-order="stroke">{_e(flow.label)}</text>'
            )

    body.extend(edges)
    body.extend(_node_svg(c, nodes[c.id]) for c in components if c.id in nodes)
    body.extend(labels)

    header = '<?xml version="1.0" encoding="UTF-8"?>\n' if standalone else ""
    return (
        f'{header}<svg xmlns="http://www.w3.org/2000/svg" viewBox="{min_x:.1f} {min_y:.1f} {width:.1f} {height:.1f}" '
        f'width="{width:.0f}" height="{height:.0f}" role="img" aria-label="Data flow diagram" '
        f'font-family="Helvetica, Arial, sans-serif">'
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" '
        'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#495057"/></marker></defs>'
        f'<rect x="{min_x:.1f}" y="{min_y:.1f}" width="{width:.1f}" height="{height:.1f}" fill="#ffffff"/>'
        + "".join(body)
        + "</svg>"
    )
