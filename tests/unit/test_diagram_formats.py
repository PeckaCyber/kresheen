"""engine/ingest/diagrams/."""

import base64
import json
import zlib
from urllib.parse import quote

from kresheen.engine.ingest.diagrams import parse_diagram
from kresheen.engine.ingest.diagrams.model import MAX_COMPONENTS, MAX_FLOWS


def _by_name(diagram):
    return {c.name: c for c in diagram.components}


def _flow(diagram, source, target):
    by_key = {c.key: c.name for c in diagram.components}
    return next(f for f in diagram.flows if (by_key[f.source], by_key[f.target]) == (source, target))


# ---- Threat Dragon -----------------------------------------------------------------------------

def _td(cells):
    return json.dumps({"summary": {"title": "t"}, "detail": {"diagrams": [{"title": "d", "cells": cells}]}})


def _td_cell(cell_id, shape, name, x, y, w=100, h=60, **data):
    return {"id": cell_id, "shape": shape, "position": {"x": x, "y": y}, "size": {"width": w, "height": h}, "data": {"name": name, **data}}


TD = _td([
    _td_cell("z", "trust-boundary-box", "Internal", 0, 0, 500, 300),
    _td_cell("z2", "trust-boundary-box", "Data zone", 300, 0, 180, 300),
    _td_cell("u", "actor", "Customer", 600, 0),
    _td_cell("w", "process", "Web app", 20, 20, isWebApplication=True),
    _td_cell("d", "store", "Orders DB", 320, 20, isEncrypted=True, storesCredentials=False, isALog=False),
    _td_cell("t", "td-text-block", "a note", 20, 200),
    {"id": "f1", "shape": "flow", "source": {"cell": "u"}, "target": {"cell": "w"}, "data": {"name": "HTTPS", "isEncrypted": True, "isPublicNetwork": True, "protocol": "HTTPS"}},
    {"id": "f2", "shape": "flow", "source": {"cell": "w"}, "target": {"cell": "d"}, "data": {"name": "SQL", "isEncrypted": False}},
])


def test_threat_dragon_types_boundaries_and_stated_properties_are_imported():
    diagram = parse_diagram(TD)
    named = _by_name(diagram)

    assert diagram.format == "threat_dragon"
    assert {n: c.type for n, c in named.items()} == {"Customer": "external_entity", "Web app": "process", "Orders DB": "data_store"}
    assert "a note" not in named  # text blocks are not components
    assert named["Web app"].boundary == "Internal"
    assert named["Orders DB"].boundary == "Data zone"  # the smallest box that contains it
    assert named["Customer"].boundary is None
    assert named["Web app"].properties == {"is_web_application": True}
    assert named["Orders DB"].properties == {"is_encrypted": True}  # unticked boxes are "not stated", not "no"
    assert _flow(diagram, "Customer", "Web app").properties == {"is_encrypted": True, "crosses_public_network": True, "protocol": "HTTPS"}
    assert _flow(diagram, "Web app", "Orders DB").properties == {}


def test_threat_dragon_files_without_shapes_still_import_as_processes():
    """The earlier importer's behaviour: an unknown cell is a process."""
    cells = [{"id": "a", "data": {"name": "A"}}, {"id": "b", "data": {"name": "B"}}, {"id": "f", "source": "a", "target": "b", "data": {"name": "x"}}]
    diagram = parse_diagram(_td(cells))
    assert {c.type for c in diagram.components} == {"process"} and len(diagram.flows) == 1


def test_threat_dragon_older_diagramjson_layout_is_read():
    old = json.dumps({"detail": {"diagrams": [{"diagramJson": {"cells": [
        {"id": "a", "data": {"name": "A", "type": "tm.Actor"}}, {"id": "s", "data": {"name": "S", "type": "tm.Store"}},
    ]}}]}})
    assert {c.name: c.type for c in parse_diagram(old).components} == {"A": "external_entity", "S": "data_store"}


# ---- draw.io -----------------------------------------------------------------------------------

def _drawio(cells_xml):
    return f'<mxfile><diagram id="p1" name="Page-1"><mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>{cells_xml}</root></mxGraphModel></diagram></mxfile>'


DRAWIO_CELLS = """
<mxCell id="zone" value="DMZ" style="rounded=0;dashed=1;fillColor=none;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="400" height="300" as="geometry"/></mxCell>
<mxCell id="web" value="Web &lt;b&gt;Server&lt;/b&gt;" style="rounded=1;" vertex="1" parent="1"><mxGeometry x="20" y="40" width="120" height="60" as="geometry"/></mxCell>
<mxCell id="db" value="Orders DB" style="shape=cylinder3;" vertex="1" parent="1"><mxGeometry x="200" y="40" width="80" height="80" as="geometry"/></mxCell>
<mxCell id="user" value="Customer" style="shape=umlActor;" vertex="1" parent="1"><mxGeometry x="600" y="40" width="30" height="60" as="geometry"/></mxCell>
<mxCell id="note" value="see wiki" style="text;html=1;" vertex="1" parent="1"><mxGeometry x="0" y="400" width="80" height="20" as="geometry"/></mxCell>
<mxCell id="e1" value="HTTPS" edge="1" parent="1" source="user" target="web"><mxGeometry relative="1" as="geometry"/></mxCell>
<mxCell id="e2" value="SQL" edge="1" parent="1" source="web" target="db"><mxGeometry relative="1" as="geometry"/></mxCell>
<mxCell id="e3" value="dangling" edge="1" parent="1" source="web"><mxGeometry relative="1" as="geometry"/></mxCell>
"""


def test_drawio_shapes_zones_and_connections():
    diagram = parse_diagram(_drawio(DRAWIO_CELLS))
    named = _by_name(diagram)

    assert diagram.format == "drawio"
    assert {n: c.type for n, c in named.items()} == {"Web Server": "process", "Orders DB": "data_store", "Customer": "external_entity"}
    assert named["Web Server"].boundary == "DMZ" and named["Orders DB"].boundary == "DMZ" and named["Customer"].boundary is None
    assert [(f.label) for f in diagram.flows] == ["HTTPS", "SQL"]  # the dangling edge is dropped
    assert "see wiki" not in named and "DMZ" not in named


def test_drawio_swimlane_containers_use_the_parent_relation_and_relative_geometry():
    cells = """
    <mxCell id="lane" value="Cluster" style="swimlane;" vertex="1" parent="1"><mxGeometry x="100" y="100" width="300" height="200" as="geometry"/></mxCell>
    <mxCell id="a" value="Svc A" style="rounded=1;" vertex="1" parent="lane"><mxGeometry x="10" y="30" width="80" height="40" as="geometry"/></mxCell>
    """
    diagram = parse_diagram(_drawio(cells))
    assert _by_name(diagram)["Svc A"].boundary == "Cluster"


def test_drawio_object_wrappers_carry_labels():
    cells = '<object label="Payments" id="p"><mxCell style="rounded=1;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="80" height="40" as="geometry"/></mxCell></object>'
    assert [c.name for c in parse_drawio_cells(cells)] == ["Payments"]


def parse_drawio_cells(cells):
    return parse_diagram(_drawio(cells)).components


def test_drawio_compressed_pages_are_inflated():
    inner = f'<mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>{DRAWIO_CELLS}</root></mxGraphModel>'
    compressor = zlib.compressobj(wbits=-15)
    packed = base64.b64encode(compressor.compress(quote(inner, safe="").encode()) + compressor.flush()).decode()
    diagram = parse_diagram(f'<mxfile><diagram id="p" name="Page-1">{packed}</diagram></mxfile>')

    assert diagram is not None and {c.name for c in diagram.components} == {"Web Server", "Orders DB", "Customer"}


def test_drawio_decompression_bombs_and_bad_payloads_are_refused_not_expanded():
    compressor = zlib.compressobj(wbits=-15)
    bomb = base64.b64encode(compressor.compress(b"A" * 30_000_000) + compressor.flush()).decode()
    assert parse_diagram(f'<mxfile><diagram id="p">{bomb}</diagram></mxfile>') is None
    assert parse_diagram('<mxfile><diagram id="p">not base64 at all !!</diagram></mxfile>') is None


def test_drawio_xml_entity_expansion_and_external_entities_are_refused():
    bomb = '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><mxfile><diagram id="p">&b;</diagram></mxfile>'
    xxe = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><mxfile><diagram id="p">&e;</diagram></mxfile>'
    assert parse_diagram(bomb) is None
    assert parse_diagram(xxe) is None


# ---- Mermaid -----------------------------------------------------------------------------------

MERMAID = """
%% a comment
flowchart LR
    User((Customer)) -->|HTTPS| Web[Web frontend]
    subgraph Backend [Application tier]
        Web --> API[Orders API]
        API -->|SQL| DB[(Orders DB)]
    end
    API -- card payments --> Pay[Payment provider]
    Web & API --> Log[Logger]
    classDef x fill:#f00
    click Web "http://x" "tip"
    this line is not mermaid at all
"""


def test_mermaid_shapes_subgraphs_and_labelled_links():
    diagram = parse_diagram(MERMAID)
    named = _by_name(diagram)

    assert diagram.format == "mermaid"
    assert named["Customer"].type == "external_entity" and named["Orders DB"].type == "data_store"
    assert named["Orders API"].type == "process" and named["Payment provider"].type == "process"
    assert named["Web frontend"].boundary is None and named["Orders API"].boundary == "Application tier"
    assert _flow(diagram, "Customer", "Web frontend").label == "HTTPS"
    assert _flow(diagram, "Orders API", "Orders DB").label == "SQL"
    assert _flow(diagram, "Orders API", "Payment provider").label == "card payments"
    assert {(f.source, f.target) for f in diagram.flows if f.target == "Log"} == {("Web", "Log"), ("API", "Log")}
    assert not any("mermaid at all" in c.name or c.key == "this" for c in diagram.components)  # prose is not a node


def test_mermaid_inside_a_markdown_fence_and_with_a_late_label():
    doc = "```mermaid\ngraph TD\n  A --> B\n  A[Gateway]\n  B[(Store)]\n```"
    named = _by_name(parse_diagram(doc))
    assert set(named) == {"Gateway", "Store"} and named["Store"].type == "data_store"


def test_other_mermaid_diagram_kinds_and_prose_are_not_flowcharts():
    assert parse_diagram("sequenceDiagram\n  A->>B: hi") is None
    assert parse_diagram("just some notes about the architecture") is None


def test_mermaid_survives_hostile_lines():
    hostile = "flowchart TD\n" + "A" * 5000 + " --> " + "B" * 5000 + "\n" + "[" * 4000 + "\n" + "A --> B\n"
    diagram = parse_diagram(hostile)
    assert diagram is not None and {c.name for c in diagram.components} >= {"A", "B"}


# ---- Threagile ---------------------------------------------------------------------------------

THREAGILE = """
technical_assets:
  Customer Client:
    id: client
    type: external-entity
    internet: true
    communication_links:
      Login:
        target: app
        protocol: https
        authentication: token
  Web App:
    id: app
    type: process
    communication_links:
      Query:
        target: db
        protocol: jdbc
  Orders DB:
    id: db
    type: datastore
    encryption: transparent
trust_boundaries:
  Company:
    id: co
    technical_assets_inside: [app, db]
  Data:
    id: data
    technical_assets_inside: [db]
"""


def test_threagile_assets_links_boundaries_and_stated_facts():
    diagram = parse_diagram(THREAGILE)
    named = _by_name(diagram)

    assert diagram.format == "threagile"
    assert {n: c.type for n, c in named.items()} == {"Customer Client": "external_entity", "Web App": "process", "Orders DB": "data_store"}
    assert named["Customer Client"].boundary == "Internet"
    assert named["Web App"].boundary == "Company" and named["Orders DB"].boundary == "Data"  # smallest enclosing
    assert named["Orders DB"].properties == {"is_encrypted": True}
    assert _flow(diagram, "Customer Client", "Web App").properties == {"protocol": "https", "is_encrypted": True, "authenticated": True}
    assert _flow(diagram, "Web App", "Orders DB").properties == {"protocol": "jdbc"}


def test_threagile_unsafe_yaml_tags_are_not_executed():
    assert parse_diagram("technical_assets: !!python/object/apply:os.system ['echo hi']") is None


# ---- dispatch and limits -----------------------------------------------------------------------

def test_unrecognised_content_is_none():
    for content in ("", "   ", "PNG\x89 binary-ish", '{"not": "a diagram"}', "<html><body>hi</body></html>", "[1, 2, 3]", "{broken json"):
        assert parse_diagram(content) is None, content


def test_component_and_flow_caps_are_enforced_and_reported():
    many = "flowchart LR\n" + "\n".join(f"n{i} --> n{i + 1}" for i in range(MAX_COMPONENTS + 50))
    diagram = parse_diagram(many)
    assert len(diagram.components) == MAX_COMPONENTS and diagram.truncated
    assert all(f.source in {c.key for c in diagram.components} for f in diagram.flows)
    assert len(diagram.flows) <= MAX_FLOWS


def test_oversized_content_is_refused():
    assert parse_diagram("flowchart LR\n" + "A --> B\n" * 1_000_000) is None
