"""Threagile model files (YAML with `technical_assets`).

Assets become components (`external-entity`, `process`, `datastore`), `communication_links`
become flows, and `trust_boundaries` place assets in zones (an asset in several nested
boundaries takes the smallest). Facts stated in the file are carried over where they map to
one of this platform's properties: a datastore with encryption other than `none` is encrypted,
a link over an encrypted protocol is encrypted, a link with authentication is authenticated.
Threagile's own risk tracking and rules are not imported; risks are re-derived here.
"""

from __future__ import annotations

from typing import Any

import yaml

from kresheen.engine.ingest.diagrams.model import (
    MAX_CONTENT_CHARS,
    DiagramComponent,
    DiagramFlow,
    ParsedDiagram,
    clean_name,
    finish,
)

_TYPES = {"external-entity": "external_entity", "process": "process", "datastore": "data_store"}
_ENCRYPTED_PROTOCOLS = {
    "https", "ssh", "sftp", "ftps", "smtp-encrypted", "pop3-encrypted", "imap-encrypted", "ldap-encrypted",
    "jdbc-encrypted", "odbc-encrypted", "nosql-access-protocol-encrypted", "binary-encrypted", "text-encrypted",
    "ssh-tunnel", "grpc-encrypted", "mqtt-encrypted", "wss", "ldaps",
}


def looks_like_threagile(content: str) -> bool:
    return "technical_assets" in content[:MAX_CONTENT_CHARS]


def _str(value: Any) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def parse_threagile(content: str) -> ParsedDiagram | None:
    if len(content) > MAX_CONTENT_CHARS:
        return None
    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError:
        return None
    if not isinstance(parsed, dict) or not isinstance(parsed.get("technical_assets"), dict):
        return None

    assets: dict[str, dict] = {}  # asset id -> asset
    names: dict[str, str] = {}
    for name, asset in parsed["technical_assets"].items():
        if isinstance(asset, dict) and isinstance(asset.get("id"), str):
            assets[asset["id"]] = asset
            names[asset["id"]] = str(name)

    boundary_of: dict[str, tuple[str, int]] = {}  # asset id -> (boundary name, size of that boundary)
    boundaries = parsed.get("trust_boundaries")
    for name, boundary in (boundaries.items() if isinstance(boundaries, dict) else []):
        inside = boundary.get("technical_assets_inside") if isinstance(boundary, dict) else None
        if not isinstance(inside, list):
            continue
        for asset_id in inside:
            if isinstance(asset_id, str) and (asset_id not in boundary_of or len(inside) < boundary_of[asset_id][1]):
                boundary_of[asset_id] = (clean_name(name), len(inside))

    diagram = ParsedDiagram(format="threagile")
    for asset_id, asset in assets.items():
        node_type = _TYPES.get(_str(asset.get("type")), "process")
        properties: dict[str, bool | str] = {}
        if node_type == "data_store" and _str(asset.get("encryption")) not in ("", "none"):
            properties["is_encrypted"] = True
        boundary = boundary_of.get(asset_id, (None, 0))[0]
        if boundary is None and node_type == "external_entity" and asset.get("internet") is True:
            boundary = "Internet"
        diagram.components.append(
            DiagramComponent(key=asset_id, name=clean_name(names[asset_id]), type=node_type, boundary=boundary, properties=properties)
        )
        links = asset.get("communication_links")
        for link_name, link in (links.items() if isinstance(links, dict) else []):
            if not isinstance(link, dict) or not isinstance(link.get("target"), str):
                continue
            protocol = _str(link.get("protocol"))
            flow_props: dict[str, bool | str] = {}
            if protocol:
                flow_props["protocol"] = protocol
                if protocol in _ENCRYPTED_PROTOCOLS:
                    flow_props["is_encrypted"] = True
            if _str(link.get("authentication")) not in ("", "none"):
                flow_props["authenticated"] = True
            diagram.flows.append(DiagramFlow(source=asset_id, target=link["target"], label=clean_name(link_name), properties=flow_props))
    return finish(diagram)
