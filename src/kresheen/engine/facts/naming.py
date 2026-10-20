"""Keeps diagram component names unique across a run.

Everything user-facing keys a component by its *name*: threat keys and their
stored status, boundary overrides, manual flows, manual threats. Kubernetes
allows `Deployment/redis` in every namespace, so two distinct workloads can
arrive with an identical name and would silently collapse into one component
(one threat, one status, boundary override applied to both).

`qualify_colliding_names` renames only the colliding ones, to
`Deployment/redis (team-a)`. A name that is already unique is left alone, so
adding this changes nothing for existing Applications' stored statuses.
"""

from __future__ import annotations

from collections import defaultdict

from kresheen.models.facts import FactNode

_DIAGRAM_NODE_TYPES = frozenset({"process", "data_store"})

UNQUALIFIED_NAME_ATTR = "unqualified_name"
"""Attribute holding the original name on a renamed fact. Rules that look up
objects by their Kubernetes name, or keyword-match the name, must read this
via `unqualified_name()` so the added namespace text can't change their result."""


def unqualified_name(node: FactNode) -> str:
    return str(node.attributes.get(UNQUALIFIED_NAME_ATTR, node.name))


def qualify_colliding_names(nodes: list[FactNode]) -> None:
    """Renames, in place, diagram-bound facts that share a name but live in
    different namespaces. Facts with the same name *and* namespace are true
    duplicates and are left alone (qualifying them would not disambiguate)."""
    by_name: dict[str, list[FactNode]] = defaultdict(list)
    for node in nodes:
        if node.node_type in _DIAGRAM_NODE_TYPES and node.attributes.get("namespace"):
            by_name[node.name].append(node)

    for name, group in by_name.items():
        if len({node.attributes["namespace"] for node in group}) < 2:
            continue
        for node in group:
            node.attributes[UNQUALIFIED_NAME_ATTR] = name
            node.name = f"{name} ({node.attributes['namespace']})"
