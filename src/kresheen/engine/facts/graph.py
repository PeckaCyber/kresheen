"""Plain-Python adjacency graph over one run's FactNode/FactEdge rows.
No graph library: a pluggable seam that could be swapped for networkx if
weighted paths or centrality are ever needed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kresheen.models.facts import FactEdge, FactNode


@dataclass
class FactGraph:
    nodes_by_id: dict[str, FactNode] = field(default_factory=dict)
    adjacency: dict[str, list[str]] = field(default_factory=dict)
    """node_id -> [neighbor_node_id, ...], directed (source -> target)."""

    @classmethod
    def build(cls, nodes: list[FactNode], edges: list[FactEdge]) -> FactGraph:
        graph = cls()
        for node in nodes:
            graph.nodes_by_id[node.id] = node
            graph.adjacency.setdefault(node.id, [])
        for edge in edges:
            graph.adjacency.setdefault(edge.source_node_id, []).append(edge.target_node_id)
        return graph

    def reachable_from(self, start_node_id: str) -> set[str]:
        """Every node reachable from `start_node_id`, including itself --
        e.g. "what can an attacker reach starting from this internet-facing
        entry point?" over the discovered flow graph."""
        visited: set[str] = set()
        stack = [start_node_id]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            stack.extend(self.adjacency.get(current, []))
        return visited

    def path_exists(self, source_node_id: str, target_node_id: str) -> bool:
        return target_node_id in self.reachable_from(source_node_id)
