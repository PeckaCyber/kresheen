"""Attack paths: reachability from an external entity, across trust
boundaries, to a data store or a crown-jewel asset.

Pure/derive-fresh, like the rest of the threat-generation stack (threats are
derived, never stored): nothing here is persisted, every call
recomputes from the run's already-merged DFD (`engine/threats/service.py::
load_dfd_model`).

Built over `DfdElement`/`DfdFlow` (the fully-merged layer: manual
components/flows, trust-boundary overrides, owner-stated properties), not
the raw facts graph -- the facts graph's `FactGraph.reachable_from` loses
that overlay and only returns a reachability set, not a reconstructable
path. Traversal is a dependency-free BFS with parent-pointer tracking
(same style as `FactGraph.reachable_from`'s explicit-stack BFS), so there is
no graph-library dependency.

"Crown jewel" here means the owner-stated `data_classification` property
(engine/threats/properties.py) -- the only automated criticality signal
that actually exists in the engine today. A plain `data_store` with no
classification is still a target (it's the other half of the feature's
"a data store or crown-jewel asset" scope), just not flagged as one.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Literal

from kresheen.engine.threats.generate import DfdElement, DfdFlow, crosses_boundary
from kresheen.engine.threats.properties import is_out_of_scope

AttackPathRisk = Literal["critical", "high", "medium"]


@dataclass(frozen=True)
class AttackPathHop:
    from_name: str
    to_name: str
    flow_label: str | None
    crosses_boundary: bool
    authenticated: bool | None
    encrypted: bool | None


@dataclass(frozen=True)
class AttackPath:
    source_name: str
    target_name: str
    target_type: str
    is_crown_jewel: bool
    risk: AttackPathRisk
    risk_factors: list[str]
    hops: list[AttackPathHop] = field(default_factory=list)

    @property
    def boundary_crossings(self) -> int:
        return sum(1 for hop in self.hops if hop.crosses_boundary)


def _is_crown_jewel(element: DfdElement) -> bool:
    value = element.properties.get("data_classification")
    return isinstance(value, str) and bool(value.strip())


def _risk_for(is_crown_jewel: bool, target: DfdElement, hops: list[AttackPathHop]) -> tuple[AttackPathRisk, list[str]]:
    any_authenticated = any(hop.authenticated for hop in hops)
    factors = []
    if is_crown_jewel:
        classification = target.properties.get("data_classification")
        factors.append(f"reaches an asset tagged '{classification}'")
    else:
        factors.append(f"reaches a {target.type.replace('_', ' ')} with no declared data classification")
    crossings = sum(1 for hop in hops if hop.crosses_boundary)
    if crossings:
        factors.append(f"crosses {crossings} trust {'boundary' if crossings == 1 else 'boundaries'}")
    if any_authenticated:
        factors.append("at least one hop requires authentication")
    else:
        factors.append("no hop on this path requires authentication")

    if is_crown_jewel and not any_authenticated:
        return "critical", factors
    if is_crown_jewel or not any_authenticated:
        return "high", factors
    return "medium", factors


def find_attack_paths(elements: list[DfdElement], flows: list[DfdFlow]) -> list[AttackPath]:
    in_scope_elements = {e.id: e for e in elements if not is_out_of_scope(e.properties)}
    adjacency: dict[str, list[DfdFlow]] = {}
    for flow in flows:
        if is_out_of_scope(flow.properties):
            continue
        if flow.source_id not in in_scope_elements or flow.target_id not in in_scope_elements:
            continue
        adjacency.setdefault(flow.source_id, []).append(flow)

    sources = [e for e in in_scope_elements.values() if e.type == "external_entity"]
    targets = {e.id: e for e in in_scope_elements.values() if e.type == "data_store" or _is_crown_jewel(e)}

    paths: list[AttackPath] = []
    for source in sources:
        # BFS with parent-pointer tracking: visited[node_id] = (prev_node_id, flow) or None for the source itself.
        visited: dict[str, tuple[str, DfdFlow] | None] = {source.id: None}
        queue: deque[str] = deque([source.id])
        while queue:
            current_id = queue.popleft()
            for flow in adjacency.get(current_id, []):
                if flow.target_id in visited:
                    continue
                visited[flow.target_id] = (current_id, flow)
                queue.append(flow.target_id)

        for target_id, target in targets.items():
            if target_id == source.id or target_id not in visited:
                continue
            hops: list[AttackPathHop] = []
            node_id = target_id
            while visited[node_id] is not None:
                prev_id, flow = visited[node_id]  # type: ignore[misc]
                hops.append(
                    AttackPathHop(
                        from_name=in_scope_elements[prev_id].name,
                        to_name=in_scope_elements[node_id].name,
                        flow_label=flow.label,
                        crosses_boundary=crosses_boundary(in_scope_elements[prev_id], in_scope_elements[node_id]),
                        authenticated=flow.properties.get("authenticated"),
                        encrypted=flow.properties.get("is_encrypted"),
                    )
                )
                node_id = prev_id
            hops.reverse()

            is_crown_jewel = _is_crown_jewel(target)
            risk, factors = _risk_for(is_crown_jewel, target, hops)
            paths.append(
                AttackPath(
                    source_name=source.name,
                    target_name=target.name,
                    target_type=target.type,
                    is_crown_jewel=is_crown_jewel,
                    risk=risk,
                    risk_factors=factors,
                    hops=hops,
                )
            )

    _RISK_RANK = {"critical": 0, "high": 1, "medium": 2}
    paths.sort(key=lambda p: (_RISK_RANK[p.risk], len(p.hops), p.source_name, p.target_name))
    return paths
