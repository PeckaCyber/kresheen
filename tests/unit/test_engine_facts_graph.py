from datetime import UTC, datetime

from kresheen.engine.facts.graph import FactGraph
from kresheen.models.facts import FactEdge, FactNode


def _node(node_id: str) -> FactNode:
    return FactNode(
        id=node_id,
        run_id="RUN-1",
        application_id="APP-1",
        node_type="process",
        name=node_id,
        source_ref="test",
        discovered_at=datetime.now(UTC),
    )


def _edge(source: str, target: str) -> FactEdge:
    return FactEdge(
        id=f"{source}->{target}",
        run_id="RUN-1",
        application_id="APP-1",
        source_node_id=source,
        target_node_id=target,
        edge_type="data_flow",
    )


def test_reachable_from_includes_the_start_node_itself():
    graph = FactGraph.build([_node("a")], [])

    assert graph.reachable_from("a") == {"a"}


def test_reachable_from_follows_directed_edges_transitively():
    graph = FactGraph.build([_node("a"), _node("b"), _node("c")], [_edge("a", "b"), _edge("b", "c")])

    assert graph.reachable_from("a") == {"a", "b", "c"}


def test_reachable_from_does_not_traverse_backwards():
    graph = FactGraph.build([_node("a"), _node("b")], [_edge("a", "b")])

    assert graph.reachable_from("b") == {"b"}


def test_path_exists_true_and_false_cases():
    graph = FactGraph.build([_node("a"), _node("b"), _node("c")], [_edge("a", "b")])

    assert graph.path_exists("a", "b") is True
    assert graph.path_exists("b", "a") is False
    assert graph.path_exists("a", "c") is False
