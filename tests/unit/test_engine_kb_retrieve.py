from datetime import UTC, datetime

from kresheen.engine.kb.retrieve import score_kb_entries
from kresheen.models.facts import FactNode
from kresheen.models.threat_kb import ThreatKBEntry


def _node(**attributes) -> FactNode:
    return FactNode(
        id="FACT-N-1",
        run_id="RUN-1",
        application_id="APP-1",
        node_type="process",
        name="web",
        attributes=attributes,
        source_ref="test",
        discovered_at=datetime.now(UTC),
    )


def _entry(
    entry_id: str, name: str, description: str = "", tags: list[str] | None = None, is_active: bool = True
) -> ThreatKBEntry:
    now = datetime.now(UTC)
    return ThreatKBEntry(
        id=entry_id,
        source="custom",
        name=name,
        description=description,
        tags=tags or [],
        is_active=is_active,
        created_at=now,
        updated_at=now,
    )


def test_scores_by_attribute_value_overlap_not_by_node_type():
    node = _node(container_images=["myregistry/web:latest"])
    matching = _entry("KB-1", "Unpinned image", description="A container image tagged latest is not reproducible")
    unrelated = _entry("KB-2", "Unrelated CWE", description="Something about SQL injection")

    results = score_kb_entries(node, [matching, unrelated])

    assert results == [matching]


def test_higher_overlap_ranks_first():
    node = _node(host_network=True, container_images=["nginx:latest"])
    high_overlap = _entry("KB-1", "host network latest", description="host network and latest image both present")
    low_overlap = _entry("KB-2", "host", description="host only")

    results = score_kb_entries(node, [low_overlap, high_overlap])

    assert results[0] == high_overlap


def test_inactive_entries_are_excluded():
    node = _node(host_network=True)
    inactive = _entry("KB-1", "host network", description="host network risk", is_active=False)

    assert score_kb_entries(node, [inactive]) == []


def test_top_n_limits_the_result_count():
    node = _node(host_network=True)
    entries = [_entry(f"KB-{i}", "host network", description="host network risk") for i in range(10)]

    results = score_kb_entries(node, entries, top_n=3)

    assert len(results) == 3


def test_no_overlap_returns_empty_list():
    node = _node(host_network=True)
    entry = _entry("KB-1", "Completely different concept", description="unrelated wording entirely")

    assert score_kb_entries(node, [entry]) == []
