"""engine/source_status.py."""

from datetime import UTC, datetime

from kresheen.engine.source_status import classify_source
from kresheen.models.facts import FactNode


def _node(node_type: str) -> FactNode:
    return FactNode(
        id="N",
        run_id="R",
        application_id="A",
        node_type=node_type,
        name="x",
        source_ref="t",
        discovered_at=datetime.now(UTC),
    )


def test_documentation_is_always_reference_only():
    result = classify_source("DS", "documentation", [_node("reference_document")])
    assert result.status == "reference_only" and "nothing in this file has been analysed" in result.message


def test_components_mean_analysed():
    result = classify_source("DS", "manifest_upload", [_node("process"), _node("data_store"), _node("config_resource")])
    assert result.status == "analysed" and result.component_count == 2 and result.message == ""


def test_vulnerabilities_alone_count_as_analysed():
    assert classify_source("DS", "github_repository", [_node("vulnerability")]).status == "analysed"


def test_unrecognised_diagram_is_reference_only():
    assert classify_source("DS", "architecture_diagram", [_node("reference_document")]).status == "reference_only"


def test_source_with_no_facts_is_empty():
    assert classify_source("DS", "github_repository", []).status == "empty"
