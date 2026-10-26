from datetime import UTC, datetime

from kresheen.engine.dfd.derive import derive_dfd
from kresheen.models.asset import AssetType
from kresheen.models.facts import FactEdge, FactNode


def _node(node_id: str, node_type: str, **attributes) -> FactNode:
    return FactNode(
        id=node_id,
        run_id="RUN-1",
        application_id="APP-1",
        node_type=node_type,
        name=node_id,
        attributes=attributes,
        source_ref="test",
        discovered_at=datetime.now(UTC),
    )


def test_derive_dfd_maps_matching_node_type_strings_to_asset_type():
    assets, flows = derive_dfd([_node("n1", "data_store")], [])

    assert flows == []
    assert len(assets) == 1
    assert assets[0].id == "n1"
    assert assets[0].type == AssetType.DATA_STORE
    assert assets[0].source == "threat_model_run"
    assert assets[0].run_id == "RUN-1"
    assert assets[0].application_id == "APP-1"


def test_derive_dfd_maps_code_artifact_to_process():
    assets, _ = derive_dfd([_node("n1", "code_artifact")], [])

    assert assets[0].type == AssetType.PROCESS


def test_derive_dfd_excludes_non_diagram_worthy_node_types():
    """Regression test: a real run (openshift/splunk-forwarder-operator)
    showed `vulnerability`/`sbom_document` facts each rendering
    as their own generic box, colored orange by the vulnerability's own
    severity -- an unrecognized `node_type` must not be coerced into a
    generic `AssetType.PROCESS`. An unrecognized (or explicitly non-diagram-worthy) fact type must produce
    no Asset at all, not a fallback box."""
    nodes = [
        _node("n1", "vulnerability"),
        _node("n2", "sbom_document"),
        _node("n3", "reference_document"),
        _node("n4", "some-future-metadata-only-node-type"),
        _node("n5", "process"),
    ]

    assets, _ = derive_dfd(nodes, [])

    assert [a.id for a in assets] == ["n5"]


def test_derive_dfd_carries_trust_boundary_attribute_through():
    assets, _ = derive_dfd([_node("n1", "process", trust_boundary="internet_facing")], [])

    assert assets[0].trust_boundary == "internet_facing"


def test_derive_dfd_maps_edges_to_asset_flows():
    nodes = [_node("n1", "process"), _node("n2", "process")]
    edge = FactEdge(
        id="e1",
        run_id="RUN-1",
        application_id="APP-1",
        source_node_id="n1",
        target_node_id="n2",
        edge_type="routes_to",
        label="custom label",
    )

    _, flows = derive_dfd(nodes, [edge])

    assert len(flows) == 1
    assert flows[0].id == "e1"
    assert flows[0].source_asset_id == "n1"
    assert flows[0].target_asset_id == "n2"
    assert flows[0].label == "custom label"


def test_derive_dfd_edge_label_falls_back_to_edge_type():
    nodes = [_node("n1", "process"), _node("n2", "process")]
    edge = FactEdge(
        id="e1",
        run_id="RUN-1",
        application_id="APP-1",
        source_node_id="n1",
        target_node_id="n2",
        edge_type="routes_to",
    )

    _, flows = derive_dfd(nodes, [edge])

    assert flows[0].label == "routes_to"


def test_derive_dfd_drops_edges_to_excluded_nodes():
    """An edge whose source or target is a non-diagram-worthy fact (e.g.
    the hub-and-spoke `discovered_in` edges github_repository_ingestor.py
    draws from its hub to a `vulnerability` fact) must not produce a
    dangling AssetFlow pointing at an Asset that was never created."""
    nodes = [_node("n1", "external_entity"), _node("n2", "vulnerability")]
    edge = FactEdge(
        id="e1",
        run_id="RUN-1",
        application_id="APP-1",
        source_node_id="n1",
        target_node_id="n2",
        edge_type="discovered_in",
    )

    _, flows = derive_dfd(nodes, [edge])

    assert flows == []
