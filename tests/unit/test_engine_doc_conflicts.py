"""Doc-vs-code conflicts,
narrow presence-only pass: engine/threats/doc_conflicts.py."""

import json
from datetime import UTC, datetime

from kresheen.engine.orchestrator import execute_run
from kresheen.engine.threats.doc_conflicts import check_doc_conflicts
from kresheen.engine.threats.view import build_threats_out
from kresheen.models.data_source import DataSourceConfig
from kresheen.models.facts import FactNode
from kresheen.models.threat_model_run import ThreatModelRun
from kresheen.storage.sql_repo import SQLRepository


def _node(name: str, source_ref: str, node_type: str = "process") -> FactNode:
    return FactNode(
        id=f"{source_ref}-{name}", run_id="R", application_id="A", node_type=node_type, name=name,
        attributes={}, source_ref=source_ref, discovered_at=datetime.now(UTC),
    )


def test_no_diagram_source_no_conflicts():
    nodes = [_node("Deployment/api", "manifest_upload")]
    assert check_doc_conflicts(nodes) == []


def test_diagram_with_no_infra_source_no_conflicts():
    nodes = [_node("API", "architecture_diagram")]
    assert check_doc_conflicts(nodes) == []


def test_matching_name_case_insensitive_is_no_conflict():
    nodes = [_node("API Service", "architecture_diagram"), _node("api service", "manifest_upload")]
    assert check_doc_conflicts(nodes) == []


def test_diagram_component_with_no_infra_match_is_flagged():
    nodes = [_node("Payments Service", "architecture_diagram"), _node("Deployment/api", "manifest_upload")]
    conflicts = check_doc_conflicts(nodes)
    assert len(conflicts) == 1
    assert conflicts[0].kind == "diagram_only"
    assert conflicts[0].name == "Payments Service"


def test_infra_only_component_is_not_flagged():
    """Deliberately one-directional: an infra component not drawn in the
    diagram is not noise, see the module's own docstring."""
    nodes = [_node("API", "architecture_diagram"), _node("api", "manifest_upload"), _node("Deployment/redis", "manifest_upload")]
    assert check_doc_conflicts(nodes) == []


def test_documentation_source_does_not_count_as_a_matching_infra_component():
    nodes = [
        _node("API", "architecture_diagram"), _node("API", "documentation"), _node("Deployment/redis", "manifest_upload"),
    ]
    conflicts = check_doc_conflicts(nodes)
    assert len(conflicts) == 1 and conflicts[0].name == "API"


def test_duplicate_diagram_names_only_flagged_once():
    nodes = [
        _node("Ghost", "architecture_diagram"), _node("Ghost", "architecture_diagram"),
        _node("Deployment/api", "manifest_upload"),
    ]
    conflicts = check_doc_conflicts(nodes)
    assert len(conflicts) == 1


def _deployment(name: str, ns: str = "n") -> str:
    return f"""
apiVersion: apps/v1
kind: Deployment
metadata: {{name: {name}, namespace: {ns}}}
spec:
  template:
    metadata: {{labels: {{app: {name}}}}}
    spec:
      containers:
      - name: c
        image: app:1
---"""


def test_end_to_end_a_stale_diagram_component_surfaces_on_the_run(tmp_path):
    diagram = {
        "detail": {
            "diagrams": [{"cells": [
                {"id": "c1", "data": {"name": "Deployment/api"}},
                {"id": "c2", "data": {"name": "Legacy Billing Service"}},
            ]}]
        }
    }
    repo = SQLRepository(f"sqlite:///{tmp_path}/doc.db")
    repo.save_data_source(DataSourceConfig(
        id="DS-manifest", application_id="APP-1", type="manifest_upload",
        connection_details={"content": _deployment("api")}, created_at=datetime.now(UTC),
    ))
    repo.save_data_source(DataSourceConfig(
        id="DS-diagram", application_id="APP-1", type="architecture_diagram",
        connection_details={"filename": "model.json", "content": json.dumps(diagram)}, created_at=datetime.now(UTC),
    ))
    repo.save_run(ThreatModelRun(
        id="RUN-1", application_id="APP-1", triggered_by_user_id="U",
        data_source_config_ids=["DS-manifest", "DS-diagram"], started_at=datetime.now(UTC),
    ))
    execute_run(repo, "RUN-1")

    out = build_threats_out("APP-1", "RUN-1", repo)
    assert [c.name for c in out.doc_conflicts] == ["Legacy Billing Service"]
