"""Classifies what a data source contributed to a run, so a source the engine
cannot yet analyse is reported as such instead of looking like "no threats
found". Pure function over the
facts one ingestor produced."""

from __future__ import annotations

from typing import Literal

from kresheen.engine.dfd.derive import DIAGRAM_WORTHY_NODE_TYPES
from kresheen.models.facts import FactNode
from kresheen.models.threat_model_run import SourceResult

_DOCUMENTATION_MESSAGE = (
    "Stored as a reference only. The rule-based engine does not read documents, so nothing in "
    "this file has been analysed. Add components by hand, or upload a manifest or a diagram (Threat Dragon JSON, draw.io, Mermaid or Threagile)."
)
_UNRECOGNISED_MESSAGE = (
    "File stored but its format was not recognised. Diagrams are read as Threat Dragon JSON, "
    "draw.io, Mermaid flowchart or Threagile YAML; Visio, images and other formats are kept as a reference."
)
_EMPTY_MESSAGE = (
    "Read successfully but no components were found. Repositories are only analysed for plain "
    "Kubernetes YAML; Helm, Kustomize, Terraform HCL and docker-compose are not parsed yet."
)


def classify_source(data_source_id: str, source_type: str, nodes: list[FactNode]) -> SourceResult:
    components = sum(1 for node in nodes if node.node_type in DIAGRAM_WORTHY_NODE_TYPES)
    vulnerabilities = sum(1 for node in nodes if node.node_type == "vulnerability")
    status: Literal["analysed", "reference_only", "empty"]
    if source_type == "documentation":
        status, message = "reference_only", _DOCUMENTATION_MESSAGE
    elif components or vulnerabilities:
        status, message = "analysed", ""
    elif nodes and all(node.node_type == "reference_document" for node in nodes):
        reason = next((str(n.attributes.get("reason", "")) for n in nodes if n.attributes.get("reason")), "")
        status, message = "reference_only", (f"{reason} " if reason else "") + _UNRECOGNISED_MESSAGE
    else:
        status, message = "empty", _EMPTY_MESSAGE
    warnings = [w for node in nodes if node.node_type == "scan_note" for w in node.attributes.get("warnings", [])]
    return SourceResult(
        data_source_id=data_source_id, type=source_type, status=status,
        component_count=components, vulnerability_count=vulnerabilities, message=message, warnings=warnings,
    )


def has_unanalysed(results: list[SourceResult]) -> bool:
    return any(result.status != "analysed" or result.warnings for result in results)
