"""Parses one uploaded static manifest file -- either a `terraform plan
-json` export or a (possibly multi-document) Kubernetes manifest YAML file
-- into facts. Hand-rolled, declarative-input parsing
rather than a `python-terraform`/`kubernetes` client dependency: this only
ever reads a file the user uploaded, it never talks to a live account or
cluster (that's the later, higher-risk `k8s_live`/cloud-account source --
see models/data_source.py's docstring).
"""

from __future__ import annotations

import json
from typing import ClassVar

import yaml

from kresheen.engine.ingest.base import SourceIngestor
from kresheen.engine.ingest.k8s_facts import build_k8s_facts
from kresheen.engine.ingest.terraform_facts import build_terraform_facts
from kresheen.engine.ingest.terraform_facts import config_refs as config_refs_of
from kresheen.engine.ingest.yaml_safety import check_yaml_aliases
from kresheen.models.facts import FactEdge, FactNode


def _detect_format(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            pass
        else:
            if "resource_changes" in parsed or "planned_values" in parsed:
                return "terraform_plan"
    return "k8s_manifest"


class ManifestUploadIngestor(SourceIngestor):
    source_type: ClassVar[str] = "manifest_upload"

    def fetch(self, *, connection_details: dict | None = None, **kwargs) -> str:
        return (connection_details or {}).get("content", "")

    def parse(self, raw: str) -> list[dict]:
        fmt = _detect_format(raw)
        if fmt == "terraform_plan":
            plan = json.loads(raw)
            refs_by_address = config_refs_of(plan)
            return [
                {"_format": fmt, "_config_refs": refs_by_address, **change}
                for change in plan.get("resource_changes", [])
                # "delete" actions have no `after` to build a fact from.
                if "delete" not in change.get("change", {}).get("actions", [])
            ]
        check_yaml_aliases(raw)
        return [
            {"_format": fmt, **doc}
            for doc in yaml.safe_load_all(raw)
            if doc and isinstance(doc, dict) and doc.get("kind")
        ]

    def normalize(
        self, records: list[dict], *, run_id: str, application_id: str
    ) -> tuple[list[FactNode], list[FactEdge]]:
        if not records:
            return [], []
        if records[0]["_format"] == "terraform_plan":
            return self._normalize_terraform(records, run_id=run_id, application_id=application_id)
        return self._normalize_k8s(records, run_id=run_id, application_id=application_id)

    def _normalize_terraform(
        self, records: list[dict], *, run_id: str, application_id: str
    ) -> tuple[list[FactNode], list[FactEdge]]:
        return build_terraform_facts(records, run_id=run_id, application_id=application_id)

    def _normalize_k8s(
        self, records: list[dict], *, run_id: str, application_id: str
    ) -> tuple[list[FactNode], list[FactEdge]]:
        return build_k8s_facts(records, run_id=run_id, application_id=application_id)
