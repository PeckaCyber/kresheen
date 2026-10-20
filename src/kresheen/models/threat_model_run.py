"""ThreatModelRun: one execution of the rule engine for one Application."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


def new_run_id() -> str:
    return f"RUN-{uuid.uuid4().hex[:16]}"


class SourceResult(BaseModel):
    """What one data source actually contributed to a run (engine/source_status.py).
    Exists so the UI and reports never present "not analysed" as "nothing found"."""

    data_source_id: str
    type: str
    status: Literal["analysed", "reference_only", "empty"]
    component_count: int = 0
    vulnerability_count: int = 0
    message: str = ""
    # Part of the source was read but a step did not run (e.g. the vulnerability scanner): the result is
    # incomplete, which must not look like a clean one.
    warnings: list[str] = Field(default_factory=list)


class ThreatModelRun(BaseModel):
    id: str
    application_id: str
    triggered_by_user_id: str
    data_source_config_ids: list[str] = Field(default_factory=list)
    status: Literal["queued", "ingesting", "reasoning", "completed", "failed"] = "queued"
    started_at: datetime
    completed_at: datetime | None = None
    error_message: str | None = None
    # Cached rollup for list views (Applications table, run history) -- not
    # authoritative, same "derive, don't duplicate" caveat as elsewhere in
    # this codebase; the real counts always come from querying Findings by
    # run_id.
    finding_counts_by_severity: dict[str, int] = Field(default_factory=dict)
    # Provenance stamp (engine/provenance.py). Set once the run completes; absent on older runs and
    # on a run that failed before reaching that point.
    engine_version: str | None = None
    rule_catalog_version: str | None = None
    input_digests: dict[str, str] = Field(default_factory=dict)  # data_source_id -> digest
    # Per-source outcome, set during ingestion. Empty on older runs;
    # the UI then simply shows no per-source status.
    source_results: list[SourceResult] = Field(default_factory=list)
    # Set when this run scanned a different git ref than the data source is
    # configured with (a CI run scanning a PR's commit; see api_applications.py::create_run).
    source_ref: str | None = None
