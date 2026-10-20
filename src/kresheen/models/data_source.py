"""DataSourceConfig: where one Application's facts come from.

Functional ingestors exist for `manifest_upload`, `github_repository`, `architecture_diagram`
and `documentation` (see `engine/ingest/`). The type list stays as stored data may
use it, but only the four types above are accepted by the API.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


def new_data_source_id() -> str:
    return f"DS-{uuid.uuid4().hex[:16]}"


class DataSourceConfig(BaseModel):
    id: str
    application_id: str
    type: Literal[
        "manifest_upload",
        "github_repository",
        "architecture_diagram",
        "documentation",
        "container_image",
        "rpm_package",
        "kubernetes_operator",
    ]
    connection_details: dict = Field(default_factory=dict)
    credential_ref: str | None = None
    # Content digest stamped when the source is created (engine.provenance.input_digest), so staleness checks
    # can compare digests without loading `connection_details`, which can be megabytes. None on older rows.
    digest: str | None = None
    created_at: datetime
    last_ingested_at: datetime | None = None
