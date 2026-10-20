"""Finding schema: a concrete issue found on one component of a threat model.

A finding comes from one of two places: the Grype dependency scan of a GitHub
source (domain `vulnerability`; see engine/ingest/github_repository_ingestor.py)
or the engine's own reasoning over the facts graph (domain `threat_model`; see
engine/reasoning.py). Findings are evidence that raises the likelihood of the
threats the engine derives; they are not threats themselves.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_DOMAIN_PREFIXES = {
    "threat_model": "TM",
    "vulnerability": "VULN",
}


class Domain(str, Enum):
    THREAT_MODEL = "threat_model"
    VULNERABILITY = "vulnerability"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Evidence(BaseModel):
    """What backs a finding. Sparse: a Grype vulnerability fills the CVE, score and fix
    fields; an engine finding fills the STRIDE category, MITRE/CWE references and
    attack path."""

    code_refs: list[str] = Field(default_factory=list)
    cwe_refs: list[str] = Field(default_factory=list)
    cve_refs: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    # Set only for a Grype-sourced vulnerability (github_repository_ingestor.py's
    # native-json scan) -- CISA's Known Exploited Vulnerabilities catalog, the
    # "actively exploited in the wild" signal engine/threats/risk.py uses as a
    # route to `almost_certain` (see its docstring).
    known_exploited: bool = False
    # Also Grype-sourced only. `fix_state` is one of Grype's own
    # fixed/not-fixed/wont-fix/unknown; blank (None) means Grype didn't know.
    fixed_versions: list[str] = Field(default_factory=list)
    fix_state: str | None = None
    stride_category: str | None = None
    mitre_technique_ids: list[str] = Field(default_factory=list)
    # Which FactNode ids (see models/facts.py) justify this finding -- set
    # only by the rule engine, for per-run explainability/provenance.
    # This is traceability over one run's already-computed graph, not a
    # stored component<->threat association, so it adds no persisted link
    # between components and threats.
    attack_path: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


def new_finding_id(domain: Domain) -> str:
    prefix = _DOMAIN_PREFIXES[domain.value]
    return f"F-{prefix}-{uuid.uuid4().hex[:16]}"


def _ensure_timezone_aware(value: datetime) -> datetime:
    """A naive datetime (or SQLite's DateTime column, which drops tzinfo on
    round-trip) is normalized to UTC so every discovered_at compares cleanly
    against `datetime.now(UTC)`."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class Finding(BaseModel):
    """One finding on one component.

    `asset_id` is the id of the component (Asset) the finding is about.
    `source_tool` is "grype" for a dependency vulnerability or
    "kresheen" for a finding produced by the rule-based engine.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    domain: Domain
    source_tool: str
    title: str
    description: str
    severity: Severity
    asset_id: str
    # Set only for engine-produced findings (source_tool="kresheen")
    # -- which ThreatModelRun this finding came from. Promoted to an
    # indexed column exactly like asset_id/source_tool, see storage/sql_repo.py.
    run_id: str | None = None
    sources: list[str] = Field(default_factory=list)
    evidence: Evidence
    discovered_at: datetime
    status: Literal["open", "resolved"] = "open"

    @field_validator("discovered_at")
    @classmethod
    def _normalize_discovered_at(cls, value: datetime) -> datetime:
        return _ensure_timezone_aware(value)

    @classmethod
    def create(
        cls,
        *,
        domain: Domain,
        source_tool: str,
        title: str,
        description: str,
        severity: Severity,
        asset_id: str,
        evidence: Evidence | None = None,
        discovered_at: datetime | None = None,
        **kwargs,
    ) -> Finding:
        """Convenience constructor: auto-generates id and sources."""
        return cls(
            id=new_finding_id(domain),
            domain=domain,
            source_tool=source_tool,
            title=title,
            description=description,
            severity=severity,
            asset_id=asset_id,
            sources=[source_tool],
            evidence=evidence or Evidence(),
            discovered_at=discovered_at or datetime.now(UTC),
            **kwargs,
        )
