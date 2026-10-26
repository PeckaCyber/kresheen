"""Design-level threats generated against DFD elements, and the user's
triage state for them.

Threats are *derived*, never stored: `engine/threats/generate.py` recomputes
them from the merged DFD (auto-generated components + manual components +
boundary overrides + manual flows) every time they're requested, so they can
never drift from what the diagram currently shows. The only persisted piece
is `ThreatStatusRecord`, the user's decision about one threat.

That record is keyed by `threat_key`, which is built from stable names
(`<rule id>|<component type>:<component name>` or
`<rule id>|flow:<source name>-><target name>`), never a run's ephemeral
Asset ids -- the same reasoning models/trust_boundary.py documents. A status
therefore survives re-scans, and reattaches if a deleted component is
re-created under the same name.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints, computed_field

ThreatStatusValue = Literal["open", "mitigated", "accepted", "not_applicable"]
"""`open` is the default and is never persisted -- setting a threat back to
open deletes its record."""

StrideCategory = Literal[
    "Spoofing",
    "Tampering",
    "Repudiation",
    "InformationDisclosure",
    "DenialOfService",
    "ElevationOfPrivilege",
]

# "Custom" is for a user-authored threat that fits none of the available
# methodologies; its category is free text. It is never selected per
# application (`Application.methodologies` is about generated rules), and
# custom threats are always on -- see `engine/threats/generate.py`.
Methodology = Annotated[str, StringConstraints(min_length=1, max_length=40)]
"""Which threat-generation methodology a rule/threat belongs to: "STRIDE", "Custom", or the name of a methodology a
plugin offers (`engine/threats/methodology.py`). It is a plain name, not a closed set, so a saved application or
threat that names a methodology this installation no longer offers still loads; the API refuses to *select* one that
is unavailable. `Application.methodologies` picks which ones are active for a run; STRIDE is the default and the only
one config-derived (`SC-Txx`) rules ever fire for. A methodology's categories are catalog data, not a type-level enum
(see `category` below)."""

CIAImpact = Literal["Confidentiality", "Integrity", "Availability"]
"""Cross-cutting impact tag every threat gets, auto-derived from its
(methodology, category) via engine/threats/cia.py -- never user-entered, and
never a selectable methodology of its own (confirmed with the user)."""

ThreatSeverity = Literal["critical", "high", "medium", "low"]

ThreatElementType = Literal["process", "data_store", "external_entity", "data_flow"]

Likelihood = Literal["very_rare", "rare", "possible", "likely", "almost_certain"]
"""How likely the threat is to be realised, after what the run shows (exposure,
evidence). `possible` is the default: a well-known technique against a
reachable element, with nothing known about this one. See engine/threats/risk.py."""

LIKELIHOOD_ORDER: tuple[Likelihood, ...] = ("very_rare", "rare", "possible", "likely", "almost_certain")

_IMPACT_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def risk_score_for(severity: str, likelihood: Likelihood) -> int:
    """Impact (1-4) x likelihood (1-5). `severity` on a threat is its impact."""
    return _IMPACT_WEIGHT[severity] * (LIKELIHOOD_ORDER.index(likelihood) + 1)


def risk_rating_for(score: int) -> Literal["critical", "high", "medium", "low"]:
    # 15 = high impact x almost certain, or critical x likely: the top band.
    if score >= 15:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


ThreatOrigin = Literal["predefined", "custom_rule", "manual"]
"""Where a threat came from: a built-in rule (engine/threats/catalog.py), a
user-authored Knowledge Base entry that auto-applies (`applies_to` set), or a
threat a user attached by hand to one specific element."""


def new_manual_threat_id() -> str:
    return f"MT-{uuid.uuid4().hex[:16]}"


def threat_status_id(application_id: str, threat_key: str) -> str:
    """Deterministic, so upserting a status for the same (application, threat)
    always hits the same row without a lookup-then-insert race."""
    digest = hashlib.sha256(f"{application_id}\0{threat_key}".encode()).hexdigest()[:16]
    return f"TS-{digest}"


class DreadScore(BaseModel):
    """An optional, purely informational scoring lens (Damage/Reproducibility/
    Exploitability/Affected users/Discoverability, 1-10 each) a user can set
    per threat. Never affects `Threat.risk_score`/`.risk` -- the existing
    impact x likelihood model stays authoritative for sorting/prioritization,
    since it is evidence- and control-aware and DREAD isn't."""

    damage: int = Field(ge=1, le=10)
    reproducibility: int = Field(ge=1, le=10)
    exploitability: int = Field(ge=1, le=10)
    affected_users: int = Field(ge=1, le=10)
    discoverability: int = Field(ge=1, le=10)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def average(self) -> float:
        return (
            self.damage + self.reproducibility + self.exploitability + self.affected_users + self.discoverability
        ) / 5


class ThreatStatusRecord(BaseModel):
    id: str
    application_id: str
    threat_key: str
    status: ThreatStatusValue
    note: str = ""
    dread: DreadScore | None = None
    updated_by_user_id: str | None = None
    updated_at: datetime


class ThreatEvidence(BaseModel):
    """A finding that supports a threat: it shows the weakness is really there.
    Evidence raises a threat's likelihood; it is never the threat itself (a
    threat survives every listed finding being fixed)."""

    finding_id: str
    title: str
    severity: str  # critical | high | medium | low | info
    # component: the finding is on this very component and STRIDE category.
    # repository: found in the source repository this component was defined in;
    # not confirmed to be present in this component's deployed image.
    scope: Literal["component", "repository"]


class Threat(BaseModel):
    """One generated threat against one DFD component or data flow."""

    key: str
    rule_id: str
    element_kind: Literal["component", "flow", "boundary"]
    # Ids are this run's ephemeral Asset/flow ids -- fine for the UI to
    # link a threat to a node on the diagram it's currently viewing, never
    # used for persistence (see module docstring).
    element_id: str
    element_name: str
    element_type: str  # process | data_store | external_entity | data_flow
    methodology: Methodology = "STRIDE"
    # None for a user-authored threat that didn't pick a category. A loose
    # string, not StrideCategory: each methodology has its own category set
    # (catalog data, see engine/threats/catalog*.py), not a shared enum.
    category: str | None = None
    # Auto-derived from (methodology, category) via engine/threats/cia.py --
    # never user-entered. Empty for a manual/KB threat whose category isn't
    # in the lookup table.
    cia_impacts: list[CIAImpact] = Field(default_factory=list)
    title: str
    description: str
    severity: ThreatSeverity
    mitigations: list[str]
    cwe_refs: list[str] = Field(default_factory=list)
    attack_refs: list[str] = Field(default_factory=list)
    # Why a conditional rule fired (e.g. "crosses a trust boundary").
    risk_factors: list[str] = Field(default_factory=list)
    origin: ThreatOrigin = "predefined"
    # Ids in a research taxonomy (e.g. "T08") this threat is an instance of,
    # set only by rules that recognise a specific misconfiguration.
    taxonomy_ids: list[str] = Field(default_factory=list)
    # Set only for origin="manual": the id to DELETE to remove it.
    manual_threat_id: str | None = None
    # Risk model (engine/threats/risk.py). `severity` above is the impact; this
    # is how likely it is here, and what supports that. Unassessed = possible.
    likelihood: Likelihood = "possible"
    likelihood_factors: list[str] = Field(default_factory=list)
    evidence: list[ThreatEvidence] = Field(default_factory=list)  # capped, worst first
    evidence_total: int = 0  # how many findings support it in all

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verification(self) -> list[str]:
        """How to check the mitigation worked from a plugin's `action_guidance` hook; empty in the
        open-source core."""
        from kresheen.plugins import get_registry

        plugin = get_registry().guidance(self.rule_id, self.methodology, self.category)
        return list(plugin.verification) if plugin is not None else []

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fix_example(self) -> str:
        """An example fix in the shape of the configuration that was read; empty when there is none."""
        from kresheen.plugins import get_registry

        plugin = get_registry().guidance(self.rule_id, self.methodology, self.category)
        return plugin.fix_example if plugin is not None else ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fix_example_for(self) -> str:
        """The mitigation the example fix implements, so it is shown beside the right one."""
        from kresheen.plugins import get_registry

        plugin = get_registry().guidance(self.rule_id, self.methodology, self.category)
        index = plugin.fix_example_mitigation_index if plugin is not None else None
        return self.mitigations[index] if index is not None and index < len(self.mitigations) else ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def basis(self) -> Literal["observed", "specific", "generic"]:
        """Why this threat is on the list.

        observed: found in the ingested configuration (an `SC-*` config rule) or backed by a
        scanner finding. specific: a fact about this design triggered it (a stated property,
        an untrusted-facing boundary, a boundary crossing), or a person added it. generic: a
        per-element checklist item that applies to any element of that type."""
        if self.rule_id.startswith("SC-") or self.evidence_total > 0:
            return "observed"
        if self.origin != "predefined" or self.risk_factors:
            return "specific"
        return "generic"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk_score(self) -> int:
        return risk_score_for(self.severity, self.likelihood)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk(self) -> Literal["critical", "high", "medium", "low"]:
        return risk_rating_for(self.risk_score)


class ManualThreat(BaseModel):
    """A threat a user attached to one specific element by hand.

    Application-scoped and keyed to its element by *name* (`element_key`, the
    same `<type>:<name>` / `flow:<src>-><tgt>` form threat keys use), so it
    survives re-scans and is simply not shown for a run that no longer has
    that element. Text is a snapshot: copying from a KB entry doesn't keep a
    live link, so editing or deleting the entry later can't change or break
    threats already attached (`kb_entry_id` is provenance only)."""

    id: str
    application_id: str
    element_kind: Literal["component", "flow"]
    element_type: ThreatElementType
    element_key: str
    element_name: str
    kb_entry_id: str | None = None
    title: str
    description: str = ""
    severity: ThreatSeverity = "medium"
    methodology: Methodology = "STRIDE"
    category: str | None = None
    mitigations: list[str] = Field(default_factory=list)
    created_by_user_id: str | None = None
    created_at: datetime


class ThreatOut(Threat):
    """A `Threat` joined with the user's status for it (default open)."""

    status: ThreatStatusValue = "open"
    note: str = ""
    dread: DreadScore | None = None
    status_updated_at: datetime | None = None


class ThreatSummary(BaseModel):
    total: int
    by_status: dict[str, int]
    # Severity counts over *open* threats only -- the number that says how
    # much triage work is left.
    open_by_severity: dict[str, int]
    # The same over *risk* (impact x likelihood), which is what threats are ranked by.
    open_by_risk: dict[str, int] = Field(default_factory=dict)


class CoverageGapOut(BaseModel):
    """An entry-point fact (Ingress, RBAC binding) no rule ever evaluated --
    see engine/threats/coverage.py. Distinct from a threat: nothing was
    found wrong, nothing was found at all."""

    kind: str
    name: str
    reason: str


class DocConflictOut(BaseModel):
    """A component the architecture diagram claims exists that no ingested
    infrastructure source matches -- see engine/threats/doc_conflicts.py."""

    kind: str
    name: str
    reason: str


class ThreatsOut(BaseModel):
    threats: list[ThreatOut]
    summary: ThreatSummary
    coverage_gaps: list[CoverageGapOut] = Field(default_factory=list)
    doc_conflicts: list[DocConflictOut] = Field(default_factory=list)
    # Methodologies the application has selected that this installation does not offer (for example a plugin's,
    # after its licence lapsed). No threats are generated for them; the UI and reports say so rather than let the
    # shorter list read as a clean result.
    unavailable_methodologies: list[str] = Field(default_factory=list)
