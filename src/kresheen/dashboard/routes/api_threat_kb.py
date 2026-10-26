"""JSON API for the Threat Knowledge Base tab: browse MITRE ATT&CK/CWE/
custom entries, add a custom threat. The Pro-managed curated feed
(`source="kresheen_curated"`) is filtered out of the list unless the Pro
plugin is licensed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from kresheen.dashboard.auth import get_current_session, get_current_user, require_csrf
from kresheen.dashboard.deps import get_repo
from kresheen.dashboard.methodology_checks import require_available_methodologies
from kresheen.engine.threats.config_rules import all_config_rules
from kresheen.engine.threats.methodology import methodology_rules
from kresheen.engine.threats.properties import property_specs
from kresheen.models.threat import Methodology, ThreatElementType, ThreatSeverity
from kresheen.models.threat_kb import ThreatKBEntry, new_kb_entry_id
from kresheen.models.user import User
from kresheen.storage.repository import Repository

router = APIRouter(prefix="/api/threat-kb", tags=["threat-kb"], dependencies=[Depends(get_current_session)])


class CreateCustomEntryRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(max_length=2000)
    tags: list[str] = Field(default_factory=list)
    url: str | None = None
    # Optional: set `applies_to` to make this entry generate a threat on every
    # matching element of every run (see engine/threats/custom.py). Leave it
    # unset for a reference-only entry.
    applies_to: ThreatElementType | None = None
    boundary_hint: str | None = Field(default=None, max_length=100)
    methodology: Methodology = "STRIDE"
    category: str | None = None
    severity: ThreatSeverity = "medium"
    mitigations: list[Annotated[str, Field(min_length=1, max_length=500)]] = Field(default_factory=list, max_length=20)


class PredefinedRuleOut(BaseModel):
    """One built-in threat generation rule (engine/threats/catalog.py, or a plugin methodology's), shaped
    for display. Unlike `ThreatKBEntry` rows these are code, not data: they are
    what actually drives threat generation today."""

    id: str
    element_type: str
    methodology: str
    category: str | None
    title: str
    description: str
    severity: str
    mitigations: list[str]
    cwe_refs: list[str]
    attack_refs: list[str]
    applies_when: str
    # Set for configuration-aware rules that recognise a specific misconfiguration
    # (an id in the research taxonomy, e.g. "T08"); None for the generic rules.
    taxonomy_id: str | None = None


_APPLIES_WHEN = {
    "always": "Every element of this type",
    "crosses_boundary": "Only when the flow crosses a trust boundary",
    "untrusted_facing": "Only when the component is in an untrusted-facing trust boundary",
}


def _generic(text: str) -> str:
    return text.replace("{name}", "<element>")


class PropertySpecOut(BaseModel):
    key: str
    label: str
    kind: str
    help: str


@router.get("/property-specs", response_model=dict[str, list[PropertySpecOut]])
def list_property_specs() -> dict[str, list[PropertySpecOut]]:
    """The properties a user can state per element type; the UI builds its
    properties form from this so the key list lives in one place."""
    return {
        element_type: [PropertySpecOut(key=s.key, label=s.label, kind=s.kind, help=s.help) for s in specs]
        for element_type, specs in property_specs().items()
    }


@router.get("/rules", response_model=list[PredefinedRuleOut])
def list_predefined_rules() -> list[PredefinedRuleOut]:
    return [
        PredefinedRuleOut(
            id=rule.id,
            element_type=rule.element_type,
            methodology=rule.methodology,
            category=rule.category,
            title=_generic(rule.title),
            description=_generic(rule.description),
            severity=rule.severity,
            mitigations=[_generic(m) for m in rule.mitigations],
            cwe_refs=list(rule.cwe),
            attack_refs=list(rule.attack),
            applies_when=f"Only when the owner states: {rule.asserted}" if rule.when else _APPLIES_WHEN[rule.condition],
        )
        for rule in methodology_rules()
    ] + [
        PredefinedRuleOut(
            id=rule.id,
            element_type=rule.target,
            methodology="STRIDE",
            category=rule.category,
            title=_generic(rule.title),
            description=_generic(rule.description),
            severity=rule.severity,
            mitigations=[_generic(m) for m in rule.mitigations],
            cwe_refs=list(rule.cwe),
            attack_refs=list(rule.attack),
            applies_when=rule.applies_when,
            taxonomy_id=rule.taxonomy_id,
        )
        for rule in all_config_rules()
    ]


@router.get("", response_model=list[ThreatKBEntry])
def list_entries(source: str | None = None, repo: Repository = Depends(get_repo)) -> list[ThreatKBEntry]:
    entries = repo.list_kb_entries(source=source)
    # The curated feed is not part of the open-source core.
    entries = [e for e in entries if e.source != "kresheen_curated"]
    return entries


@router.post("", response_model=ThreatKBEntry, dependencies=[Depends(require_csrf)])
def create_custom_entry(
    body: CreateCustomEntryRequest,
    user: User = Depends(get_current_user),
    repo: Repository = Depends(get_repo),
) -> ThreatKBEntry:
    require_available_methodologies([body.methodology])
    now = datetime.now(UTC)
    entry = ThreatKBEntry(
        id=new_kb_entry_id(),
        source="custom",
        name=body.name,
        description=body.description,
        tags=body.tags,
        url=body.url,
        applies_to=body.applies_to,
        boundary_hint=(body.boundary_hint or "").strip() or None,
        methodology=body.methodology,
        category=body.category,
        severity=body.severity,
        mitigations=body.mitigations,
        created_by_user_id=user.id,
        created_at=now,
        updated_at=now,
    )
    repo.save_kb_entries([entry])
    return entry


@router.delete("/{entry_id}", status_code=204, dependencies=[Depends(require_csrf)])
def delete_entry(entry_id: str, repo: Repository = Depends(get_repo)) -> None:
    entry = repo.get_kb_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Unknown threat knowledge base entry")
    if entry.source != "custom":
        raise HTTPException(status_code=403, detail="Only custom entries can be deleted")
    repo.delete_kb_entry(entry_id)
