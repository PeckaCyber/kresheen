"""Persists a hand-drawn model (components, connections, stated facts) built in code.

Shared by the bundled sample (engine/samples) and the guided intake
(engine/intake.py): both produce an ordinary manual model, the same rows the diagram
editor writes, so everything downstream (threats, completeness, the action plan,
exports, editing) treats it like any other hand-drawn model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from kresheen.models.application import Application
from kresheen.models.asset import Asset, AssetType, new_manual_asset_id
from kresheen.models.element_properties import ElementPropertiesRecord, element_properties_id
from kresheen.models.manual_flow import ManualFlow, new_manual_flow_id
from kresheen.storage.repository import Repository

PropertyValue = bool | str


@dataclass
class ComponentSpec:
    name: str
    type: AssetType
    boundary: str
    properties: dict[str, PropertyValue] = field(default_factory=dict)


@dataclass
class FlowSpec:
    source: str  # a component name
    target: str
    label: str
    properties: dict[str, PropertyValue] = field(default_factory=dict)


def persist_manual_model(
    repo: Repository,
    application: Application,
    owner_user_id: str,
    components: list[ComponentSpec],
    flows: list[FlowSpec],
) -> None:
    """Saves the application, then its components, connections and stated properties.
    Component names must be unique: overlays are keyed by name."""
    names = [c.name for c in components]
    if len(set(names)) != len(names):
        raise ValueError("Component names must be unique")
    now = datetime.now(UTC)
    repo.save_application(application)

    ids: dict[str, str] = {}
    for component in components:
        asset = Asset(
            id=new_manual_asset_id(),
            name=component.name,
            type=component.type,
            trust_boundary=component.boundary,
            source="manual",
            application_id=application.id,
            run_id=None,
            created_at=now,
        )
        repo.save_asset(asset)
        ids[component.name] = asset.id
        _save_properties(
            repo, application.id, owner_user_id, f"{component.type.value}:{component.name}", component.properties, now
        )
    for flow in flows:
        if flow.source not in ids or flow.target not in ids:
            raise ValueError(f"Flow {flow.source} -> {flow.target} references an unknown component")
        repo.save_manual_flow(
            ManualFlow(
                id=new_manual_flow_id(),
                application_id=application.id,
                source_ref=f"asset:{ids[flow.source]}",
                target_ref=f"asset:{ids[flow.target]}",
                label=flow.label,
                created_at=now,
                updated_at=now,
            )
        )
        _save_properties(repo, application.id, owner_user_id, f"flow:{flow.source}->{flow.target}", flow.properties, now)


def _save_properties(
    repo: Repository,
    application_id: str,
    user_id: str,
    element_key: str,
    properties: dict[str, PropertyValue],
    now: datetime,
) -> None:
    if not properties:
        return
    repo.save_element_properties(
        ElementPropertiesRecord(
            id=element_properties_id(application_id, element_key),
            application_id=application_id,
            element_key=element_key,
            properties=dict(properties),
            updated_by_user_id=user_id,
            updated_at=now,
        )
    )
