"""Renaming a manual DFD component without orphaning the state keyed to its name.

Every Application-scoped overlay refers to a component by *name*, never by a
run's ephemeral asset id (see models/trust_boundary.py), so changing a name has
to move that state with it: the trust-boundary label, manual flows that use a
`name:` ref, the triage status of each threat, stated element properties, and manual threats
attached to the component or to a flow touching it.

Flow element keys are `flow:<source>-><target>`. A name that itself contains
`->` makes that ambiguous; `rename_element_key` resolves it by trying every
split, which is exact for any name that doesn't reproduce the other endpoint's
text around an arrow (a deliberate limit, not worth a new key format).
"""

from __future__ import annotations

from datetime import UTC, datetime

from kresheen.models.diagram_layout import diagram_element_layout_id
from kresheen.models.element_properties import element_properties_id
from kresheen.models.manual_flow import name_ref
from kresheen.models.threat import ThreatStatusRecord, threat_status_id
from kresheen.storage.repository import Repository

_ARROW = "->"


def rename_element_key(element_key: str, element_type: str, old: str, new: str) -> str | None:
    """The element key after renaming component `old` (of `element_type`) to
    `new`, or None when this key doesn't refer to that component."""
    if element_key == f"{element_type}:{old}":
        return f"{element_type}:{new}"
    if not element_key.startswith("flow:"):
        return None
    body = element_key.removeprefix("flow:")
    position = body.find(_ARROW)
    while position != -1:
        source, target = body[:position], body[position + len(_ARROW) :]
        if source == old or target == old:
            return f"flow:{new if source == old else source}{_ARROW}{new if target == old else target}"
        position = body.find(_ARROW, position + 1)
    return None


def _display_name(element_key: str) -> str:
    if element_key.startswith("flow:"):
        source, _, target = element_key.removeprefix("flow:").partition(_ARROW)
        return f"{source} -> {target}"
    return element_key.partition(":")[2]


def rename_component_overlays(
    repo: Repository, application_id: str, *, element_type: str, old: str, new: str
) -> None:
    """Moves every name-keyed overlay from `old` to `new` for this Application."""
    now = datetime.now(UTC)

    assignments = repo.list_trust_boundary_assignments(application_id)
    moving = next((a for a in assignments if a.component_name == old), None)
    if moving is not None:
        for stale in (a for a in assignments if a.component_name == new):
            repo.delete_trust_boundary_assignment(stale.id)
        repo.save_trust_boundary_assignment(
            moving.model_copy(update={"component_name": new, "updated_at": now})
        )

    for flow in repo.list_manual_flows(application_id):
        updates = {}
        if flow.source_ref == name_ref(old):
            updates["source_ref"] = name_ref(new)
        if flow.target_ref == name_ref(old):
            updates["target_ref"] = name_ref(new)
        if updates:
            repo.save_manual_flow(flow.model_copy(update={**updates, "updated_at": now}))

    for record in repo.list_threat_statuses(application_id):
        rule_id, separator, element_key = record.threat_key.partition("|")
        renamed = rename_element_key(element_key, element_type, old, new) if separator else None
        if renamed is None:
            continue
        new_key = f"{rule_id}|{renamed}"
        repo.delete_threat_status(record.id)
        replacement: ThreatStatusRecord = record.model_copy(
            update={"id": threat_status_id(application_id, new_key), "threat_key": new_key}
        )
        repo.save_threat_status(replacement)

    for stated in repo.list_element_properties(application_id):
        renamed = rename_element_key(stated.element_key, element_type, old, new)
        if renamed is None:
            continue
        repo.delete_element_properties(stated.id)
        repo.save_element_properties(
            stated.model_copy(update={"id": element_properties_id(application_id, renamed), "element_key": renamed})
        )

    for manual in repo.list_manual_threats(application_id):
        renamed = rename_element_key(manual.element_key, element_type, old, new)
        if renamed is None:
            continue
        repo.save_manual_threat(
            manual.model_copy(update={"element_key": renamed, "element_name": _display_name(renamed)})
        )

    for diagram in repo.list_diagrams_for_application(application_id):
        for layout in repo.list_diagram_element_layouts(diagram.id):
            renamed = rename_element_key(layout.element_key, element_type, old, new)
            if renamed is None:
                continue
            repo.delete_diagram_element_layout(layout.id)
            repo.save_diagram_element_layout(
                layout.model_copy(
                    update={"id": diagram_element_layout_id(diagram.id, renamed), "element_key": renamed}
                )
            )
