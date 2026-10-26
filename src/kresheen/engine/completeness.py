"""What a threat model does not say yet.

Threats and their ranking depend on a few facts only the owner knows: what data a
store holds, whether a service authenticates callers, whether a flow that leaves a
trust boundary is encrypted. An element with none of these stated gets the generic
result. This lists the unstated ones so the owner can answer them (each answer is an
ordinary element property) and shows how much of the model is stated. Pure: it
reads the merged DFD and stores nothing.

The score counts only the property questions (the four `_check_*` below), not the
structural notes: those have no answer that can be given inline.
"""

from __future__ import annotations

import re

from kresheen.engine.threats.generate import DfdElement, DfdFlow, crosses_boundary
from kresheen.engine.threats.properties import is_out_of_scope
from kresheen.models.completeness import Alternative, CompletenessItem, CompletenessOut, FixSpec
from kresheen.models.threat_model_run import SourceResult

_SECURE_HINT = re.compile(r"\b(https|tls|ssl|mtls|ssh|sftp|grpcs|amqps|wss|ldaps)\b", re.IGNORECASE)
_INSECURE_HINT = re.compile(r"\b(http|ftp|telnet|plaintext|plain text|unencrypted)\b(?!s)", re.IGNORECASE)
_CLASSIFICATIONS = ["PII", "PHI", "PCI", "Credentials", "Secrets"]
_IMPACT_ORDER = {"high": 0, "medium": 1, "low": 2}


def _stated(properties: dict, key: str) -> bool:
    value = properties.get(key)
    return value is not None and value != ""


def _hint_for_flow(flow: DfdFlow) -> tuple[bool | None, str]:
    """A guess at 'is it encrypted' from the flow's label or stated protocol. Only ever a
    suggestion the owner confirms; a label is not evidence."""
    for source, text in (("protocol", str(flow.properties.get("protocol", ""))), ("label", flow.label or "")):
        if not text:
            continue
        if _SECURE_HINT.search(text):
            return True, f'the {source} says "{text}"'
        if _INSECURE_HINT.search(text):
            return False, f'the {source} says "{text}"'
    return None, ""


def assess_completeness(
    elements: list[DfdElement], flows: list[DfdFlow], source_results: list[SourceResult]
) -> CompletenessOut:
    live = [e for e in elements if not is_out_of_scope(e.properties)]
    live_ids = {e.id for e in live}
    by_id = {e.id: e for e in live}
    live_flows = [
        f for f in flows if not is_out_of_scope(f.properties) and f.source_id in live_ids and f.target_id in live_ids
    ]
    inbound = {f.target_id for f in live_flows}
    connected = inbound | {f.source_id for f in live_flows}

    items: list[CompletenessItem] = []
    answered = 0
    total = 0

    for element in live:
        if element.type == "data_store":
            total += 1
            if (
                _stated(element.properties, "data_classification")
                or element.properties.get("no_sensitive_data") is True
            ):
                answered += 1
            else:
                items.append(
                    CompletenessItem(
                        id=f"data_classification|component:{element.id}",
                        check="data_classification",
                        element_kind="component",
                        element_id=element.id,
                        element_name=element.name,
                        message=f"What kind of data does {element.name} hold?",
                        why="Sensitive data (personal, health, payment, credentials) raises the impact of every threat on it by one level.",
                        impact="high",
                        fix=FixSpec(
                            property_key="data_classification",
                            kind="text",
                            options=_CLASSIFICATIONS,
                            alternative=Alternative(
                                key="no_sensitive_data", value=True, label="Holds no sensitive data"
                            ),
                        ),
                    )
                )
            total += 1
            if _stated(element.properties, "is_encrypted"):
                answered += 1
            else:
                items.append(
                    CompletenessItem(
                        id=f"encrypted_at_rest|component:{element.id}",
                        check="encrypted_at_rest",
                        element_kind="component",
                        element_id=element.id,
                        element_name=element.name,
                        message=f"Is {element.name} encrypted at rest?",
                        why="Without it, the engine assumes the stored data can be read by anyone who gets the disk or a backup.",
                        impact="medium",
                        fix=FixSpec(property_key="is_encrypted", kind="bool"),
                    )
                )
        elif element.type == "process" and element.id in inbound:
            total += 1
            if _stated(element.properties, "authenticates_callers"):
                answered += 1
            else:
                items.append(
                    CompletenessItem(
                        id=f"authenticates_callers|component:{element.id}",
                        check="authenticates_callers",
                        element_kind="component",
                        element_id=element.id,
                        element_name=element.name,
                        message=f"Does {element.name} require callers to authenticate?",
                        why="If it does, the exposure-driven likelihood of impersonation and access threats drops; if it does not, they stay high.",
                        impact="high",
                        fix=FixSpec(property_key="authenticates_callers", kind="bool"),
                    )
                )

    for flow in live_flows:
        source, target = by_id[flow.source_id], by_id[flow.target_id]
        if not crosses_boundary(source, target):
            continue
        total += 1
        if _stated(flow.properties, "is_encrypted"):
            answered += 1
            continue
        suggested, reason = _hint_for_flow(flow)
        items.append(
            CompletenessItem(
                id=f"encrypted_in_transit|flow:{flow.id}",
                check="encrypted_in_transit",
                element_kind="flow",
                element_id=flow.id,
                element_name=f"{source.name} -> {target.name}",
                message=f"Is {source.name} -> {target.name} encrypted in transit?",
                why="It crosses a trust boundary. Unencrypted, it is exposed to interception and tampering; the engine assumes that until told otherwise.",
                impact="high",
                fix=FixSpec(
                    property_key="is_encrypted", kind="bool", suggested_value=suggested, suggestion_reason=reason
                ),
            )
        )

    # Structural notes: no inline answer, they are fixed by editing the diagram.
    if len(live) >= 2 and not any(e.trust_boundary for e in live):
        items.append(
            CompletenessItem(
                id="no_boundaries|model",
                check="no_boundaries",
                element_kind="model",
                message="No trust boundaries are drawn.",
                why="Boundary-crossing threats (unencrypted or unvalidated data leaving a zone) can only be found where boundaries exist. Draw one around each zone that trusts different things.",
                impact="high",
            )
        )
    for element in live:
        if element.id not in connected and len(live) >= 2:
            items.append(
                CompletenessItem(
                    id=f"isolated_component|component:{element.id}",
                    check="isolated_component",
                    element_kind="component",
                    element_id=element.id,
                    element_name=element.name,
                    message=f"{element.name} is not connected to anything.",
                    why="Threats on data flows, and attack paths, need connections. Connect it, or mark it out of scope.",
                    impact="medium",
                )
            )
    if any(e.type == "process" for e in live) and not any(e.type == "external_entity" for e in live):
        items.append(
            CompletenessItem(
                id="no_external_actor|model",
                check="no_external_actor",
                element_kind="model",
                message="No users or third parties are drawn.",
                why="Attack paths start from external entities. Add whoever or whatever reaches the system from outside.",
                impact="low",
            )
        )
    for result in source_results:
        if result.status != "analysed":
            items.append(
                CompletenessItem(
                    id=f"unanalysed_input|{result.data_source_id}",
                    check="unanalysed_input",
                    element_kind="model",
                    message=f"A {result.type.replace('_', ' ')} input was stored but not analysed.",
                    why=result.message,
                    impact="high",
                )
            )

    for result in source_results:
        for index, warning in enumerate(result.warnings):
            items.append(
                CompletenessItem(
                    id=f"partial_input|{result.data_source_id}|{index}",
                    check="partial_input",
                    element_kind="model",
                    message=f"A {result.type.replace('_', ' ')} input was only partly analysed.",
                    why=warning,
                    impact="high",
                )
            )

    items.sort(key=lambda i: (_IMPACT_ORDER[i.impact], i.check, i.element_name.lower()))
    score = round(100 * answered / total) if total else None
    return CompletenessOut(score=score, answered=answered, total=total, items=items)
