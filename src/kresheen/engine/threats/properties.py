"""Which properties a user can state about a DFD element, and validation.

One table drives the API (validation), `GET /api/element-property-specs`, and
the UI form, so the key list is never duplicated. Booleans are tri-state in the
UI (unknown / yes / no): unknown is simply an absent key. Rules that read a
property live in catalog.py (`ThreatRule.when`); a plugin methodology can add
properties for its own rules (`MethodologySpec.properties`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from kresheen.models.element_properties import PropertyValue

PropertyKind = Literal["bool", "text"]

TEXT_LIMIT = 500


@dataclass(frozen=True)
class PropertySpec:
    key: str
    label: str
    kind: PropertyKind
    help: str = ""


_OUT_OF_SCOPE = (
    PropertySpec(
        "out_of_scope", "Out of scope", "bool", "Excluded from this threat model; its generated threats are hidden."
    ),
    PropertySpec("out_of_scope_reason", "Reason out of scope", "text", "Why it is excluded (shown on the diagram)."),
)

_DIE = (
    # Sounil Yu's resilience heuristic, modeled as owner-stated properties rather than generated
    # threats -- it rates a component's posture, it doesn't enumerate ways
    # to attack it. See ApplicationDetail.tsx's "Resilience (DIE)" badge,
    # computed client-side from whichever of these three are set.
    PropertySpec(
        "die_distributed",
        "Distributed",
        "bool",
        "Runs as multiple, independently-failable replicas rather than a single instance.",
    ),
    PropertySpec(
        "die_immutable", "Immutable", "bool", "Rebuilt and replaced on change, never patched or mutated in place."
    ),
    PropertySpec("die_ephemeral", "Ephemeral", "bool", "Short-lived; easily and routinely destroyed and recreated."),
)

_DATA_CLASSIFICATION = (
    # Asset sensitivity as an impact input. Free text, not a closed enum -- classification
    # schemes vary (PII, PCI, credentials, ...) and PropertySpec only has
    # bool/text kinds. Any non-empty value raises every threat on this
    # element (or, for a flow, this flow) by one impact level, capped at
    # critical -- see engine/threats/risk.py::_bump_for_sensitivity.
    PropertySpec(
        "data_classification",
        "Data classification",
        "text",
        "e.g. PII, PCI, credentials -- any non-empty value raises this element's threats by one impact level.",
    ),
    # Settles the model-completeness question (engine/completeness.py) without asserting a class:
    # no threat rule reads it, and it must not raise impact the way a classification does.
    PropertySpec(
        "no_sensitive_data",
        "Holds no sensitive data",
        "bool",
        "Say so once, so the completeness check stops asking. Does not change any threat.",
    ),
)


def _plugin_specs(element_type: str) -> tuple[PropertySpec, ...]:
    """Properties the available plugin methodologies' rules read (see `MethodologySpec.properties`)."""
    from kresheen.engine.threats.methodology import available_methodologies

    return tuple(
        spec
        for methodology in available_methodologies()
        if element_type in methodology.property_element_types
        for spec in methodology.properties
    )


def property_specs() -> dict[str, tuple[PropertySpec, ...]]:
    """The properties a user can state per element type: the core's, plus those the available plugin methodologies
    add (shown after the resilience properties)."""
    return {
        "process": (
            PropertySpec(
                "authenticates_callers", "Authenticates callers", "bool", "Every caller must prove who it is."
            ),
            PropertySpec(
                "runs_privileged",
                "Runs with elevated privileges",
                "bool",
                "Root, administrator, or a privileged container.",
            ),
            PropertySpec("is_web_application", "Is a web application", "bool", "Handles browser or HTTP input."),
            *_DIE,
            *_plugin_specs("process"),
            *_DATA_CLASSIFICATION,
            *_OUT_OF_SCOPE,
        ),
        "data_store": (
            PropertySpec("is_encrypted", "Encrypted at rest", "bool"),
            PropertySpec("stores_credentials", "Stores credentials", "bool", "Passwords, keys, tokens or secrets."),
            PropertySpec("is_a_log", "Is a log", "bool"),
            PropertySpec("is_signed", "Tamper-evident (signed or append-only)", "bool", "Only matters for a log."),
            *_DIE,
            *_plugin_specs("data_store"),
            *_DATA_CLASSIFICATION,
            *_OUT_OF_SCOPE,
        ),
        "external_entity": (*_plugin_specs("external_entity"), *_OUT_OF_SCOPE),
        "data_flow": (
            PropertySpec("protocol", "Protocol", "text", "e.g. HTTPS, gRPC, SQL."),
            PropertySpec("is_encrypted", "Encrypted in transit", "bool"),
            PropertySpec("crosses_public_network", "Crosses a public network", "bool"),
            PropertySpec("authenticated", "Both ends authenticate", "bool", "e.g. mutual TLS or signed requests."),
            *_plugin_specs("data_flow"),
            *_DATA_CLASSIFICATION,
            *_OUT_OF_SCOPE,
        ),
    }


def known_property_keys(element_type: str) -> frozenset[str]:
    return frozenset(spec.key for spec in property_specs().get(element_type, ()))


class InvalidPropertiesError(ValueError):
    pass


def validate_properties(element_type: str, properties: dict[str, PropertyValue]) -> dict[str, PropertyValue]:
    """Returns the cleaned properties (text trimmed, empty text dropped), or
    raises InvalidPropertiesError for an unknown key or a value of the wrong type."""
    specs = {spec.key: spec for spec in property_specs().get(element_type, ())}
    if not specs:
        raise InvalidPropertiesError(f"Unknown element type: {element_type}")
    cleaned: dict[str, PropertyValue] = {}
    for key, value in properties.items():
        spec = specs.get(key)
        if spec is None:
            raise InvalidPropertiesError(f"'{key}' is not a property of a {element_type.replace('_', ' ')}")
        if spec.kind == "bool":
            if not isinstance(value, bool):
                raise InvalidPropertiesError(f"'{key}' must be true or false")
            cleaned[key] = value
        else:
            if not isinstance(value, str) or len(value) > TEXT_LIMIT:
                raise InvalidPropertiesError(f"'{key}' must be text of at most {TEXT_LIMIT} characters")
            if value.strip():
                cleaned[key] = value.strip()
    return cleaned


def is_out_of_scope(properties: dict[str, PropertyValue]) -> bool:
    return properties.get("out_of_scope") is True
