"""Threat-modelling methodologies as data: the core ships STRIDE; a plugin can add more.

A `MethodologySpec` bundles everything one methodology contributes: its categories and their descriptions, the
Confidentiality/Integrity/Availability impact of each category, its generation rules, and any owner-stated element
properties those rules read. `available_methodologies()` is STRIDE followed by whatever the installed plugins offer
through `Plugin.methodologies`; threat generation, the CIA tags, the knowledge-base rule list, the rule-catalog hash
and the API all read it, so a methodology that is not offered is simply absent everywhere.

"Custom" is not a methodology in this sense: it is the free-text category of user-authored threats, always on, and
has no spec.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

from kresheen.engine.threats.catalog import RULES, ThreatRule
from kresheen.models.threat import CIAImpact
from kresheen.plugins import get_registry

if TYPE_CHECKING:
    from kresheen.engine.threats.properties import PropertySpec

STRIDE = "STRIDE"
CUSTOM = "Custom"
"""The free-text methodology of user-authored threats. Always allowed, never selected per application."""

_CIA_ORDER = ("Confidentiality", "Integrity", "Availability")


@dataclass(frozen=True)
class MethodologySpec:
    name: str
    description: str
    categories: tuple[str, ...]
    category_descriptions: Mapping[str, str] = field(default_factory=dict)
    # category -> CIA impacts. A category without an entry (or with an empty set) has no CIA tag.
    cia: Mapping[str, frozenset[CIAImpact]] = field(default_factory=dict)
    rules: tuple[ThreatRule, ...] = ()
    # Owner-stated properties the rules read, offered on the element types in `property_element_types`.
    properties: tuple[PropertySpec, ...] = ()
    property_element_types: tuple[str, ...] = ("process", "data_store")


# STRIDE-to-CIA has several published variants (some map Spoofing/Repudiation to "Authentication" and
# "Non-repudiation", outside the CIA triad); this picks the closest CIA-only equivalent for each category.
STRIDE_SPEC = MethodologySpec(
    name=STRIDE,
    description=(
        "Six ways an attacker can misuse a system: spoofing, tampering, repudiation, information disclosure, "
        "denial of service and elevation of privilege."
    ),
    categories=("Spoofing", "Tampering", "Repudiation", "InformationDisclosure", "DenialOfService", "ElevationOfPrivilege"),
    category_descriptions=MappingProxyType(
        {
            "Spoofing": "Someone pretends to be a user or service they are not.",
            "Tampering": "Data or code is modified without authorization.",
            "Repudiation": "An attacker denies performing an action and cannot be proven otherwise.",
            "InformationDisclosure": "Data is disclosed to people who should not have access.",
            "DenialOfService": "An attacker makes a service unavailable or unusable.",
            "ElevationOfPrivilege": "An attacker gains higher-level permissions than intended.",
        }
    ),
    cia=MappingProxyType(
        {
            "Spoofing": frozenset({"Confidentiality", "Integrity"}),
            "Tampering": frozenset({"Integrity"}),
            "Repudiation": frozenset({"Integrity"}),
            "InformationDisclosure": frozenset({"Confidentiality"}),
            "DenialOfService": frozenset({"Availability"}),
            "ElevationOfPrivilege": frozenset({"Confidentiality", "Integrity", "Availability"}),
        }
    ),
    rules=RULES,
)


def available_methodologies() -> tuple[MethodologySpec, ...]:
    """STRIDE, then the plugins' methodologies. A plugin methodology that reuses a name already taken (or "Custom")
    is skipped, as are rules whose `methodology` is not the spec's own name."""
    specs = [STRIDE_SPEC]
    taken = {STRIDE, CUSTOM}
    for spec in get_registry().methodologies():
        if spec.name in taken:
            continue
        taken.add(spec.name)
        specs.append(spec)
    return tuple(specs)


def available_methodology_names() -> frozenset[str]:
    return frozenset(spec.name for spec in available_methodologies())


def methodology_rules() -> tuple[ThreatRule, ...]:
    """Every built-in generation rule of every available methodology."""
    return tuple(rule for spec in available_methodologies() for rule in spec.rules if rule.methodology == spec.name)


def cia_for(methodology: str, category: str | None) -> list[CIAImpact]:
    if category is None:
        return []
    for spec in available_methodologies():
        if spec.name == methodology:
            return sorted(spec.cia.get(category, ()), key=_CIA_ORDER.index)
    return []


def unavailable_methodologies(selected: list[str] | tuple[str, ...]) -> list[str]:
    """The selected names this installation cannot generate for (for example after a licence lapsed)."""
    names = available_methodology_names()
    return [m for m in selected if m not in names]
