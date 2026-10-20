"""F2 content assembly: per-value trimming, dropping whole properties, never trimming the always-sent parts."""

from __future__ import annotations

from kresheen.dashboard.routes.api_threat_explain import build_explain_content
from kresheen.engine.llm import limits
from kresheen.models.threat import Threat


def _threat(**kw) -> Threat:
    base = {
        "key": "K", "rule_id": "R-1", "element_kind": "component", "element_id": "N-1", "element_name": "DB",
        "element_type": "data_store", "methodology": "STRIDE", "category": "Tampering",
        "title": "DB can be altered", "description": "Describes the threat.", "severity": "high",
        "mitigations": ["Restrict writes."], "cwe_refs": [], "attack_refs": [], "risk_factors": ["No auth"],
        "origin": "predefined",
    }
    base.update(kw)
    return Threat(**base)


def test_under_the_cap_nothing_changes():
    built = build_explain_content(_threat(), {"a": "x", "b": "y"})
    assert built.trimmed is False
    assert built.content == built.full
    assert "- a: x" in built.content


def test_long_value_is_cut_with_a_marker():
    built = build_explain_content(_threat(), {"a": "z" * 3000})
    assert built.trimmed is True
    assert f"- a: {'z' * limits.EXPLAIN_MAX_PROPERTY_CHARS} [trimmed]" in built.content
    assert "z" * 3000 in built.full


def test_longest_properties_are_dropped_first_with_a_note():
    props = {f"p{i}": "v" * 900 for i in range(6)} | {"keep": "short"}
    built = build_explain_content(_threat(), props, max_chars=2500)
    assert len(built.content) <= 2500
    assert built.trimmed is True
    assert "- keep: short" in built.content
    assert "properties were left out" in built.content or "property was left out" in built.content
    assert "p0" in built.full and "p5" in built.full


def test_always_sent_parts_are_never_trimmed():
    long_desc = "d" * 20_000
    built = build_explain_content(_threat(description=long_desc, mitigations=["m" * 5000]), {"a": "b"})
    assert long_desc in built.content
    assert "m" * 5000 in built.content
    assert "Name: DB" in built.content and "Type: data_store" in built.content
    assert len(built.content) > limits.EXPLAIN_MAX_INPUT_CHARS
