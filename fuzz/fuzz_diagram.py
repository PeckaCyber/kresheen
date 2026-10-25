"""Coverage-guided fuzzing (Atheris) of the architecture diagram parser.

Any text must parse to a result within the caps or to None, never raise. The same property as
tests/fuzz/test_ingest_fuzz.py, driven by libFuzzer's coverage feedback instead of generated shapes.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from kresheen.engine.ingest.diagrams import parse_diagram
    from kresheen.engine.ingest.diagrams.model import MAX_COMPONENTS, MAX_FLOWS, MAX_NAME_CHARS


def TestOneInput(data: bytes) -> None:
    result = parse_diagram(data.decode("utf-8", errors="replace"))
    if result is None:
        return
    assert len(result.components) <= MAX_COMPONENTS
    assert len(result.flows) <= MAX_FLOWS
    keys = {c.key for c in result.components}
    for component in result.components:
        assert len(component.name) <= MAX_NAME_CHARS
        assert "\n" not in component.name
        assert component.type in ("process", "data_store", "external_entity")
    for flow in result.flows:
        assert flow.source in keys and flow.target in keys


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
