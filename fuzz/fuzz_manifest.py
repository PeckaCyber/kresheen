"""Coverage-guided fuzzing (Atheris) of the manifest upload: Kubernetes YAML and Terraform plan JSON.

Any text must be read or refused with a "bad input" error (ValueError, a YAML error), never fail with a TypeError,
KeyError or AttributeError from an unexpected shape. The same property as tests/fuzz/test_ingest_fuzz.py.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    import yaml

    from kresheen.engine.ingest.manifest_ingestor import ManifestUploadIngestor

EXPECTED_INPUT_ERRORS = (ValueError, yaml.YAMLError, RecursionError)


def TestOneInput(data: bytes) -> None:
    ingestor = ManifestUploadIngestor()
    try:
        records = ingestor.parse(data.decode("utf-8", errors="replace"))
        ingestor.normalize(records, run_id="run-1", application_id="app-1")
    except EXPECTED_INPUT_ERRORS:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
