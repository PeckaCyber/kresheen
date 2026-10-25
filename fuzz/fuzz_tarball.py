"""Coverage-guided fuzzing (Atheris) of the GitHub tarball extraction.

The input is an uncompressed tar archive (gzipped here, so mutations hit the tar headers rather than the deflate
stream). Extraction either refuses the archive or writes only inside its folder, never next to it. The same
property as tests/fuzz/test_ingest_fuzz.py.
"""

from __future__ import annotations

import gzip
import os
import sys
import tarfile
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from kresheen.engine.ingest.github_repository_ingestor import _extract_tarball_safely


def _escapes(root: Path, sandbox: Path) -> list[str]:
    bad = []
    for path in sandbox.rglob("*"):
        if path.is_relative_to(root):
            if path.is_symlink() and not Path(os.path.realpath(path)).is_relative_to(root.resolve()):
                bad.append(str(path))
            continue
        if path != root and not root.is_relative_to(path):
            bad.append(str(path))
    return bad


def TestOneInput(data: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        sandbox = Path(tmp)
        archive = sandbox / "repo.tar.gz"
        archive.write_bytes(gzip.compress(data, compresslevel=1))
        root = sandbox / "extract"
        root.mkdir()
        try:
            _extract_tarball_safely(str(archive), str(root))
        except (ValueError, tarfile.TarError, OSError):
            pass
        archive.unlink()
        assert _escapes(root, sandbox) == []


def main() -> None:
    # The archive parsing happens in the standard library's tarfile and gzip, so instrument those too: without
    # coverage there the fuzzer cannot steer towards new header shapes.
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
