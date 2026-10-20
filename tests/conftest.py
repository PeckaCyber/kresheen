"""Shared test fixtures.

`KRESHEEN_SECRET_KEY` is required by secrets/store.py's `DbSecretStore`
(used by Connector/AgentConfig routes); tests get a fixed value so every
test file doesn't need to set it individually.
"""

from __future__ import annotations

import io
import tarfile

import pytest
from cryptography.fernet import Fernet


@pytest.fixture(autouse=True)
def _kresheen_secret_key(monkeypatch):
    monkeypatch.setenv("KRESHEEN_SECRET_KEY", Fernet.generate_key().decode())


@pytest.fixture(autouse=True)
def _core_only(monkeypatch):
    """The core suite runs without any plugin, even where Pro is installed in the development environment."""
    from kresheen.plugins import PluginRegistry, set_registry

    set_registry(PluginRegistry())
    monkeypatch.setattr("kresheen.dashboard.app.load_plugins", lambda: PluginRegistry())
    monkeypatch.setattr("kresheen.cli.main.load_plugins", lambda: PluginRegistry())
    monkeypatch.setattr("kresheen.plugins.load_plugins", lambda: PluginRegistry())  # used by `kresheen db`


def build_tarball_bytes(files: dict[str, str], *, root_dir: str = "acme-widget-abc123") -> bytes:
    """Builds an in-memory gzipped tarball shaped like GitHub's tarball
    export (everything wrapped in one top-level `{owner}-{repo}-{sha}/`
    directory -- `GithubRepositoryIngestor._find_extracted_root` expects
    and strips exactly that shape). `files` maps a repo-relative path to
    its text content. Shared by `test_engine_ingest.py` and
    `test_api_applications.py` so both exercise the real tarball-pull path
    without hitting real GitHub.
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for rel_path, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"{root_dir}/{rel_path}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()
