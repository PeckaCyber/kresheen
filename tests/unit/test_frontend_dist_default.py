"""The server finds the web build next to a checkout first, then inside the installed package."""

from __future__ import annotations

from kresheen.dashboard import app as app_module


def test_repo_build_wins_when_present(tmp_path, monkeypatch):
    repo_dist, packaged = tmp_path / "repo-dist", tmp_path / "packaged"
    repo_dist.mkdir()
    packaged.mkdir()
    monkeypatch.setattr(app_module, "_DEFAULT_FRONTEND_DIST", repo_dist)
    monkeypatch.setattr(app_module, "_PACKAGED_FRONTEND_DIST", packaged)
    assert app_module._default_frontend_dist() == repo_dist


def test_packaged_build_is_used_without_a_checkout(tmp_path, monkeypatch):
    packaged = tmp_path / "packaged"
    packaged.mkdir()
    monkeypatch.setattr(app_module, "_DEFAULT_FRONTEND_DIST", tmp_path / "missing")
    monkeypatch.setattr(app_module, "_PACKAGED_FRONTEND_DIST", packaged)
    assert app_module._default_frontend_dist() == packaged
