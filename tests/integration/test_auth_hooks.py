"""Core with no plugin has no SSO, no SCIM and no directory sync; plugins reach sign-in and sign-out only through
`password_login_allowed` and `logout_redirect`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.plugins import AuthProvider, Plugin, PluginRegistry
from kresheen.storage.sql_repo import SQLRepository

_PW = "member-password-1"  # nosec: test fixture, not a real credential


def _app(tmp_path, *plugins: Plugin):
    url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(url)
    for uid, role in (("U-owner", "owner"), ("U-member", "member")):
        repo.save_user(
            User(
                id=uid, email=f"{uid}@x.test", password_hash=hash_password(_PW), role=role, created_at=datetime.now(UTC)
            )
        )
    return create_app(db_url=url, plugins=PluginRegistry(list(plugins)))


def _login(client: TestClient, uid: str):
    return client.post("/api/auth/login", json={"email": f"{uid}@x.test", "password": _PW})


class _Policy(Plugin):
    name = "policy"

    def __init__(self, answer):
        self.answer = answer
        self.asked: list[str] = []

    def password_login_allowed(self, user):
        self.asked.append(user.id)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def test_core_alone_has_no_sso_or_scim_surface(tmp_path):
    c = TestClient(_app(tmp_path))
    for path in ("/api/auth/oidc/login", "/api/auth/oidc/callback", "/api/auth/oidc/config"):
        assert c.get(path).status_code == 404, path
    # Outside /api the core knows nothing about SCIM: a GET gets the SPA shell when a frontend build exists, else a
    # 404. Either way no SCIM API answers.
    for path in ("/scim/v2/Users", "/scim/v2/ServiceProviderConfig"):
        response = c.get(path)
        assert response.status_code == 404 or response.headers["content-type"].startswith("text/html"), path
    assert c.post("/scim/v2/Users", json={"userName": "x@y.z"}).status_code in (404, 405)
    assert c.get("/api/capabilities").json()["auth_providers"] == []


def test_core_alone_allows_every_password_login_and_logout_has_no_redirect(tmp_path, monkeypatch):
    # Environment variables meant for a plugin do nothing in the core.
    monkeypatch.setenv("KRESHEEN_OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("KRESHEEN_OIDC_PASSWORD_LOGIN", "disabled")
    monkeypatch.setenv("KRESHEEN_SCIM_TOKEN", "t")
    c = TestClient(_app(tmp_path))
    csrf = _login(c, "U-member").json()["csrf_token"]
    assert c.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).json() == {"ok": True, "redirect": None}
    assert _login(c, "U-owner").status_code == 200


def test_a_plugin_can_refuse_a_password_login_only_after_the_password_is_verified(tmp_path):
    policy = _Policy(False)
    c = TestClient(_app(tmp_path, policy))
    assert (
        c.post("/api/auth/login", json={"email": "U-member@x.test", "password": "wrong-password-123"}).status_code
        == 401
    )
    assert policy.asked == []  # not consulted for a wrong password, so the 403 reveals nothing
    assert _login(c, "U-member").status_code == 403
    assert c.get("/api/auth/me").status_code == 401
    assert policy.asked == ["U-member"]


def test_any_refusal_wins_and_none_or_true_do_not_refuse(tmp_path):
    c = TestClient(_app(tmp_path, _Policy(None), _Policy(True), _Policy(False)))
    assert _login(c, "U-member").status_code == 403
    assert _login(TestClient(c.app), "U-owner").status_code == 403  # the owner exception is the plugin's to make
    other = tmp_path / "b"
    other.mkdir()
    ok = TestClient(_app(other, _Policy(None), _Policy(True)))
    assert _login(ok, "U-member").status_code == 200


def test_a_plugin_that_raises_refuses_members_but_never_locks_the_owner_out(tmp_path):
    c = TestClient(_app(tmp_path, _Policy(RuntimeError("bug"))))
    assert _login(c, "U-member").status_code == 403
    assert _login(c, "U-owner").status_code == 200


class _Redirect(Plugin):
    name = "redirect"

    def __init__(self, answer):
        self.answer = answer
        self.seen: list[tuple[bool, str | None]] = []

    def logout_redirect(self, session, user):
        self.seen.append((session.sso, user.id if user else None))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def test_logout_redirect_comes_from_the_plugin(tmp_path):
    plugin = _Redirect("https://idp.example.com/logout")
    c = TestClient(_app(tmp_path, plugin))
    csrf = _login(c, "U-member").json()["csrf_token"]
    out = c.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).json()
    assert out == {"ok": True, "redirect": "https://idp.example.com/logout"}
    assert plugin.seen == [(False, "U-member")]
    assert c.get("/api/auth/me").status_code == 401


@pytest.mark.parametrize("answer", [None, RuntimeError("bug")])
def test_no_answer_or_a_failing_plugin_still_signs_out_without_a_redirect(tmp_path, answer):
    c = TestClient(_app(tmp_path, _Redirect(answer)))
    csrf = _login(c, "U-member").json()["csrf_token"]
    assert c.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).json() == {"ok": True, "redirect": None}
    assert c.get("/api/auth/me").status_code == 401


class _Provider(Plugin):
    name = "provider"

    def auth_providers(self):
        return [AuthProvider(id="idp", label="Okta", login_url="/idp/login", password_login=False)]


def test_a_provider_can_say_that_passwords_are_tucked_away(tmp_path):
    (p,) = TestClient(_app(tmp_path, _Provider())).get("/api/capabilities").json()["auth_providers"]
    assert p == {"id": "idp", "label": "Okta", "login_url": "/idp/login", "password_login": False}
