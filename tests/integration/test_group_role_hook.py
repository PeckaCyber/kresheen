"""Group access in the core: a shared workspace unless a plugin's `group_role` hook narrows it. Owners and a group's
creator are decided before the plugin; a plugin that fails denies access (fail closed)."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from kresheen.dashboard.app import create_app
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.plugins import GroupRole, Plugin, PluginRegistry
from kresheen.storage.sql_repo import SQLRepository

_PW = "member-password-1"  # nosec: test fixture, not a real credential


class _Roles(Plugin):
    """Answers `decision(user_id)` for every group."""

    name = "roles"

    def __init__(self, decision):
        self.decision = decision

    def group_role(self, user, group, repo):
        return self.decision(user.id)


def _app(tmp_path, *plugins: Plugin):
    url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(url)
    for uid, role in (("U-owner", "owner"), ("U-creator", "member"), ("U-member", "member")):
        repo.save_user(
            User(
                id=uid, email=f"{uid}@x.test", password_hash=hash_password(_PW), role=role, created_at=datetime.now(UTC)
            )
        )
    return create_app(db_url=url, plugins=PluginRegistry(list(plugins)))


def _sign_in(app, uid: str) -> TestClient:
    c = TestClient(app)
    c.headers["X-CSRF-Token"] = c.post("/api/auth/login", json={"email": f"{uid}@x.test", "password": _PW}).json()[
        "csrf_token"
    ]
    return c


def _group_and_app(creator: TestClient) -> tuple[str, str]:
    group = creator.post("/api/groups", json={"name": "Payments"}).json()["id"]
    application = creator.post("/api/applications", json={"name": "Ledger", "group_id": group}).json()["id"]
    return group, application


def test_core_alone_gives_every_signed_in_user_editor_on_every_group(tmp_path):
    app = _app(tmp_path)
    group, application = _group_and_app(_sign_in(app, "U-creator"))
    member = _sign_in(app, "U-member")
    assert member.get(f"/api/groups/{group}").json()["my_role"] == "editor"
    assert group in [g["id"] for g in member.get("/api/groups").json()["groups"]]
    assert member.get(f"/api/applications/{application}").status_code == 200
    assert member.post(f"/api/applications/{application}/runs", json={}).status_code == 200
    assert (
        member.put(f"/api/groups/{group}", json={"name": "Renamed"}).status_code == 403
    )  # editors do not manage groups
    assert _sign_in(app, "U-owner").get(f"/api/groups/{group}").json()["my_role"] == "admin"
    assert _sign_in(app, "U-creator").get(f"/api/groups/{group}").json()["my_role"] == "admin"


def test_core_alone_has_no_group_access_routes_and_no_restricted_flag(tmp_path):
    app = _app(tmp_path)
    owner = _sign_in(app, "U-owner")
    group, _ = _group_and_app(owner)
    assert owner.get(f"/api/groups/{group}/access").status_code == 404
    assert owner.put(f"/api/groups/{group}/access", json={"restricted": True, "members": []}).status_code == 404
    assert "restricted" not in owner.get(f"/api/groups/{group}").json()
    assert "restricted" not in owner.get("/api/groups").json()["groups"][0]


def test_a_stored_group_with_the_old_restricted_flag_still_loads(tmp_path):
    app = _app(tmp_path)
    owner = _sign_in(app, "U-owner")
    group, _ = _group_and_app(owner)
    db = sqlite3.connect(f"{tmp_path}/t.db")
    (blob,) = db.execute("select data from application_groups where id = ?", (group,)).fetchone()
    data = json.loads(blob) if isinstance(blob, str) else blob
    data["restricted"] = True
    db.execute("update application_groups set data = ? where id = ?", (json.dumps(data), group))
    db.commit()
    assert _sign_in(app, "U-member").get(f"/api/groups/{group}").status_code == 200


def test_a_plugin_decision_sets_the_role_or_hides_the_group(tmp_path):
    decisions = {"U-member": GroupRole("viewer")}
    app = _app(tmp_path, _Roles(lambda uid: decisions.get(uid)))
    creator = _sign_in(app, "U-creator")
    group, application = _group_and_app(creator)
    member = _sign_in(app, "U-member")
    assert member.get(f"/api/groups/{group}").json()["my_role"] == "viewer"
    assert member.post(f"/api/applications/{application}/runs", json={}).status_code == 403
    decisions["U-member"] = GroupRole(None)
    assert member.get(f"/api/groups/{group}").status_code == 404
    assert member.get(f"/api/applications/{application}").status_code == 404
    assert group not in [g["id"] for g in member.get("/api/groups").json()["groups"]]
    assert member.get("/api/applications").json() == []
    assert member.get("/api/dashboard").json()["applications"] == []


def test_owner_and_creator_keep_admin_even_when_the_plugin_denies_everyone(tmp_path):
    app = _app(tmp_path, _Roles(lambda uid: GroupRole(None)))
    creator = _sign_in(app, "U-creator")
    group, application = _group_and_app(creator)
    assert creator.get(f"/api/groups/{group}").json()["my_role"] == "admin"
    assert _sign_in(app, "U-owner").get(f"/api/groups/{group}").json()["my_role"] == "admin"
    assert _sign_in(app, "U-owner").get(f"/api/applications/{application}").status_code == 200
    assert _sign_in(app, "U-member").get(f"/api/groups/{group}").status_code == 404
    # Ungrouped is the shared bucket: a plugin is never asked about it.
    ungrouped = creator.post("/api/applications", json={"name": "Loose"}).json()["id"]
    assert _sign_in(app, "U-member").get(f"/api/applications/{ungrouped}").status_code == 200


def _raise(_uid):
    raise RuntimeError("plugin bug")


@pytest.mark.parametrize("decision", [_raise, lambda uid: "admin", lambda uid: GroupRole("root")])
def test_a_failing_or_malformed_plugin_fails_closed(tmp_path, decision, caplog):
    app = _app(tmp_path, _Roles(decision))
    creator = _sign_in(app, "U-creator")
    group, application = _group_and_app(creator)
    member = _sign_in(app, "U-member")
    assert member.get(f"/api/groups/{group}").status_code == 404
    assert member.get(f"/api/applications/{application}").status_code == 404
    assert member.post(f"/api/applications/{application}/runs", json={}).status_code == 404
    assert group not in [g["id"] for g in member.get("/api/groups").json()["groups"]]
    assert "denying access" in caplog.text
    # The owner and the creator are decided before the plugin, so a broken plugin cannot lock them out.
    assert _sign_in(app, "U-owner").get(f"/api/applications/{application}").status_code == 200
    assert creator.get(f"/api/applications/{application}").status_code == 200


def test_the_first_plugin_with_an_opinion_wins(tmp_path):
    app = _app(
        tmp_path, _Roles(lambda uid: None), _Roles(lambda uid: GroupRole("viewer")), _Roles(lambda uid: GroupRole(None))
    )
    group, _ = _group_and_app(_sign_in(app, "U-creator"))
    assert _sign_in(app, "U-member").get(f"/api/groups/{group}").json()["my_role"] == "viewer"
