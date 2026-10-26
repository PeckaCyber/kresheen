"""Triage: required reasons, bulk status and the reviewed stamp."""

from tests.integration.test_api_applications import _logged_in_client, _run_with_manifest


def _setup(tmp_path):
    client, csrf = _logged_in_client(tmp_path)
    application, run = _run_with_manifest(client, csrf)
    base = f"/api/applications/{application['id']}/runs/{run['id']}"
    return client, {"X-CSRF-Token": csrf}, application, run, base


def _threats(client, base):
    return client.get(f"{base}/threats").json()


def test_accepting_or_dismissing_a_threat_needs_a_reason(tmp_path):
    client, headers, _app, _run, base = _setup(tmp_path)
    key = _threats(client, base)["threats"][0]["key"]

    for status in ("accepted", "not_applicable"):
        assert (
            client.put(
                f"{base}/threats/status", headers=headers, json={"threat_key": key, "status": status}
            ).status_code
            == 422
        )
        assert (
            client.put(
                f"{base}/threats/status", headers=headers, json={"threat_key": key, "status": status, "note": "  "}
            ).status_code
            == 422
        )
    assert (
        client.put(
            f"{base}/threats/status",
            headers=headers,
            json={"threat_key": key, "status": "accepted", "note": "Reviewed by security"},
        ).status_code
        == 200
    )
    # Mitigated and open do not need one.
    assert (
        client.put(
            f"{base}/threats/status", headers=headers, json={"threat_key": key, "status": "mitigated"}
        ).status_code
        == 200
    )


def test_bulk_sets_status_on_many_threats_and_keeps_the_summary_consistent(tmp_path):
    client, headers, _app, _run, base = _setup(tmp_path)
    before = _threats(client, base)
    keys = [t["key"] for t in before["threats"][:5]]

    response = client.put(
        f"{base}/threats/status/bulk",
        headers=headers,
        json={"threat_keys": keys, "status": "mitigated", "note": "Fixed in PR 12"},
    )

    assert response.status_code == 200 and response.json() == {"updated": 5}
    after = _threats(client, base)
    changed = [t for t in after["threats"] if t["key"] in keys]
    assert all(t["status"] == "mitigated" and t["note"] == "Fixed in PR 12" for t in changed)
    assert after["summary"]["by_status"]["mitigated"] == 5
    assert after["summary"]["by_status"]["open"] == before["summary"]["total"] - 5


def test_bulk_needs_a_reason_for_accepted_and_rejects_unknown_keys_without_changing_anything(tmp_path):
    client, headers, _app, _run, base = _setup(tmp_path)
    keys = [t["key"] for t in _threats(client, base)["threats"][:3]]

    assert (
        client.put(
            f"{base}/threats/status/bulk", headers=headers, json={"threat_keys": keys, "status": "accepted"}
        ).status_code
        == 422
    )
    mixed = client.put(
        f"{base}/threats/status/bulk", headers=headers, json={"threat_keys": [*keys, "NOPE|x"], "status": "mitigated"}
    )
    assert mixed.status_code == 404
    assert _threats(client, base)["summary"]["by_status"]["mitigated"] == 0  # all or nothing
    assert (
        client.put(f"{base}/threats/status/bulk", json={"threat_keys": keys, "status": "mitigated"}).status_code == 403
    )
    assert (
        client.put(
            f"{base}/threats/status/bulk", headers=headers, json={"threat_keys": [], "status": "mitigated"}
        ).status_code
        == 422
    )


def test_bulk_keeps_existing_notes_and_dread_when_no_new_note_is_given(tmp_path):
    client, headers, _app, _run, base = _setup(tmp_path)
    key = _threats(client, base)["threats"][0]["key"]
    dread = {"damage": 5, "reproducibility": 5, "exploitability": 5, "affected_users": 5, "discoverability": 5}
    client.put(
        f"{base}/threats/status",
        headers=headers,
        json={"threat_key": key, "status": "open", "note": "look at this", "dread": dread},
    )

    client.put(f"{base}/threats/status/bulk", headers=headers, json={"threat_keys": [key], "status": "mitigated"})

    threat = next(t for t in _threats(client, base)["threats"] if t["key"] == key)
    assert threat["status"] == "mitigated" and threat["note"] == "look at this" and threat["dread"]["damage"] == 5


def test_bulk_back_to_open_clears_records_that_have_nothing_left_to_say(tmp_path):
    client, headers, _app, _run, base = _setup(tmp_path)
    keys = [t["key"] for t in _threats(client, base)["threats"][:2]]
    client.put(f"{base}/threats/status/bulk", headers=headers, json={"threat_keys": keys, "status": "mitigated"})

    client.put(f"{base}/threats/status/bulk", headers=headers, json={"threat_keys": keys, "status": "open"})

    assert _threats(client, base)["summary"]["by_status"]["open"] == _threats(client, base)["summary"]["total"]


def test_marking_a_model_reviewed_stamps_who_and_when_and_can_be_cleared(tmp_path):
    client, headers, application, _run, base = _setup(tmp_path)
    url = f"/api/applications/{application['id']}/review"

    reviewed = client.put(url, headers=headers, json={"reviewed": True}).json()
    assert reviewed["reviewed_at"] and reviewed["reviewed_by"]
    assert client.get(f"/api/applications/{application['id']}").json()["reviewed_by"] == reviewed["reviewed_by"]
    assert "Marked reviewed" in client.get(f"{base}/report.html").text

    cleared = client.put(url, headers=headers, json={"reviewed": False}).json()
    assert cleared["reviewed_at"] is None and cleared["reviewed_by"] == ""
    assert "Marked reviewed" not in client.get(f"{base}/report.html").text
    assert client.put(url, json={"reviewed": True}).status_code == 403
