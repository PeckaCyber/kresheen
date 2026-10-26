import time
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kresheen.dashboard import auth
from kresheen.dashboard.app import create_app
from kresheen.dashboard.audit import record_event
from kresheen.dashboard.auth import hash_password
from kresheen.models.user import User
from kresheen.storage.sql_repo import SQLRepository

EMAIL = "owner@example.com"
PASSWORD = "correct-password"  # nosec: test fixture


def _client(tmp_path):
    db_url = f"sqlite:///{tmp_path}/t.db"
    repo = SQLRepository(db_url)
    repo.save_user(
        User(
            id="USER-t", email=EMAIL, password_hash=hash_password(PASSWORD), role="owner", created_at=datetime.now(UTC)
        )
    )
    return TestClient(create_app(db_url=db_url)), repo


def test_repeated_failures_get_429_with_retry_after_and_other_accounts_are_unaffected(tmp_path, monkeypatch):
    monkeypatch.setenv("KRESHEEN_LOGIN_MAX_FAILURES_PER_ACCOUNT", "3")
    monkeypatch.setenv("KRESHEEN_LOGIN_MAX_FAILURES_PER_IP", "1000")
    client, _ = _client(tmp_path)
    codes = [client.post("/api/auth/login", json={"email": EMAIL, "password": "bad"}).status_code for _ in range(5)]
    assert codes == [401, 401, 401, 429, 429]
    blocked = client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert blocked.status_code == 429 and int(blocked.headers["Retry-After"]) > 0  # even the right password waits
    # a different account is not blocked by the first one's failures
    assert client.post("/api/auth/login", json={"email": "other@example.com", "password": "bad"}).status_code == 401


def test_unknown_email_is_throttled_like_a_known_one(tmp_path, monkeypatch):
    monkeypatch.setenv("KRESHEEN_LOGIN_MAX_FAILURES_PER_ACCOUNT", "2")
    client, _ = _client(tmp_path)
    codes = [
        client.post("/api/auth/login", json={"email": "ghost@x.test", "password": "x"}).status_code for _ in range(3)
    ]
    assert codes == [401, 401, 429]


def test_successful_login_resets_the_counter(tmp_path, monkeypatch):
    monkeypatch.setenv("KRESHEEN_LOGIN_MAX_FAILURES_PER_ACCOUNT", "3")
    client, _ = _client(tmp_path)
    for _ in range(2):
        client.post("/api/auth/login", json={"email": EMAIL, "password": "bad"})
    assert client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD}).status_code == 200
    for _ in range(2):
        assert client.post("/api/auth/login", json={"email": EMAIL, "password": "bad"}).status_code == 401


def test_unknown_account_still_does_a_full_hash_check(tmp_path, monkeypatch):
    client, _ = _client(tmp_path)
    calls = []
    real = auth._hasher

    class Spy:
        def hash(self, p):
            return real.hash(p)

        def verify(self, h, p):
            calls.append(1)
            return real.verify(h, p)

    monkeypatch.setattr(auth, "_hasher", Spy())
    monkeypatch.setattr(auth, "_dummy_hash", None)
    client.post("/api/auth/login", json={"email": "ghost@x.test", "password": "x"})
    assert calls, "no password hash was verified for an unknown account, so timing reveals it does not exist"


def test_concurrent_hashing_is_bounded(monkeypatch):
    import threading as th

    monkeypatch.setattr(auth, "_hash_slots", th.BoundedSemaphore(2))
    live = {"now": 0, "max": 0}
    lock = th.Lock()

    def slow_verify(_h, _p):
        with lock:
            live["now"] += 1
            live["max"] = max(live["max"], live["now"])
        time.sleep(0.05)
        with lock:
            live["now"] -= 1
        return True

    class Slow:
        verify = staticmethod(slow_verify)

    monkeypatch.setattr(auth, "_hasher", Slow())
    threads = [th.Thread(target=auth.verify_password, args=("p", "h")) for _ in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert live["max"] <= 2


def test_busy_hasher_answers_503_not_a_hang(monkeypatch):
    import threading as th

    import pytest
    from fastapi import HTTPException

    monkeypatch.setattr(auth, "_hash_slots", th.BoundedSemaphore(1))
    monkeypatch.setattr(auth, "_HASH_WAIT_SECONDS", 0.05)
    auth._hash_slots.acquire()
    with pytest.raises(HTTPException) as exc:
        auth.verify_password("p", "h")
    assert exc.value.status_code == 503 and exc.value.headers["Retry-After"]


def test_failed_login_flood_cannot_evict_other_audit_history(tmp_path, monkeypatch):
    monkeypatch.setattr("kresheen.dashboard.audit.DEFAULT_MAX_ENTRIES", 100)
    monkeypatch.setattr("kresheen.dashboard.audit.DEFAULT_MAX_FAILED_LOGINS", 20)
    _, repo = _client(tmp_path)
    for i in range(10):
        record_event(
            repo, action="POST /api/groups", user_id="USER-t", user_email=EMAIL, subject={"n": str(i)}, status_code=200
        )
    for i in range(500):
        record_event(repo, action="auth.login_failed", user_email=f"x{i}@x.test", status_code=401)
    events = repo.list_audit_events(limit=500)
    actions = [e.action for e in events]
    assert actions.count("POST /api/groups") == 10, "real history was evicted by failed logins"
    assert actions.count("auth.login_failed") == 20


def test_a_burst_of_logins_turns_excess_requests_away_at_once(monkeypatch):
    import threading as th

    monkeypatch.setattr(auth, "_hash_slots", th.BoundedSemaphore(1))
    monkeypatch.setattr(auth, "_hash_waiting", 0)
    monkeypatch.setenv("KRESHEEN_MAX_QUEUED_HASHES", "2")
    release = th.Event()

    class Held:
        @staticmethod
        def verify(_h, _p):
            release.wait(5)
            return True

    monkeypatch.setattr(auth, "_hasher", Held())
    outcomes = []

    def attempt():
        try:
            auth.verify_password("p", "h")
            outcomes.append("ok")
        except Exception as exc:  # noqa: BLE001
            outcomes.append(getattr(exc, "status_code", "error"))

    threads = [th.Thread(target=attempt) for _ in range(10)]
    started = time.time()
    [t.start() for t in threads]
    time.sleep(0.5)
    rejected_quickly = outcomes.count(503)
    release.set()
    [t.join() for t in threads]
    assert rejected_quickly == 7, outcomes  # 1 running + 2 waiting accepted, the other 7 refused immediately
    assert outcomes.count("ok") == 3
    assert time.time() - started < 5


def test_repeated_failures_from_one_address_get_a_short_delay_not_a_lockout(tmp_path, monkeypatch):
    monkeypatch.setenv("KRESHEEN_LOGIN_FREE_FAILURES", "2")
    monkeypatch.setenv("KRESHEEN_LOGIN_MAX_FAILURES_PER_ACCOUNT", "100")
    client, _ = _client(tmp_path)
    codes = [client.post("/api/auth/login", json={"email": EMAIL, "password": "bad"}).status_code for _ in range(3)]
    assert codes == [401, 401, 401]
    delayed = client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert delayed.status_code == 429 and 1 <= int(delayed.headers["Retry-After"]) <= 3
    # another account from the same address is not delayed
    assert client.post("/api/auth/login", json={"email": "other@example.com", "password": "bad"}).status_code == 401
