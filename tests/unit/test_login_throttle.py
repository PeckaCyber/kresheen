from kresheen.dashboard.login_throttle import LoginThrottle


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_blocks_after_account_limit_and_recovers_after_window():
    clock = Clock()
    t = LoginThrottle(max_per_account=3, max_per_ip=100, window_seconds=60, clock=clock)
    for _ in range(3):
        assert t.retry_after("a@x.test", "1.1.1.1") is None
        t.record_failure("a@x.test", "1.1.1.1")
    wait = t.retry_after("a@x.test", "2.2.2.2")  # a different address does not help
    assert wait is not None and 0 < wait <= 61
    clock.t += 61
    assert t.retry_after("a@x.test", "1.1.1.1") is None


def test_account_key_is_case_and_whitespace_insensitive():
    t = LoginThrottle(max_per_account=2, max_per_ip=100, window_seconds=60, clock=Clock())
    t.record_failure("A@X.test", None)
    t.record_failure(" a@x.test ", None)
    assert t.retry_after("a@x.TEST", None) is not None


def test_pair_delay_is_progressive_capped_and_per_account():
    clock = Clock()
    t = LoginThrottle(max_per_account=100, max_per_ip=1000, window_seconds=900, free_failures=2,
                      delay_base=1, delay_max=8, clock=clock)
    ip, acct = "1.1.1.1", "a@x.test"
    waits = []
    for _ in range(7):
        t.record_failure(acct, ip)
        w = t.retry_after(acct, ip)
        waits.append(w)
        if w is not None:
            clock.t += w  # wait it out, then fail again
    assert waits[1] is None  # two free failures
    seen = [w for w in waits if w is not None]
    assert seen == sorted(seen) and seen[0] == 2 and seen[-1] == 9  # 1s, 2s, 4s, 8s cap (+1 rounding)
    assert t.retry_after("other@x.test", ip) is None  # same address, different account: no pair delay
    assert t.retry_after(acct, "2.2.2.2") is None  # same account, different address: no pair delay


def test_delay_expires_by_itself():
    clock = Clock()
    t = LoginThrottle(max_per_account=100, max_per_ip=1000, window_seconds=900, free_failures=1, clock=clock)
    t.record_failure("a@x.test", "1.1.1.1")
    t.record_failure("a@x.test", "1.1.1.1")
    assert t.retry_after("a@x.test", "1.1.1.1") is not None
    clock.t += 3
    assert t.retry_after("a@x.test", "1.1.1.1") is None


def test_ip_spray_across_accounts_is_slowed_but_never_locked_out():
    clock = Clock()
    t = LoginThrottle(max_per_account=100, max_per_ip=5, window_seconds=900, ip_delay_max=30, clock=clock)
    for i in range(200):
        t.record_failure(f"user{i}@x.test", "9.9.9.9")
    wait = t.retry_after("brand-new@x.test", "9.9.9.9")
    assert wait is not None and wait <= 31  # capped: a user behind the same proxy waits seconds, not minutes
    assert t.retry_after("brand-new@x.test", "8.8.8.8") is None
    clock.t += 31
    assert t.retry_after("brand-new@x.test", "9.9.9.9") is None


def test_account_lockout_still_applies_from_any_address():
    t = LoginThrottle(max_per_account=3, max_per_ip=1000, window_seconds=60, free_failures=100, clock=Clock())
    for i in range(3):
        t.record_failure("a@x.test", f"10.0.0.{i}")
    assert t.retry_after("a@x.test", "10.0.0.99") is not None


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("KRESHEEN_LOGIN_FREE_FAILURES", "7")
    monkeypatch.setenv("KRESHEEN_LOGIN_DELAY_BASE_SECONDS", "2")
    monkeypatch.setenv("KRESHEEN_LOGIN_DELAY_MAX_SECONDS", "60")
    monkeypatch.setenv("KRESHEEN_LOGIN_IP_DELAY_MAX_SECONDS", "9")
    t = LoginThrottle()
    assert (t.free_failures, t.delay_base, t.delay_max, t.ip_delay_max) == (7, 2, 60, 9)


def test_success_clears_the_account_and_pair_counters():
    t = LoginThrottle(max_per_account=2, max_per_ip=100, window_seconds=60, free_failures=1, clock=Clock())
    t.record_failure("a@x.test", "1.1.1.1")
    t.record_failure("a@x.test", "1.1.1.1")
    t.record_success("a@x.test", "1.1.1.1")
    assert t.retry_after("a@x.test", "1.1.1.1") is None
    t.record_failure("a@x.test", None)
    t.record_success("a@x.test")
    t.record_failure("a@x.test", None)
    assert t.retry_after("a@x.test", None) is None


def test_unknown_and_known_accounts_are_treated_identically():
    t = LoginThrottle(max_per_account=2, max_per_ip=100, window_seconds=60, clock=Clock())
    for email in ("real@x.test", "ghost@x.test"):
        t.record_failure(email, None)
        t.record_failure(email, None)
        assert t.retry_after(email, None) is not None


def test_memory_is_bounded_under_a_spray_of_distinct_emails(monkeypatch):
    import kresheen.dashboard.login_throttle as mod

    monkeypatch.setattr(mod, "_MAX_TRACKED_KEYS", 50)
    t = LoginThrottle(max_per_account=5, max_per_ip=1000, window_seconds=600, clock=Clock())
    for i in range(500):
        t.record_failure(f"u{i}@x.test", "1.1.1.1")
    assert len(t._failures) <= 60
