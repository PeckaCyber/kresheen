from kresheen.engine.threats import cache as cache_mod
from kresheen.engine.threats.cache import VersionedCache


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def test_hit_until_app_invalidated():
    c = VersionedCache()
    key = ("A", "R1", False)
    c.put(key, "v1", c.stamp("A"), 1)
    assert c.get(key, "A") == "v1"
    c.invalidate_app("A")
    assert c.get(key, "A") is None


def test_other_apps_survive_an_app_invalidation_but_not_a_global_one():
    c = VersionedCache()
    c.put(("A", "R1", False), "a", c.stamp("A"), 1)
    c.put(("B", "R2", False), "b", c.stamp("B"), 1)
    c.invalidate_app("A")
    assert c.get(("B", "R2", False), "B") == "b"
    c.invalidate_all()
    assert c.get(("B", "R2", False), "B") is None


def test_result_computed_during_a_write_is_never_served():
    c = VersionedCache()
    stamp = c.stamp("A")  # read before computing
    c.invalidate_app("A")  # a write lands while the value is being computed
    c.put(("A", "R1", False), "stale", stamp, 1)
    assert c.get(("A", "R1", False), "A") is None


def test_ttl_expiry_and_disable(monkeypatch):
    clock = Clock()
    c = VersionedCache(clock=clock)
    monkeypatch.setenv("KRESHEEN_THREATS_CACHE_TTL", "10")
    c.put(("A", "R", False), "v", c.stamp("A"), 1)
    clock.t = 9
    assert c.get(("A", "R", False), "A") == "v"
    clock.t = 11
    assert c.get(("A", "R", False), "A") is None
    monkeypatch.setenv("KRESHEEN_THREATS_CACHE_TTL", "0")
    c.put(("A", "R", False), "v", c.stamp("A"), 1)
    assert c.get(("A", "R", False), "A") is None


def test_memory_is_bounded_by_entries_and_weight(monkeypatch):
    monkeypatch.setattr(cache_mod, "_MAX_ENTRIES", 3)
    c = VersionedCache()
    for i in range(10):
        c.put(("A", f"R{i}", False), i, c.stamp("A"), 1)
    assert len(c._entries) == 3 and c.get(("A", "R9", False), "A") == 9
    monkeypatch.setattr(cache_mod, "_MAX_ENTRIES", 100)
    monkeypatch.setattr(cache_mod, "_MAX_TOTAL_WEIGHT", 10)
    c2 = VersionedCache()
    for i in range(5):
        c2.put(("A", f"R{i}", False), i, c2.stamp("A"), 4)
    assert c2._weight <= 10
