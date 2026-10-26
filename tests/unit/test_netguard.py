"""Outbound URL guard."""

import pytest

from kresheen.netguard import OutboundBlocked, check_outbound_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:9100",
        "http://localhost:9100",
        "http://[::1]:9100",
        "http://2130706433:9100",
        "http://0x7f.1/",
        "http://017700000001/",
        "http://169.254.169.254/latest",
        "http://[::ffff:127.0.0.1]/",
        "http://10.0.0.5",
        "http://192.168.1.10",
        "http://172.16.0.1",
        "http://0.0.0.0",
        "http://[fe80::1]/",
        "file:///etc/passwd",
        "ftp://example.com",
        "gopher://x",
        "http://example.com@127.0.0.1:9100",
        "http://",
        "https://",
        "http://[::1",
        "http://127.0.0.1:99999",
    ],
)
def test_internal_and_odd_urls_are_refused(url):
    with pytest.raises(OutboundBlocked):
        check_outbound_url(url)


def test_public_literal_ip_and_https_are_allowed():
    assert check_outbound_url("https://93.184.216.34/rest") == "https://93.184.216.34/rest"


def test_unresolvable_name_passes_at_config_time_but_not_when_strict():
    assert check_outbound_url("https://no-such-host.invalid") == "https://no-such-host.invalid"
    with pytest.raises(OutboundBlocked):
        check_outbound_url("https://no-such-host.invalid", strict_dns=True)


def test_private_can_be_opted_in_but_metadata_never(monkeypatch):
    monkeypatch.setenv("KRESHEEN_OUTBOUND_ALLOW_PRIVATE", "1")
    assert check_outbound_url("http://10.0.0.5:8080") and check_outbound_url("http://127.0.0.1:9100")
    with pytest.raises(OutboundBlocked):
        check_outbound_url("http://169.254.169.254")
    with pytest.raises(OutboundBlocked):
        check_outbound_url("http://[::ffff:169.254.169.254]/")


def test_per_host_allowlist(monkeypatch):
    monkeypatch.setenv("KRESHEEN_OUTBOUND_ALLOW_HOSTS", "localhost")
    assert check_outbound_url("http://localhost:8080")
    with pytest.raises(OutboundBlocked):
        check_outbound_url("http://127.0.0.1:8080")


def test_ipv6_loopback_is_classified_as_loopback_so_the_allowlist_can_admit_it(monkeypatch):
    from kresheen.netguard import _classify

    assert _classify("::1") == "loopback" and _classify("127.0.0.1") == "loopback" and _classify("::") is not None
