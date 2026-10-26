"""Security report DNS rebinding row: guarded_request resolves once and connects to the validated address."""

import http.server
import socket
import threading
from typing import ClassVar

import pytest
import requests

from kresheen import netguard
from kresheen.netguard import OutboundBlocked, guarded_request

PUBLIC = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


def _answers(monkeypatch, *addresses):
    """Resolver stub: each lookup returns the next entry (the last one repeats); returns the lookup log."""
    calls: list[str] = []
    real = socket.getaddrinfo

    def fake(host, port, *a, **k):
        if host in ("127.0.0.1", PUBLIC, PUBLIC_V6):  # literals (urllib3's own connect) are not lookups of ours
            return real(host, port, *a, **k)
        calls.append(host)
        address = addresses[min(len(calls), len(addresses)) - 1]
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (address, port))]

    monkeypatch.setattr("kresheen.netguard.socket.getaddrinfo", fake)
    return calls


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("KRESHEEN_OUTBOUND_ALLOW_HOSTS", raising=False)
    monkeypatch.delenv("KRESHEEN_OUTBOUND_ALLOW_PRIVATE", raising=False)


@pytest.fixture
def connects(monkeypatch):
    """Records every TCP connect urllib3 attempts and refuses it, so nothing leaves the machine."""
    seen: list[tuple[str, int]] = []

    def fake_create_connection(address, *a, **k):
        seen.append(address)
        raise OSError("blocked by test")

    monkeypatch.setattr("urllib3.util.connection.create_connection", fake_create_connection)
    return seen


def test_rebinding_answer_is_never_connected_to(monkeypatch, connects):
    calls = _answers(monkeypatch, PUBLIC, "169.254.169.254")
    with pytest.raises(requests.ConnectionError):
        guarded_request("GET", "http://rebind.example.com/x", timeout=2)
    assert calls == ["rebind.example.com"]  # resolved exactly once
    assert connects == [(PUBLIC, 80)]  # the validated address, never the second answer


def test_private_answer_is_refused_before_any_connect(monkeypatch, connects):
    _answers(monkeypatch, "169.254.169.254")
    with pytest.raises(OutboundBlocked):
        guarded_request("GET", "http://meta.example.com/", timeout=2)
    assert connects == []


def test_one_private_record_among_public_ones_is_refused(monkeypatch, connects):
    monkeypatch.setattr(
        "kresheen.netguard.socket.getaddrinfo",
        lambda host, port, *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port)),
        ],
    )
    with pytest.raises(OutboundBlocked):
        guarded_request("GET", "http://mixed.example.com/", timeout=2)
    assert connects == []


def test_unresolvable_host_is_refused(monkeypatch, connects):
    def fail(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr("kresheen.netguard.socket.getaddrinfo", fail)
    with pytest.raises(OutboundBlocked):
        guarded_request("GET", "http://nothing.example.com/", timeout=2)


def test_ipv6_address_is_pinned(monkeypatch, connects):
    _answers(monkeypatch, PUBLIC_V6)
    with pytest.raises(requests.ConnectionError):
        guarded_request("GET", "http://v6.example.com:8080/", timeout=2)
    assert connects == [(PUBLIC_V6, 8080)]


def test_tls_uses_the_original_host_name(monkeypatch, connects):
    """SNI and certificate verification get the URL's host, the TCP connect gets the pinned address."""
    _answers(monkeypatch, PUBLIC)
    handshakes: list[dict] = []

    class Stop(Exception):
        pass

    def fake_create_connection(address, *a, **k):
        connects.append(address)
        return socket.socket()

    def fake_wrap(*args, **kwargs):
        handshakes.append(kwargs)
        raise Stop

    monkeypatch.setattr("urllib3.util.connection.create_connection", fake_create_connection)
    monkeypatch.setattr("urllib3.connection._ssl_wrap_socket_and_match_hostname", fake_wrap)
    with pytest.raises(Exception):  # noqa: B017 - urllib3 wraps Stop in a requests error
        guarded_request("GET", "https://api.idp.example.com/token", timeout=2)
    assert connects == [(PUBLIC, 443)]
    assert handshakes[0]["server_hostname"] == "api.idp.example.com"
    assert handshakes[0]["assert_hostname"] is None  # verified against server_hostname, never the IP


class _Handler(http.server.BaseHTTPRequestHandler):
    seen_host: ClassVar[list[str]] = []

    def do_GET(self):
        _Handler.seen_host.append(self.headers["Host"])
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest")
            self.end_headers()
            return
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def local_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Handler.seen_host = []
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def test_connects_to_pinned_address_and_keeps_host_header(monkeypatch, local_server):
    monkeypatch.setenv("KRESHEEN_OUTBOUND_ALLOW_PRIVATE", "1")
    calls = _answers(monkeypatch, "127.0.0.1", "169.254.169.254")
    response = guarded_request("GET", f"http://internal.example.com:{local_server}/", timeout=5)
    assert response.status_code == 200 and response.text == "ok"
    assert _Handler.seen_host == [f"internal.example.com:{local_server}"]
    assert len(calls) == 1


def test_redirects_are_not_followed(monkeypatch, local_server):
    monkeypatch.setenv("KRESHEEN_OUTBOUND_ALLOW_PRIVATE", "1")
    _answers(monkeypatch, "127.0.0.1")
    response = guarded_request("GET", f"http://internal.example.com:{local_server}/redirect", timeout=5)
    assert response.status_code == 302
    assert len(_Handler.seen_host) == 1


def test_allow_hosts_still_permits_a_private_host(monkeypatch, local_server):
    monkeypatch.setenv("KRESHEEN_OUTBOUND_ALLOW_HOSTS", "jira.corp.example")
    _answers(monkeypatch, "127.0.0.1")
    assert guarded_request("GET", f"http://jira.corp.example:{local_server}/", timeout=5).status_code == 200
    with pytest.raises(OutboundBlocked):
        guarded_request("GET", f"http://other.corp.example:{local_server}/", timeout=5)


def test_environment_proxy_is_ignored(monkeypatch, local_server):
    monkeypatch.setenv("KRESHEEN_OUTBOUND_ALLOW_PRIVATE", "1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")  # nothing listens here; honouring it would fail
    monkeypatch.setenv("NO_PROXY", "")
    _answers(monkeypatch, "127.0.0.1")
    assert guarded_request("GET", f"http://internal.example.com:{local_server}/", timeout=5).status_code == 200


def test_redirect_and_proxy_arguments_are_rejected():
    with pytest.raises(TypeError):
        guarded_request("GET", "http://x.example.com/", timeout=1, allow_redirects=True)
    with pytest.raises(TypeError):
        guarded_request("GET", "http://x.example.com/", timeout=1, proxies={})


def test_pin_hook_still_exists_in_urllib3():
    # The pin swaps urllib3's private `_dns_host`; if an upgrade drops it, fail loudly here.
    conn = netguard.HTTPConnection("example.com")
    assert conn._dns_host == "example.com"
