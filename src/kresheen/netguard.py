"""Outbound URL guard: one check for every URL a user or admin can configure.

Allows http/https only, refuses userinfo (`http://good@evil/`), resolves the host, and refuses loopback, private,
link-local (cloud metadata, 169.254.169.254), multicast, unspecified and reserved addresses, including IPv4-mapped
IPv6 and decimal/octal spellings (the resolver normalises them, so the check sees the real address).

Self-hosted Jira on a private address is a legitimate setup, so private and loopback targets can be opted in with
`KRESHEEN_OUTBOUND_ALLOW_PRIVATE=1` or per host with `KRESHEEN_OUTBOUND_ALLOW_HOSTS=jira.corp.example,...`.
Link-local and metadata addresses stay blocked even then.

`check_outbound_url` alone only checks; it cannot stop DNS rebinding, because the HTTP client resolves the host again
when it connects. Requests therefore go through `guarded_request`, which resolves the host once, validates every
address it got, and connects to one of those exact addresses. TLS still uses the original host name (SNI, certificate
verification), and the `Host` header is unchanged. Redirects are never followed and environment proxies are ignored.
A network egress policy (the Helm NetworkPolicy) remains a second line of defence.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool


class OutboundBlocked(ValueError):
    """The URL is not allowed as an outbound target."""


def _allowed_hosts() -> set[str]:
    return {h.strip().lower() for h in os.environ.get("KRESHEEN_OUTBOUND_ALLOW_HOSTS", "").split(",") if h.strip()}


def _allow_private() -> bool:
    return os.environ.get("KRESHEEN_OUTBOUND_ALLOW_PRIVATE", "").strip().lower() in ("1", "true", "yes")


def _classify(address: str) -> str | None:
    """Returns why an address is refused, or None if it is a public unicast address."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_link_local:
        return "link-local/metadata"
    if ip.is_multicast or ip.is_unspecified:
        return "multicast/unspecified/reserved"
    if ip.is_loopback:  # before is_reserved: ::1 sits inside the reserved ::/8 block on some Python versions
        return "loopback"
    if ip.is_reserved:
        return "multicast/unspecified/reserved"
    if ip.is_private or not ip.is_global:
        return "private/internal"
    return None


def _resolve(url: str, what: str, strict_dns: bool) -> list[str]:
    """Validates the URL and every address its host resolves to. Returns the addresses in resolver order.

    With `strict_dns=False` a name that does not resolve returns an empty list."""
    try:
        parts = urlsplit(url.strip())
    except ValueError as exc:
        raise OutboundBlocked(f"{what} is not a valid URL") from exc
    if parts.scheme not in ("http", "https"):
        raise OutboundBlocked(f"{what} must start with http:// or https://")
    if "@" in parts.netloc:
        raise OutboundBlocked(f"{what} must not contain credentials")
    host = (parts.hostname or "").lower()
    if not host:
        raise OutboundBlocked(f"{what} has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise OutboundBlocked(f"{what} has an invalid port") from exc
    try:
        infos = socket.getaddrinfo(host, port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        if strict_dns:
            raise OutboundBlocked(f"{what} host does not resolve") from exc
        return []
    addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
    permitted = _allow_private() or host in _allowed_hosts()
    for address in addresses:
        reason = _classify(address)
        if reason is None:
            continue
        if permitted and reason in ("loopback", "private/internal"):
            continue
        raise OutboundBlocked(f"{what} points at a {reason} address and is refused")
    return addresses


def check_outbound_url(url: str, *, what: str = "URL", strict_dns: bool = False) -> str:
    """Returns the URL unchanged if allowed, otherwise raises OutboundBlocked.

    `strict_dns=False` lets a name that does not resolve yet pass (config time); the request itself will then fail.
    This is a check only. To make a request use `guarded_request`, which also pins the connection."""
    _resolve(url, what, strict_dns)
    return url


# Connection pinning. urllib3 connects to `self._dns_host` and uses `self.host` for SNI, certificate verification and
# the Host header; in urllib3 2.x both read the same attribute, so for the duration of the TCP connect we swap in the
# validated address and restore the name straight after. The TLS handshake runs after the restore, against the name.
def _pinned(base: type, address: str) -> type:
    class Pinned(base):  # type: ignore[misc, valid-type]
        def _new_conn(self) -> Any:
            name = self._dns_host  # type: ignore[has-type]
            self._dns_host = address
            try:
                return super()._new_conn()
            finally:
                self._dns_host = name

    return Pinned


class _PinnedAdapter(HTTPAdapter):
    def __init__(self, address: str) -> None:
        self._address = address
        super().__init__(max_retries=0)

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        super().init_poolmanager(*args, **kwargs)
        http_pool = type("PinnedHTTPPool", (HTTPConnectionPool,), {"ConnectionCls": _pinned(HTTPConnection, self._address)})
        https_pool = type("PinnedHTTPSPool", (HTTPSConnectionPool,), {"ConnectionCls": _pinned(HTTPSConnection, self._address)})
        self.poolmanager.pool_classes_by_scheme = {"http": http_pool, "https": https_pool}


def guarded_request(method: str, url: str, *, what: str = "URL", timeout: float, **kwargs: Any) -> requests.Response:
    """The one way to make an HTTP request to a configurable URL.

    Runs the `check_outbound_url` rules with the host resolved now (an unresolvable host is refused), requires every
    returned address to pass (so a name with one public and one private record is refused), then connects to the first
    address, never resolving again. Redirects are not followed (a 3xx response is returned as is). Environment
    proxies and `.netrc` are ignored (`trust_env=False`), because a proxy would resolve the name itself and defeat the
    pin; `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` are still honoured for TLS verification. Only the first address is
    tried, so there is no fallback to a second record.
    Raises OutboundBlocked if refused; network errors surface as requests.RequestException."""
    if "allow_redirects" in kwargs or "proxies" in kwargs:
        raise TypeError("guarded_request does not take allow_redirects or proxies")
    addresses = _resolve(url, what, strict_dns=True)
    session = requests.Session()
    session.trust_env = False
    if "verify" not in kwargs:
        session.verify = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE") or True
    adapter = _PinnedAdapter(addresses[0].split("%", 1)[0])
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    try:
        return session.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)
    finally:
        if not kwargs.get("stream"):  # a streamed body still needs its pool
            session.close()
