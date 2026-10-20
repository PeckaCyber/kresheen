"""Response security headers for the SPA and the JSON API.

Pure ASGI so it adds headers to every response, including static assets and errors. Headers a route already set
(the report and SVG downloads send their own stricter CSP) are left alone. HSTS is sent only when the request
arrived over TLS as the app sees it, which needs `KRESHEEN_FORWARDED_ALLOW_IPS` behind a TLS-terminating proxy.
`KRESHEEN_HSTS_MAX_AGE` (seconds, default one year, 0 = off) tunes it.

The CSP allows only same-origin scripts; `style-src` keeps 'unsafe-inline' because React Flow and the charts set
inline `style` attributes, and `img-src` allows data:/blob: for the diagram PNG capture.
"""

from __future__ import annotations

import os

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
    "font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)
_STATIC = {
    b"content-security-policy": CSP.encode(),
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"referrer-policy": b"no-referrer",
    b"permissions-policy": b"camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    b"cross-origin-opener-policy": b"same-origin",
    b"cross-origin-resource-policy": b"same-origin",
}


def hsts_max_age() -> int:
    try:
        return max(0, int(os.environ.get("KRESHEEN_HSTS_MAX_AGE", "31536000")))
    except ValueError:
        return 31536000


class SecurityHeadersMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        secure_request = scope.get("scheme") == "https"

        async def send_with_headers(message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                for name, value in _STATIC.items():
                    if name not in present:
                        headers.append((name, value))
                max_age = hsts_max_age()
                if secure_request and max_age and b"strict-transport-security" not in present:
                    headers.append((b"strict-transport-security", f"max-age={max_age}".encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
