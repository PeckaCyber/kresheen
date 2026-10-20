"""Reject oversized request bodies before they are read into memory.

Uploads (manifests, diagrams, documents) arrive as JSON, so one body holds a whole file plus overhead.
Without a cap, a single authenticated request of a few hundred MB exhausted a 2 GB container. The default cap is 25 MB; `KRESHEEN_MAX_REQUEST_BYTES` overrides it.

Pure ASGI (not `BaseHTTPMiddleware`) so a streamed body is counted as it arrives and cut off at the limit
instead of being buffered first. A declared `Content-Length` over the limit is refused without reading anything.
"""

from __future__ import annotations

import json
import os

DEFAULT_MAX_REQUEST_BYTES = 25 * 1024 * 1024


def max_request_bytes() -> int:
    try:
        value = int(os.environ.get("KRESHEEN_MAX_REQUEST_BYTES", str(DEFAULT_MAX_REQUEST_BYTES)))
    except ValueError:
        return DEFAULT_MAX_REQUEST_BYTES
    return value if value > 0 else DEFAULT_MAX_REQUEST_BYTES


class _TooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    def __init__(self, app, limit: int | None = None) -> None:
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limit or max_request_bytes()
        declared = next((v for k, v in scope["headers"] if k == b"content-length"), None)
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = False
            if too_big:
                await self._reject(send, limit)
                return

        received = 0
        started = False  # the app began its own response
        rejected = False  # we already answered 413: drop whatever the app tries to send after

        async def counting_receive():
            nonlocal received, rejected
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit and not started and not rejected:
                    # Answer now: frameworks catch exceptions raised while reading the body and turn them
                    # into their own 400, so raising alone would not produce a 413.
                    rejected = True
                    await self._reject(send, limit)
                if rejected:
                    raise _TooLarge
            return message

        async def tracking_send(message):
            nonlocal started
            if rejected:
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            pass

    @staticmethod
    async def _reject(send, limit: int) -> None:
        body = json.dumps({"detail": f"Request body too large (limit {limit // (1024 * 1024)} MB)"}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})
