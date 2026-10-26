"""A tiny local stand-in for the Anthropic API, for browser checks and end-to-end tests of the AI assist.

It answers just what Kresheen calls: `GET /v1/models` and `POST /v1/messages`. It accepts any API key. The reply to
`/v1/messages` is canned: a JSON text block chosen by the task, found from the system prompt ("intake" or "explain").

Run it, then point the server at it:

    python tests/support/anthropic_stub.py --port 8765 &
    KRESHEEN_AI_BASE_URL=http://127.0.0.1:8765 KRESHEEN_SECRET_KEY=<fernet key> kresheen serve ...

Override a canned reply with `--intake-json '{...}'` or `--explain-json '{...}'`. Test and demo use only: it listens on
localhost and does no checking of what it is sent.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL_ID = "stub-model"

INTAKE_REPLY = {
    "name": "Patient portal",
    "description": "Patients log in to see health records and pay bills by card. Staff use an admin panel.",
    "system_type": "web_app",
    "users": ["customers", "staff"],
    "authentication": "password",
    "data": ["personal", "payment"],
    "third_parties": ["payments"],
    "has_admin": True,
}
EXPLAIN_REPLY = {
    "text": "This threat means an attacker could abuse this part of the system. The mitigation reduces that risk."
}

_replies = {"intake": INTAKE_REPLY, "explain": EXPLAIN_REPLY}


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: object) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path.split("?")[0].rstrip("/") == "/v1/models":
            model = {
                "type": "model",
                "id": MODEL_ID,
                "display_name": "Stub model",
                "created_at": "2026-01-01T00:00:00Z",
            }
            self._send(200, {"data": [model], "has_more": False, "first_id": MODEL_ID, "last_id": MODEL_ID})
        else:
            self._send(404, {"type": "error", "error": {"type": "not_found_error", "message": "not found"}})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length) or b"{}")
        if self.path.split("?")[0].rstrip("/") != "/v1/messages":
            self._send(404, {"type": "error", "error": {"type": "not_found_error", "message": "not found"}})
            return
        system = str(request.get("system", "")).lower()
        reply = _replies["intake"] if "intake" in system else _replies["explain"]
        self._send(
            200,
            {
                "id": "msg_stub",
                "type": "message",
                "role": "assistant",
                "model": request.get("model", MODEL_ID),
                "content": [{"type": "text", "text": json.dumps(reply)}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 120, "output_tokens": 60},
            },
        )

    def log_message(self, format: str, *args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--intake-json", help="JSON object to return for the intake draft task")
    parser.add_argument("--explain-json", help="JSON object to return for the explain task")
    args = parser.parse_args()
    if args.intake_json:
        _replies["intake"] = json.loads(args.intake_json)
    if args.explain_json:
        _replies["explain"] = json.loads(args.explain_json)
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
