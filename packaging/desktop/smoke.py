"""Smoke test of a desktop build: start it like a first launch and check it serves the app and the setup page.

    python packaging/desktop/smoke.py build/desktop/dist/kresheen
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def get(port: int, path: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def main() -> None:
    app = Path(sys.argv[1])
    exe = app / ("kresheen.exe" if sys.platform == "win32" else "kresheen")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with tempfile.TemporaryDirectory() as home:
        env = {**os.environ, "KRESHEEN_HOME": home}
        process = subprocess.Popen([exe, "desktop", "--no-browser", "--port", str(port)], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            for _ in range(120):
                try:
                    if get(port, "/healthz")[0] == 200:
                        break
                except OSError:
                    pass
                if process.poll() is not None:
                    raise SystemExit(f"the app exited early:\n{process.stdout.read() if process.stdout else ''}")
                time.sleep(0.5)
            else:
                raise SystemExit("the app did not answer /healthz within 60 s")
            status, body = get(port, "/")
            assert status == 200 and b"<html" in body.lower(), "the web interface is not served"
            status, body = get(port, "/api/auth/setup")
            assert status == 200 and json.loads(body) == {"needed": True}, f"setup not offered: {status} {body!r}"
            assert (Path(home) / "secret.key").exists(), "no secret key was created"
            assert (Path(home) / "kresheen.db").exists(), "no database was created"
            print(f"smoke test passed on port {port}")
        finally:
            process.terminate()
            try:
                output, _ = process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate()
            print(output)


if __name__ == "__main__":
    main()
