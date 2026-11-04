"""Real HTTP example, deliberately offline: no Core/IdP/DB credentials or dependencies."""

import json
import os
import signal
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path not in {"/health/live", "/health/ready", "/version"}:
            self.send_error(404)
            return
        status = (
            503
            if self.path == "/health/ready"
            and (Path("/tmp/not-ready").exists() or os.environ.get("HELLO_READY") != "true")
            else 200
        )
        value = (
            {"version": os.environ.get("HELLO_VERSION", "1.0.0")}
            if self.path == "/version"
            else {"status": "ok" if status == 200 else "not_ready"}
        )
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        pass


def stop(signum: int, frame: object) -> None:
    raise SystemExit(0)


def crash(signum: int, frame: object) -> None:
    # Explicit demo fault injection, not a public HTTP route or agent command.
    raise SystemExit(1)


# Python as container PID 1 needs an explicit handler for graceful Docker stop.
for signum in (signal.SIGTERM, signal.SIGINT):
    signal.signal(signum, stop)
signal.signal(signal.SIGUSR1, crash)
server = HTTPServer(("0.0.0.0", 8080), Handler)
try:
    server.serve_forever()
finally:
    server.server_close()
