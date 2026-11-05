"""Real company-scoped example. Volatile demo data, never a production persistence model."""

import json
import os
import re
import signal
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID, uuid4

items: dict[str, list[dict[str, str]]] = {}
lock = threading.Lock()
permissions = {
    "status-read": "hello.status.read",
    "items-read": "hello.items.read",
    "items-create": "hello.items.create",
}
if os.environ.get("HELLO_VERSION", "1.0.0").startswith("2."):
    del permissions["status-read"]
    permissions["status-read-v2"] = "hello.status_v2.read"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, status: int, value: dict) -> None:
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        fault = Path("/tmp/gateway-fault")
        if fault.exists() and fault.read_text() == "headers":
            self.send_header("Set-Cookie", "module=untrusted; Path=/")
            self.send_header("Location", "https://untrusted.invalid/")
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:
        if self.path in {"/health/live", "/health/ready"}:
            self.reply(200, {"status": "ok"})
        elif self.path == "/version":
            self.reply(200, {"version": os.environ.get("HELLO_VERSION", "1.0.0"), "process_nonce": nonce})
        else:
            self.reply(404, {"error": "not_found"})

    def do_POST(self) -> None:
        try:
            match = re.fullmatch(r"/_xarionix/api/v1/([a-z][a-z0-9-]{0,62})", self.path)
            if (
                not match
                or match[1] not in permissions
                or self.headers.get("Content-Type") != "application/json"
            ):
                raise ValueError()
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= 72000:
                raise ValueError()
            value = json.loads(self.rfile.read(size))
            if set(value) != {"context", "body"}:
                raise ValueError()
            ctx, body = value["context"], value["body"]
            company = str(UUID(ctx["company_id"]))
            if (
                ctx["operation_id"] != match[1]
                or ctx["permission"] != permissions[match[1]]
                or datetime.fromisoformat(ctx["deadline"].replace("Z", "+00:00")) <= datetime.now(UTC)
            ):
                raise ValueError()
            UUID(ctx["actor_id"])
            UUID(ctx["request_id"])
            # Fixed local-only fault flags for disposable E2E; there is no HTTP/admin fault route.
            fault = Path("/tmp/gateway-fault")
            mode = fault.read_text() if fault.exists() else ""
            if mode == "unicode":
                self.reply(200, {"unicode": "я" * 20000})
                return
            if mode == "unicode-request":
                self.reply(200, {"received_utf8_bytes": len(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode())})
                return
            if mode == "slow":
                time.sleep(12)
            elif mode == "paused":
                Path("/tmp/gateway-entered").write_text(ctx["request_id"])
                for _ in range(160):
                    if Path("/tmp/gateway-release").exists():
                        break
                    time.sleep(.05)
            elif mode == "oversized":
                self.reply(200, {"oversized": "x" * 70000})
                return
            with lock:
                dataset = items.setdefault(company, [])
                if match[1] == "items-create":
                    if (
                        set(body) != {"name"}
                        or not isinstance(body["name"], str)
                        or not 1 <= len(body["name"]) <= 100
                        or len(dataset) >= 100
                    ):
                        raise ValueError()
                    dataset.append({"id": str(uuid4()), "name": body["name"]})
                elif body:
                    raise ValueError()
                answer = {
                    "company_id": company,
                    "actor_id": ctx["actor_id"],
                    "request_id": ctx["request_id"],
                    "operation_id": match[1],
                    "version": os.environ.get("HELLO_VERSION", "1.0.0"),
                    "process_nonce": nonce,
                    "items": list(dataset),
                }
            self.reply(200, answer)
        except (ValueError, KeyError, TypeError):
            self.reply(422, {"error": "invalid_request"})

    def log_message(self, format: str, *args: object) -> None:
        pass


def stop(*args: object) -> None:
    raise SystemExit(0)


def crash(*args: object) -> None:
    raise SystemExit(1)


for number in (signal.SIGTERM, signal.SIGINT):
    signal.signal(number, stop)
signal.signal(signal.SIGUSR1, crash)
nonce = str(uuid4())
server = ThreadingHTTPServer(("127.0.0.1", 8080), Handler)
try:
    server.serve_forever()
finally:
    server.server_close()
