"""Fixed loopback HTTP contract, bounded concurrency and safe runtime logging."""

import asyncio
import json
import logging
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .application import Module, ModuleError
from .validation import decode, json_bytes


def serve(module: Module) -> None:
    module.contract()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    stopping = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            self.request.settimeout(5)
            super().setup()

        def reply(self, status: int, value: dict[str, Any]) -> None:
            raw = json_bytes(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass

        def do_GET(self) -> None:
            if self.path in {"/health/live", "/health/ready"}:
                if self.path == "/health/ready":
                    try:
                        ready = module.readiness()
                    except Exception:
                        ready = False
                    if ready is not True:
                        self.reply(503, {"status": "not_ready"})
                        return
                self.reply(
                    503 if stopping.is_set() else 200, {"status": "draining" if stopping.is_set() else "ok"}
                )
            elif self.path == "/version":
                self.reply(200, {"module_id": module.id, "version": module.version, "sdk_protocol": 1})
            elif self.path == "/_xarionix/storage/v1":
                try:
                    self.reply(200, module.storage_status())
                except Exception:
                    self.reply(503, {"error": "storage_not_ready"})
            else:
                self.reply(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if stopping.is_set():
                self.reply(503, {"error": "module_unavailable"})
                return
            try:
                prefix = "/_xarionix/api/v1/"
                if (
                    not self.path.startswith(prefix)
                    or self.headers.get("Content-Type") != "application/json"
                    or self.headers.get("Transfer-Encoding") is not None
                    or len(self.headers.get_all("Content-Length", [])) != 1
                ):
                    raise ValueError()
                size = int(self.headers["Content-Length"])
                if not 1 <= size <= 72000:
                    raise ValueError()
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError()
                result = asyncio.run(module.dispatch(self.path[len(prefix) :], decode(raw, 72000)))
                self.reply(200, result)
            except (TimeoutError, ValueError, ModuleError, KeyError, RecursionError):
                self.reply(422, {"error": "module_request_failed"})
                # Deliberately omit raw body, exception and headers, even on invalid JSON.
                sys.stderr.write(json.dumps({"event": "module_request_rejected", "module": module.id}) + "\n")

        def log_message(self, format: str, *args: object) -> None:
            pass

    class Server(ThreadingHTTPServer):
        daemon_threads = False
        block_on_close = True
        request_queue_size = 8

        def __init__(self) -> None:
            self.capacity = threading.BoundedSemaphore(4)
            super().__init__(("127.0.0.1", 8080), Handler)

        def process_request(self, request: Any, address: Any) -> None:
            if not self.capacity.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, address)
            except Exception:
                self.capacity.release()
                raise

        def process_request_thread(self, request: Any, address: Any) -> None:
            try:
                super().process_request_thread(request, address)
            finally:
                self.capacity.release()

        def handle_error(self, request: Any, client_address: Any) -> None:
            sys.stderr.write('{"event":"module_transport_error"}\n')

    server = Server()

    def stop(*args: object) -> None:
        if not stopping.is_set():
            stopping.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, stop)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        stopping.set()
        server.server_close()
        module.shutdown()
