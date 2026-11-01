"""Exercise the actual Uvicorn process in explicit dev mode, without Docker/mocks.

Intentionally unavailable DB/IdP must mean unready + denied authentication, not a fallback.
Both ephemeral ports stay reserved by this test, never touching a neighboring service.
"""

import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx


def test_actual_core_process_fails_closed_when_dependencies_are_unavailable():
    with socket.socket() as listener, socket.socket() as unavailable:
        listener.bind(("127.0.0.1", 0))
        unavailable.bind(("127.0.0.1", 0))  # Reserved but deliberately not listening.
        port, dependency_port = listener.getsockname()[1], unavailable.getsockname()[1]
        secret = secrets.token_hex(32)
        environment = {key: value for key, value in os.environ.items() if not key.startswith("XARIONIX_")}
        environment |= {
            "XARIONIX_ENVIRONMENT": "development",
            "XARIONIX_KEYCLOAK_MODE": "external",
            "XARIONIX_PUBLIC_URL": f"http://localhost:{port}",
            "XARIONIX_OIDC_ISSUER": f"http://localhost:{dependency_port}/realms/xarionix",
            "XARIONIX_OIDC_TIMEOUT_SECONDS": "0.1",
            "XARIONIX_DB_HOST": "127.0.0.1",
            "XARIONIX_DB_PORT": str(dependency_port),
            "XARIONIX_DB_PASSWORD": secret,
        }
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:create_app",
                "--factory",
                "--fd",
                str(listener.fileno()),
                "--no-access-log",
                "--no-proxy-headers",
                "--no-server-header",
            ],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            pass_fds=(listener.fileno(),),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=1, trust_env=False) as client:
                for _ in range(100):
                    try:
                        live = client.get("/health/live")
                        break
                    except httpx.HTTPError:
                        if process.poll() is not None:
                            raise AssertionError("Core process exited before serving health") from None
                        time.sleep(0.05)
                else:
                    raise AssertionError("Core process did not start")
                assert live.status_code == 200 and live.json() == {"status": "ok"}
                # DB readiness has a deliberate six-second total deadline, independent of HTTP liveness.
                ready = client.get("/health/ready", timeout=8)
                assert ready.status_code == 503 and ready.json() == {"status": "not_ready"}
                assert (
                    client.get(
                        "/api/v1/me", headers={"Authorization": "Bearer intentionally-invalid-token"}
                    ).status_code
                    == 401
                )
        finally:
            process.terminate()
            try:
                output, _ = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=5)
        assert secret.encode() not in output
        assert b"intentionally-invalid-token" not in output
