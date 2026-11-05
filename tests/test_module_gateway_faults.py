import asyncio
import socket
import struct
import tempfile
import threading
import time
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException
from test_module_gateway import offered, response
from test_module_gateway import relay as relay
from test_module_gateway import verdict as verdict

from app.integrations.keycloak.oidc import OIDCVerifier
from app.main import create_app
from scripts.deployment_agent.ipc import exchange


@pytest.mark.parametrize("status,stream,size", [(200, 1, 0), (101, 2, 10), (101, 1, 1000000)])
def test_ipc_rejects_downgrade_stderr_and_oversized_frames(status, stream, size):
    with tempfile.TemporaryDirectory(prefix="xgw-") as folder:
        path = Path(folder) / "ipc.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            listener.listen(1)

            def server():
                with listener.accept()[0] as connection:
                    connection.settimeout(2)
                    request = bytearray()
                    try:
                        while not request.endswith(b"\r\n\r\n"):
                            request.extend(connection.recv(1))
                        length = int(
                            next(
                                line.split(b":")[1]
                                for line in request.split(b"\r\n")
                                if line.startswith(b"Content-Length:")
                            )
                        )
                        connection.recv(length)
                        connection.sendall(
                            f"HTTP/1.1 {status} UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n".encode()
                        )
                        if status == 101:
                            connection.recv(4096)
                            connection.sendall(bytes([stream, 0, 0, 0]) + struct.pack("!I", size))
                    except (OSError, ValueError):
                        pass

            thread = threading.Thread(target=server)
            thread.start()
            try:
                with pytest.raises(ValueError):
                    exchange(path, "a" * 64, b'{"private":"business"}', 2, 100)
            finally:
                thread.join(timeout=3)
                assert not thread.is_alive()


def test_ipc_body_uses_stdin_and_never_request_headers_or_exec_url():
    observed = {}
    with tempfile.TemporaryDirectory(prefix="xgw-") as folder:
        path = Path(folder) / "ipc.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            listener.listen(1)

            def server():
                with listener.accept()[0] as connection:
                    connection.settimeout(2)
                    request = bytearray()
                    while not request.endswith(b"\r\n\r\n"):
                        request.extend(connection.recv(1))
                    length = int(
                        next(
                            line.split(b":")[1]
                            for line in request.split(b"\r\n")
                            if line.startswith(b"Content-Length:")
                        )
                    )
                    observed["start"] = connection.recv(length)
                    observed["headers"] = bytes(request)
                    connection.sendall(
                        b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
                    )
                    length = struct.unpack("!I", connection.recv(4))[0]
                    observed["frame"] = connection.recv(length)
                    value = b'{"body":{"ok":true}}'
                    connection.sendall(b"\1\0\0\0" + struct.pack("!I", len(value)) + value)

            thread = threading.Thread(target=server)
            thread.start()
            try:
                result = exchange(path, "b" * 64, b'{"private":"business"}', 2, 100)
                assert result == {"body": {"ok": True}}
            finally:
                thread.join(timeout=3)
            assert b"business" not in observed["headers"] + observed["start"]
            assert observed["frame"] == b'{"private":"business"}'


async def test_timeout_cleans_pending_and_rejects_late_response(relay, verdict):
    relay.config.gateway_deadline_seconds = 1
    session, task, frame = await offered(relay, verdict)
    with pytest.raises(HTTPException) as error:
        await task
    assert error.value.status_code == 504 and not relay.pending
    with pytest.raises(HTTPException):
        await relay.complete(verdict.host_id, response(frame, session), 1)


async def test_mutated_generation_is_rejected_even_if_permission_still_exists(relay, verdict, monkeypatch):
    from dataclasses import replace

    async def changed(*args):
        return replace(verdict, deployment_generation=verdict.deployment_generation + 1)

    monkeypatch.setattr("app.domains.module_gateway.transport.authorize", changed)
    session, task, frame = await offered(relay, verdict)
    with pytest.raises(HTTPException):
        await relay.claim(verdict.host_id, session, frame.context.request_id, 1)
    with pytest.raises(HTTPException) as error:
        await task
    assert error.value.detail["code"] == "gateway_authorization_changed"


async def test_result_cannot_change_installation_or_generation(relay, verdict, monkeypatch):
    async def allow(*args):
        return verdict

    monkeypatch.setattr("app.domains.module_gateway.transport.authorize", allow)
    session, task, frame = await offered(relay, verdict)
    await relay.claim(verdict.host_id, session, frame.context.request_id, 1)
    result = response(frame, session).model_copy(update={"installation_id": uuid4()})
    with pytest.raises(HTTPException):
        await relay.complete(verdict.host_id, result, 1)
    assert not task.done()
    await relay.complete(verdict.host_id, response(frame, session), 1)
    assert (await task)["body"]["answer"] == 42


async def test_expired_session_and_shutdown_cannot_redispatch(relay, verdict):
    session, task, frame = await offered(relay, verdict)
    relay.sessions[verdict.host_id].expires = time.time() - 1
    with pytest.raises(HTTPException):
        await relay.claim(verdict.host_id, session, frame.context.request_id, 1)
    relay.close()
    with pytest.raises(HTTPException) as error:
        await task
    assert error.value.detail["code"] == "gateway_shutdown" and not relay.pending


async def test_revocation_after_execution_also_denies_response(relay, verdict, monkeypatch):
    async def allow(*args):
        return verdict

    monkeypatch.setattr("app.domains.module_gateway.transport.authorize", allow)
    session, task, frame = await offered(relay, verdict)
    await relay.claim(verdict.host_id, session, frame.context.request_id, 1)

    async def revoked(*args):
        raise HTTPException(403, detail={"code": "company_permission_denied"})

    monkeypatch.setattr("app.domains.module_gateway.transport.authorize", revoked)
    with pytest.raises(HTTPException):
        await relay.complete(verdict.host_id, response(frame, session), 1)
    with pytest.raises(HTTPException) as error:
        await task
    assert error.value.status_code == 403


async def test_oversized_response_terminates_request_with_safe_code(relay, verdict, monkeypatch):
    async def allow(*args):
        return verdict

    monkeypatch.setattr("app.domains.module_gateway.transport.authorize", allow)
    session, task, frame = await offered(relay, verdict)
    await relay.claim(verdict.host_id, session, frame.context.request_id, 1)
    result = response(frame, session).model_copy(update={"body": {"large": "x" * 70000}})
    with pytest.raises(HTTPException):
        await relay.complete(verdict.host_id, result, 1)
    with pytest.raises(HTTPException) as error:
        await task
    assert error.value.detail == {"code": "gateway_response_limit"}


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "xarionix-core"},
        {"aud": "xarionix-core-deployment", "xarionix_principal": "deployment"},
        {"aud": ["xarionix-core-gateway", "xarionix-core"], "xarionix_principal": "gateway", "azp": "agent"},
        {"aud": "xarionix-core-gateway", "xarionix_principal": "machine"},
        {"aud": "xarionix-core-gateway", "xarionix_principal": "gateway", "azp": "agent", "exp": 1},
        {
            "aud": "xarionix-core-gateway",
            "xarionix_principal": "gateway",
            "azp": "agent",
            "client_id": "another",
        },
    ],
)
async def test_data_plane_rejects_wrong_token_purpose_audience_expiry_and_client(provider, changes):
    app = create_app(provider.settings)
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as oidc:
        app.state.oidc = OIDCVerifier(provider.settings, oidc)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=provider.settings.public_url
        ) as client:
            result = await client.post(
                f"/api/v1/module-gateway/hosts/{uuid4()}/sessions",
                headers={"Authorization": "Bearer " + provider.token(**changes)},
                json={"protocol": "module-gateway-poll-v1"},
            )
            assert result.status_code == 401


async def test_slow_body_is_cancelled_before_database_and_frees_ingress():
    from app.core.module_body_limit import ModuleBodyLimit

    called, sent = [], []

    async def app(scope, receive, send):
        called.append(True)

    async def receive():
        await asyncio.Event().wait()

    async def send(message):
        sent.append(message)

    middleware = ModuleBodyLimit(app, gateway_body_seconds=0.01)
    await middleware({"type": "http", "path": "/api/v1/module-gateway/hosts/test/poll"}, receive, send)
    assert not called and middleware.readers == 0
    assert sent[0]["status"] == 408


async def test_ingress_backpressure_does_not_queue_another_body():
    from starlette.responses import JSONResponse

    from app.core.module_body_limit import ModuleBodyLimit

    entered, release = asyncio.Event(), asyncio.Event()

    async def app(scope, receive, send):
        entered.set()
        await release.wait()
        await JSONResponse({"ok": True})(scope, receive, send)

    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    sent = []

    async def send(message):
        sent.append(message)

    middleware = ModuleBodyLimit(app, gateway_ingress=1)
    scope = {"type": "http", "path": "/api/v1/module-gateway/hosts/test/poll"}
    first = asyncio.create_task(middleware(scope, receive, send))
    await entered.wait()
    await middleware(scope, receive, send)
    assert sent[0]["status"] == 429
    release.set()
    await first
    assert middleware.readers == 0


async def test_operator_can_reduce_json_depth_without_raising_hard_cap(relay, verdict):
    relay.config.gateway_json_depth = 1
    relay.open(verdict.host_id, 1, time.time() + 60)
    with pytest.raises(HTTPException) as error:
        await relay.invoke(verdict, {"nested": {"value": 1}})
    assert error.value.status_code == 413 and not relay.pending


async def test_operation_id_policy_is_enforced_before_database(settings):
    from app.domains.module_gateway.authorization import authorize

    settings.gateway_operation_id_length = 4
    with pytest.raises(HTTPException) as error:
        await authorize(None, settings, {"exp": time.time() + 60}, uuid4(), "test-module", "objects-read")
    assert error.value.detail == {"code": "gateway_operation_not_found"}
