import asyncio
import json
import time

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class ModuleBodyLimit:
    """Bound module protocol JSON even for chunked requests before DB acquisition."""

    def __init__(self, app: ASGIApp, gateway_ingress: int = 64, gateway_body_seconds: float = 10):
        self.app = app
        self.gateway_ingress = gateway_ingress
        self.gateway_body_seconds = gateway_body_seconds
        self.readers = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        gateway = self.is_gateway(scope)
        if gateway and self.readers >= self.gateway_ingress:
            await JSONResponse({"detail": {"code": "gateway_ingress_capacity"}}, status_code=429)(
                scope, receive, send
            )
            return
        if gateway:
            self.readers += 1
        try:
            await self.dispatch(scope, receive, send, gateway)
        finally:
            if gateway:
                self.readers -= 1

    @staticmethod
    def is_gateway(scope: Scope) -> bool:
        return scope["type"] == "http" and (
            scope["path"].startswith("/api/v1/module-gateway/")
            or (
                scope["path"].startswith("/api/v1/companies/")
                and "/modules/" in scope["path"]
                and "/operations/" in scope["path"]
            )
        )

    async def dispatch(self, scope: Scope, receive: Receive, send: Send, gateway: bool) -> None:
        if scope["type"] != "http" or (
            not gateway
            and not scope["path"].startswith(
                (
                    "/api/v1/module-agent",
                    "/api/v1/deployment-agent",
                    "/api/v1/platform/deployment-",
                    "/api/v1/platform/runtime-",
                    "/api/v1/platform/module-",
                    "/api/v1/platform/package-publishers",
                    "/api/v1/platform/packages/",
                )
            )
        ):
            await self.app(scope, receive, send)
            return
        data = bytearray()
        deadline = time.monotonic() + self.gateway_body_seconds
        limit = (
            1100000
            if gateway and scope["path"].startswith("/api/v1/module-gateway/")
            else 65536
            if gateway
            else 16384
        )
        while True:
            try:
                async with asyncio.timeout(max(0, deadline - time.monotonic()) if gateway else None):
                    message = await receive()
            except TimeoutError:
                await JSONResponse({"detail": {"code": "gateway_body_timeout"}}, status_code=408)(
                    scope, receive, send
                )
                return
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(data) + len(chunk) > limit:
                await JSONResponse({"detail": {"code": "module_payload_too_large"}}, status_code=413)(
                    scope, receive, send
                )
                return
            data.extend(chunk)
            if not message.get("more_body", False):
                break
        if gateway:
            try:

                def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
                    result: dict[str, object] = {}
                    for key, value in values:
                        if key in result:
                            raise ValueError("duplicate_key")
                        result[key] = value
                    return result

                decoded = json.loads(
                    data,
                    object_pairs_hook=pairs,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
                )
                from app.domains.module_gateway.contracts import json_bytes

                json_bytes(decoded, limit=limit, depth=24)
            except (ValueError, RecursionError):
                await JSONResponse({"detail": {"code": "gateway_json_invalid"}}, status_code=422)(
                    scope, receive, send
                )
                return
        delivered = False

        async def bounded_receive() -> Message:
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(data), "more_body": False}

        await self.app(scope, bounded_receive, send)
