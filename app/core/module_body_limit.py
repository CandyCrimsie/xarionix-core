from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class ModuleBodyLimit:
    """Bound module protocol JSON even for chunked requests before DB acquisition."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith(
            (
                "/api/v1/module-agent",
                "/api/v1/platform/module-",
                "/api/v1/platform/package-publishers",
                "/api/v1/platform/packages/",
            )
        ):
            await self.app(scope, receive, send)
            return
        data = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(data) + len(chunk) > 16384:
                await JSONResponse({"detail": {"code": "module_payload_too_large"}}, status_code=413)(
                    scope, receive, send
                )
                return
            data.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive() -> Message:
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(data), "more_body": False}

        await self.app(scope, bounded_receive, send)
