import asyncio
import logging
import re
import ssl
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from app.api.v1.routes import router
from app.api.v1.tenants import router as tenants_router
from app.core.config import Settings
from app.core.database import create_database, database_ready
from app.core.logging import configure_logging
from app.integrations.keycloak.oidc import OIDCVerifier


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        try:
            settings = Settings()
        except ValidationError:
            raise RuntimeError("Invalid Xarionix configuration; run the configuration validator") from None
    config = settings
    configure_logging()
    logger = logging.getLogger("xarionix")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine, sessions = create_database(config)
        app.state.engine, app.state.sessions = engine, sessions
        try:
            async with httpx.AsyncClient(
                verify=ssl.create_default_context(),
                timeout=config.oidc_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                app.state.oidc = OIDCVerifier(config, client)
                # Transient outage => unready, never bypass validation. Requests can retry later.
                await app.state.oidc.ready()
                yield
        finally:
            await engine.dispose()

    app = FastAPI(
        title="Xarionix Core",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if config.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if config.docs_enabled else None,
    )
    app.state.settings = config

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, error: RequestValidationError) -> JSONResponse:
        # Pydantic's usual input/ctx echo can reproduce an invitation secret.
        return JSONResponse(
            {
                "detail": [
                    {"loc": item["loc"], "type": item["type"], "msg": "Invalid request field"}
                    for item in error.errors()
                ]
            },
            status_code=422,
        )

    if config.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.cors_origins,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
            allow_credentials=False,
        )

    @app.middleware("http")
    async def request_context(request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if re.fullmatch(r"[A-Za-z0-9_-]{8,64}", supplied) else uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            response = JSONResponse({"detail": "Internal server error"}, status_code=500)
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        logger.info(
            "request",
            extra={
                "event": "http_request",
                "request_id": request_id,
                "method": request.method,
                "status": response.status_code,
                "duration_ms": round((time.monotonic() - start) * 1000),
            },
        )
        return response

    @app.get("/health/live", include_in_schema=False)
    async def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    async def ready() -> JSONResponse:
        database_ok, identity_ok = await asyncio.gather(
            database_ready(app.state.engine), app.state.oidc.ready()
        )
        healthy = database_ok and identity_ok
        return JSONResponse(
            {"status": "ready" if healthy else "not_ready"}, status_code=200 if healthy else 503
        )

    app.include_router(router)
    app.include_router(tenants_router)
    return app
