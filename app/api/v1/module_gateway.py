"""Narrow operation gateway and separate outbound-only agent data plane."""

import asyncio
import time
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field

from app.api.v1.dependencies import Ctx
from app.core.access import audit, fail, require_platform
from app.core.authentication import verified_claims, verified_gateway_claims
from app.domains.audit.model import AuditEvent
from app.domains.deployments.model import DeploymentHost
from app.domains.module_gateway.authorization import authorize, gateway_host
from app.domains.module_gateway.contracts import Correlation, Frame, Poll, Result, SessionOpen
from app.domains.module_gateway.model import GatewayIdentity
from app.domains.module_gateway.transport import Relay

router = APIRouter(prefix="/api/v1", tags=["module-gateway"])
Human = Annotated[dict[str, Any], Depends(verified_claims)]
Gateway = Annotated[dict[str, Any], Depends(verified_gateway_claims)]


class IdentityCreate(Frame):
    issuer: str = Field(max_length=512)
    subject: str = Field(min_length=1, max_length=255)
    client_id: str = Field(min_length=1, max_length=120)


class IdentityStatus(Frame):
    status: Literal["active", "disabled", "revoked"]
    expected_revision: int | None = Field(default=None, ge=1, strict=True)


@router.get("/platform/deployment-hosts/{host_id}/gateway-identity")
async def identity_detail(host_id: UUID, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    if await ctx.session.get(DeploymentHost, host_id) is None:
        fail(404, "deployment_host_not_found")
    value = await ctx.session.get(GatewayIdentity, host_id)
    return {
        "host_id": host_id,
        "identity": {
            "issuer": value.issuer,
            "subject": value.subject,
            "client_id": value.client_id,
            "revision": value.revision,
            "status": value.status,
        }
        if value
        else None,
    }


@router.post("/platform/deployment-hosts/{host_id}/gateway-identity", status_code=201)
async def bind_identity(host_id: UUID, payload: IdentityCreate, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx)
    host = await ctx.session.get(DeploymentHost, host_id)
    if host is None or host.status != "active" or payload.issuer != ctx.config.oidc_issuer:
        fail(409, "gateway_host_unavailable")
    if (payload.subject, payload.client_id) == (host.subject, host.client_id):
        fail(422, "gateway_separate_identity_required")
    if await ctx.session.get(GatewayIdentity, host_id):
        fail(409, "gateway_identity_exists")
    value = GatewayIdentity(
        host_id=host_id,
        issuer=payload.issuer,
        subject=payload.subject,
        client_id=payload.client_id,
        approved_by=ctx.user.id,
        revision=1,
        status="active",
    )
    ctx.session.add(value)
    audit(ctx, "gateway.identity_approved", "deployment_host", host_id)
    await ctx.session.flush()
    return {"host_id": host_id, "revision": value.revision, "status": value.status}


@router.patch("/platform/deployment-hosts/{host_id}/gateway-identity")
async def identity_status(host_id: UUID, payload: IdentityStatus, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx)
    value = await ctx.session.get(GatewayIdentity, host_id, with_for_update=True)
    if value is None or value.status == "revoked":
        fail(409, "gateway_identity_unavailable")
    if payload.expected_revision is not None and payload.expected_revision != value.revision:
        fail(409, "gateway_identity_revision_conflict")
    value.status, value.revision = payload.status, value.revision + 1
    audit(ctx, "gateway.identity_status_changed", "deployment_host", host_id, status=value.status)
    return {"host_id": host_id, "revision": value.revision, "status": value.status}


@router.post("/companies/{company_id}/modules/{module_id}/operations/{operation_id}")
async def operation(
    company_id: UUID, module_id: str, operation_id: str, body: dict[str, Any], request: Request, claims: Human
) -> dict[str, Any]:
    config, sessions = request.app.state.settings, request.app.state.sessions
    verdict = await authorize(sessions, config, claims, company_id, module_id, operation_id)
    status = 200
    relay: Relay = request.app.state.gateway
    identifier = uuid4()
    task = asyncio.create_task(relay.invoke(verdict, body, request_id=identifier))

    async def disconnected() -> None:
        while not task.done():
            if await request.is_disconnected():
                task.cancel()
                return
            await asyncio.sleep(0.1)

    watcher = asyncio.create_task(disconnected())
    try:
        return await task
    except HTTPException as error:
        status = error.status_code
        detail = dict(error.detail) if isinstance(error.detail, dict) else {"code": "gateway_request_failed"}
        raise HTTPException(status, detail=detail | {"request_id": str(identifier)}) from None
    except asyncio.CancelledError:
        status = 499
        task.cancel()
        raise
    finally:
        watcher.cancel()
        # Metadata only. No remote transaction and no bodies, token, headers or raw exceptions.
        async with sessions() as session, session.begin():
            session.add(
                AuditEvent(
                    actor_user_id=verdict.actor_id,
                    action="gateway.operation_finished",
                    resource_type="module_installation",
                    resource_id=verdict.installation_id,
                    company_id=company_id,
                    request_id=str(identifier),
                    details={
                        "operation_id": operation_id,
                        "status": status,
                        "deployment_generation": verdict.deployment_generation,
                        "http_request_id": request.state.request_id,
                    },
                )
            )


@router.post("/module-gateway/hosts/{host_id}/sessions")
async def session_open(
    host_id: UUID, payload: SessionOpen, request: Request, claims: Gateway
) -> dict[str, Any]:
    revision = await gateway_host(request.app.state.sessions, claims, host_id)
    identifier = request.app.state.gateway.open(host_id, revision, float(claims["exp"]))
    return {
        "schema_version": 1,
        "session_id": identifier,
        "expires_in": min(300, int(claims["exp"] - time.time())),
        "protocol": payload.protocol,
    }


@router.post("/module-gateway/hosts/{host_id}/poll")
async def poll(host_id: UUID, payload: Poll, request: Request, claims: Gateway) -> dict[str, Any]:
    revision = await gateway_host(request.app.state.sessions, claims, host_id)
    frames = await request.app.state.gateway.poll(
        host_id, payload.session_id, revision, payload.sequence, payload.capacity
    )
    return {"schema_version": 1, "requests": [f.model_dump(mode="json") for f in frames]}


@router.post("/module-gateway/hosts/{host_id}/claim")
async def claim(host_id: UUID, payload: Correlation, request: Request, claims: Gateway) -> dict[str, bool]:
    revision = await gateway_host(request.app.state.sessions, claims, host_id)
    await request.app.state.gateway.claim(host_id, payload.session_id, payload.request_id, revision)
    return {"accepted": True}


@router.post("/module-gateway/hosts/{host_id}/result")
async def result(host_id: UUID, payload: Result, request: Request, claims: Gateway) -> dict[str, bool]:
    revision = await gateway_host(request.app.state.sessions, claims, host_id)
    await request.app.state.gateway.complete(host_id, payload, revision)
    return {"accepted": True}
