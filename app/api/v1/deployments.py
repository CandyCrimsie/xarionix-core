"""Administrative plans and a separate deployment principal, never a generic execution API."""

import os
import stat
from collections.abc import AsyncIterator, Iterator
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from starlette.types import Receive, Scope, Send

from app.api.v1.dependencies import Ctx, Limit, Offset
from app.api.v1.modules import machine_context
from app.api.v1.packages import Claims, live_claims, transaction
from app.core.access import audit, fail, require_platform
from app.core.authentication import verified_deployment_claims
from app.domains.deployments import service
from app.domains.deployments.artifacts import validate_runtime
from app.domains.deployments.contracts import (
    SAFETY,
    Approval,
    CheckIn,
    HostCreate,
    Input,
    PlanCreate,
    Receipt,
)
from app.domains.deployments.model import (
    DeploymentHost,
    DeploymentJob,
    DeploymentPlan,
    ModuleRetirement,
    RuntimeDeployment,
)
from app.domains.installations import service as installations
from app.domains.module_sdk.model import ModuleDataBackup, ModuleStorageAllocation
from app.domains.modules.authorization import MachineContext
from app.domains.packages.archive import Limits, verify
from app.domains.packages.storage import Storage
from app.domains.packages.work import file_work

router = APIRouter(prefix="/api/v1", tags=["deployment"])


@router.get("/platform/runtime-deployments/{installation_id}/storage")
async def storage_detail(
    installation_id: UUID, ctx: Ctx, limit: Limit = 20, offset: Offset = 0
) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    await installations.installation(ctx, installation_id)
    value = await ctx.session.get(ModuleStorageAllocation, installation_id)
    if value is None:
        return {"allocation": None, "items": [], "limit": limit, "offset": offset}
    backups = (
        await ctx.session.scalars(
            select(ModuleDataBackup)
            .where(ModuleDataBackup.installation_id == installation_id)
            .order_by(ModuleDataBackup.created_at.desc(), ModuleDataBackup.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return {
        "allocation": {
            "installation_id": installation_id,
            "host_id": value.host_id,
            "epoch_id": value.epoch_id,
            "revision": value.revision,
            "data_schema_version": value.data_schema_version,
            "maximum_bytes": value.maximum_bytes,
            "retained_epoch_count": len(value.retained_epochs),
            "deletion_supported": False,
        },
        "items": [
            {
                "id": b.id,
                "data_schema_version": b.data_schema_version,
                "sha256": b.sha256,
                "size": b.size,
                "package_version": b.package_version,
                "created_at": b.created_at,
            }
            for b in backups
        ],
        "limit": limit,
        "offset": offset,
    }


async def deployment_context(
    request: Request, claims: Annotated[dict[str, Any], Depends(verified_deployment_claims)]
) -> AsyncIterator[MachineContext]:
    async for value in machine_context(request, claims):
        yield value


Agent = Annotated[MachineContext, Depends(deployment_context, scope="function")]


class ArtifactResponse(StreamingResponse):
    """Own the verified descriptor even if the client disconnects before iteration."""

    def __init__(self, descriptor: int, size: int, sha256: str):
        self.descriptor = descriptor

        def chunks() -> Iterator[bytes]:
            while chunk := os.read(descriptor, 65536):
                yield chunk

        super().__init__(
            chunks(),
            media_type="application/octet-stream",
            headers={
                "Content-Length": str(size),
                "X-Artifact-SHA256": sha256,
            },
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            os.close(self.descriptor)


def host_view(value: DeploymentHost) -> dict[str, Any]:
    return {
        "id": value.id,
        "name": value.name,
        "status": value.status,
        "revision": value.revision,
        "engine_id": value.engine_id,
        "platform": value.platform,
        "owner_user_id": value.owner_user_id,
        "last_seen": value.last_seen,
    }


@router.post("/platform/deployment-hosts", status_code=201)
async def register(payload: HostCreate, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx)
    if payload.issuer != ctx.config.oidc_issuer:
        fail(422, "deployment_issuer_untrusted")
    value = DeploymentHost(
        **payload.model_dump(), owner_user_id=ctx.user.id, status="active", revision=1, sequence=0
    )
    ctx.session.add(value)
    await ctx.session.flush()
    audit(ctx, "deployment.host_registered", "deployment_host", value.id)
    return host_view(value)


@router.get("/platform/deployment-hosts")
async def hosts(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    rows = (
        await ctx.session.scalars(
            select(DeploymentHost)
            .order_by(DeploymentHost.created_at, DeploymentHost.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return {"items": [host_view(v) for v in rows], "limit": limit, "offset": offset}


class Revision(Input):
    expected_revision: int


@router.post("/platform/deployment-hosts/{host_id}/{action}")
async def host_status(
    host_id: UUID, action: Literal["enable", "disable", "revoke"], payload: Revision, ctx: Ctx
) -> dict[str, Any]:
    await require_platform(ctx)
    value = await ctx.session.get(DeploymentHost, host_id, with_for_update=True)
    if value is None:
        fail(404, "deployment_host_not_found")
    if value.revision != payload.expected_revision or value.status == "revoked":
        fail(409, "deployment_host_revision_or_terminal_conflict")
    value.status = {"enable": "active", "disable": "disabled", "revoke": "revoked"}[action]
    value.revision += 1
    audit(ctx, "deployment.host_" + value.status, "deployment_host", value.id)
    await ctx.session.flush()
    return host_view(value)


@router.post("/platform/deployment-plans", status_code=201)
async def prepare(payload: PlanCreate, request: Request, claims: Claims) -> dict[str, Any]:
    async with transaction(request, claims) as ctx:
        await require_platform(ctx, serialize=False)
        installation = await installations.installation(ctx, payload.installation_id)
        package = await installations.package(ctx, installation.package_id)
        if payload.operation in {*SAFETY, "backup"}:
            latest = await ctx.session.scalar(
                select(DeploymentJob)
                .where(DeploymentJob.installation_id == installation.id)
                .order_by(DeploymentJob.generation.desc())
                .limit(1)
            )
            if latest is None:
                fail(409, "deployment_not_provisioned")
            return service.plan_view(await service.prepare(ctx, payload, latest.body["runtime"]))
        trust = await service.trust(ctx.session, package)
        expected_sha, expected_manifest = package.package_sha256, package.manifest
    from app.domains.packages.schema import TrustStore

    storage = Storage(request.app.state.settings.packages_storage_root)
    lease = storage.lease()
    try:
        checked = await file_work(
            verify,
            storage.blob(expected_sha),
            TrustStore.model_validate(trust),
            Limits.configured(request.app.state.settings),
        )
        if (
            not checked.core_compatible
            or checked.package_sha256 != expected_sha
            or checked.manifest_data != expected_manifest
        ):
            fail(409, "deployment_package_registry_mismatch")
        contract = await file_work(validate_runtime, storage.blob(expected_sha), checked.manifest)
        async with transaction(request, await live_claims(request)) as ctx:
            await require_platform(ctx, serialize=False)
            return service.plan_view(await service.prepare(ctx, payload, contract.model_dump()))
    finally:
        lease.close()


@router.get("/platform/deployment-plans/{plan_id}")
async def plan_detail(plan_id: UUID, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    value = await ctx.session.get(DeploymentPlan, plan_id)
    if value is None:
        fail(404, "deployment_plan_not_found")
    return service.plan_view(value)


@router.post("/platform/deployment-plans/{plan_id}/approve")
async def approve(plan_id: UUID, payload: Approval, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    value = await ctx.session.get(DeploymentPlan, plan_id)
    if value is None:
        fail(404, "deployment_plan_not_found")
    job = await service.queue(ctx, value, payload.digest)
    return {"job_id": job.id, "state": job.state, "generation": job.generation}


@router.post("/platform/deployment-plans/{plan_id}/cancel")
async def cancel(plan_id: UUID, payload: Approval, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    value = await ctx.session.get(DeploymentPlan, plan_id, with_for_update=True)
    if value is None:
        fail(404, "deployment_plan_not_found")
    if value.digest != payload.digest or value.state != "pending":
        fail(409, "deployment_plan_conflict")
    value.state = "cancelled"
    audit(ctx, "deployment.plan_cancelled", "deployment_plan", value.id)
    return service.plan_view(value)


@router.get("/platform/runtime-deployments")
async def deployments(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    rows = (
        await ctx.session.scalars(
            select(RuntimeDeployment).order_by(RuntimeDeployment.installation_id).limit(limit).offset(offset)
        )
    ).all()
    return {
        "items": [{c.name: getattr(r, c.name) for c in RuntimeDeployment.__table__.columns} for r in rows],
        "limit": limit,
        "offset": offset,
    }


@router.get("/platform/runtime-deployments/{installation_id}/jobs")
async def history(installation_id: UUID, ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    rows = (
        await ctx.session.scalars(
            select(DeploymentJob)
            .where(DeploymentJob.installation_id == installation_id)
            .order_by(DeploymentJob.generation.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return {
        "items": [
            {
                "id": r.id,
                "generation": r.generation,
                "operation": r.operation,
                "state": r.state,
                "attempts": r.attempts,
                "result": r.result,
            }
            for r in rows
        ],
        "limit": limit,
        "offset": offset,
    }


class Retirement(Input):
    expected_installation_generation: int
    state: Literal["quarantined", "retired"]


@router.post("/platform/module-installations/{installation_id}/retire")
async def retire(installation_id: UUID, payload: Retirement, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    value = await installations.installation(ctx, installation_id)
    await service.module_lock(ctx.session, value)
    await ctx.session.refresh(value)
    if value.generation != payload.expected_installation_generation:
        fail(409, "installation_generation_conflict")
    old = await ctx.session.get(ModuleRetirement, installation_id)
    if old is None:
        old = ModuleRetirement(
            installation_id=installation_id, state=payload.state, revision=1, performed_by=ctx.user.id
        )
        ctx.session.add(old)
    elif old.state != payload.state:
        if old.state == "retired":
            fail(409, "retirement_terminal")
        old.state, old.revision, old.performed_by = payload.state, old.revision + 1, ctx.user.id
    audit(ctx, "deployment.security_" + payload.state, "module_installation", installation_id)
    await ctx.session.flush()
    return {"installation_id": installation_id, "state": old.state, "revision": old.revision}


@router.post("/deployment-agent/hosts/{host_id}/check-in")
async def check_in(host_id: UUID, payload: CheckIn, ctx: Agent) -> dict[str, Any]:
    return await service.check_in(ctx, await service.host(ctx, host_id), payload)


class Fence(Input):
    fence: UUID


@router.post("/deployment-agent/hosts/{host_id}/jobs/{job_id}/authorize")
async def authorize(host_id: UUID, job_id: UUID, payload: Fence, ctx: Agent) -> dict[str, Any]:
    value = await service.authorize(ctx, await service.host(ctx, host_id), job_id, payload.fence)
    return {"job_id": value.id, "generation": value.generation, "lease_until": value.lease_until}


@router.post("/deployment-agent/hosts/{host_id}/jobs/{job_id}/ack")
async def ack(host_id: UUID, job_id: UUID, payload: Receipt, ctx: Agent) -> dict[str, Any]:
    value = await service.acknowledge(ctx, await service.host(ctx, host_id), job_id, payload)
    return {"job_id": value.id, "state": value.state}


@router.get("/deployment-agent/hosts/{host_id}/jobs/{job_id}/artifact")
async def artifact(
    host_id: UUID, job_id: UUID, fence: UUID, request: Request, ctx: Agent
) -> StreamingResponse:
    value = await service.authorize(ctx, await service.host(ctx, host_id), job_id, fence)
    if value.operation in SAFETY:
        fail(403, "deployment_artifact_not_required")
    storage = Storage(request.app.state.settings.packages_storage_root)
    path = storage.blob(value.body["package_sha256"])
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != value.body["package_size"]:
        os.close(descriptor)
        fail(409, "deployment_artifact_invalid")

    return ArtifactResponse(descriptor, metadata.st_size, value.body["package_sha256"])
