from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from sqlalchemy import func, select

from app.api.v1.dependencies import Ctx, Limit, Offset
from app.api.v1.installation_schemas import BindInstance, PlanCreate, PlanDigest
from app.api.v1.packages import Claims, live_claims, transaction
from app.core.access import fail, require_platform
from app.domains.installations import service
from app.domains.installations.model import (
    ModuleInstallation,
    ModuleInstallationHistory,
    ModuleInstallOperation,
    ModuleInstallPlan,
)
from app.domains.packages.archive import Limits
from app.domains.packages.storage import Storage
from app.domains.packages.work import file_work

router = APIRouter(prefix="/api/v1/platform", tags=["module-manager"])


@router.get("/module-install-plans")
async def plans(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    rows = (
        await ctx.session.scalars(
            select(ModuleInstallPlan)
            .order_by(ModuleInstallPlan.created_at.desc(), ModuleInstallPlan.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return {"items": [service.plan_view(value) for value in rows], "limit": limit, "offset": offset}


@router.post("/module-install-plans", status_code=201)
async def create(payload: PlanCreate, request: Request, claims: Claims) -> dict[str, Any]:
    async with transaction(request, claims) as ctx:
        await require_platform(ctx, serialize=False)
        body, store = await service.snapshot(
            ctx, payload.action, payload.package_id, payload.expected_generation
        )
    storage = Storage(request.app.state.settings.packages_storage_root)
    lease = storage.lease()
    try:
        await file_work(
            service.verify_blobs, body, store, storage, Limits.configured(request.app.state.settings)
        )
        async with transaction(request, await live_claims(request)) as ctx:
            await require_platform(ctx, serialize=False)
            await service.locks(ctx, body)
            fresh, _ = await service.snapshot(
                ctx, payload.action, payload.package_id, payload.expected_generation
            )
            if fresh != body:
                fail(409, "installation_plan_snapshot_changed")
            return service.plan_view(await service.create_plan(ctx, payload.idempotency_key, body))
    finally:
        lease.close()


@router.get("/module-install-plans/{plan_id}")
async def detail(plan_id: UUID, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    return service.plan_view(await service.plan(ctx, plan_id))


@router.post("/module-install-plans/{plan_id}/refresh", status_code=201)
async def refresh_plan(plan_id: UUID, request: Request, claims: Claims) -> dict[str, Any]:
    # A NEW plan/nonce, full verification and fresh approval; never extend the old approval/MFA TTL.
    async with transaction(request, claims) as ctx:
        await require_platform(ctx, serialize=False)
        old = await service.plan(ctx, plan_id)
        current = await ctx.session.scalar(
            select(ModuleInstallation).where(ModuleInstallation.module_id == old.module_id)
        )
        payload = PlanCreate.model_validate(
            {
                "action": old.action,
                "package_id": old.package_id,
                "expected_generation": current.generation if current else 0,
                "idempotency_key": uuid4(),
            }
        )
    return await create(payload, request, await live_claims(request))


@router.post("/module-install-plans/{plan_id}/approve")
async def approve(plan_id: UUID, payload: PlanDigest, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    value = await service.plan(ctx, plan_id)
    await service.locks(ctx, value.body)
    return service.plan_view(
        await service.approve(ctx, await service.plan(ctx, plan_id, lock=True), payload.digest)
    )


@router.post("/module-install-plans/{plan_id}/cancel")
async def cancel(plan_id: UUID, payload: PlanDigest, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    value = await service.plan(ctx, plan_id)
    await service.locks(ctx, value.body)
    value = await service.plan(ctx, plan_id, lock=True)
    if value.digest != payload.digest:
        fail(409, "installation_plan_digest_conflict")
    return service.plan_view(await service.cancel(ctx, value))


@router.get("/module-installations")
async def installations(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    total = await ctx.session.scalar(select(func.count()).select_from(ModuleInstallation))
    rows = (
        await ctx.session.scalars(
            select(ModuleInstallation).order_by(ModuleInstallation.module_id).limit(limit).offset(offset)
        )
    ).all()
    return {
        "items": await service.views(ctx, rows),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/module-installations/{installation_id}")
async def installation(installation_id: UUID, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    return await service.view(ctx, await service.installation(ctx, installation_id))


@router.get("/module-installations/{installation_id}/history")
async def history(installation_id: UUID, ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    await service.installation(ctx, installation_id)
    query = select(ModuleInstallationHistory).where(
        ModuleInstallationHistory.installation_id == installation_id
    )
    total = await ctx.session.scalar(select(func.count()).select_from(query.subquery()))
    rows = (
        await ctx.session.scalars(
            query.order_by(ModuleInstallationHistory.generation.desc()).limit(limit).offset(offset)
        )
    ).all()
    return {
        "items": [
            {
                "id": r.id,
                "operation_id": r.operation_id,
                "previous_package_id": r.previous_package_id,
                "package_id": r.package_id,
                "previous_state": r.previous_state,
                "state": r.state,
                "generation": r.generation,
                "performed_by": r.performed_by,
                "created_at": r.created_at,
            }
            for r in rows
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/module-install-operations")
async def operations(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    total = await ctx.session.scalar(select(func.count()).select_from(ModuleInstallOperation))
    rows = (
        await ctx.session.scalars(
            select(ModuleInstallOperation)
            .order_by(ModuleInstallOperation.created_at.desc(), ModuleInstallOperation.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return {
        "items": [service.operation_view(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/module-install-operations/{operation_id}")
async def operation(operation_id: UUID, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    return service.operation_view(await service.operation(ctx, operation_id))


@router.post("/module-installations/{installation_id}/bind-instance")
async def bind(installation_id: UUID, payload: BindInstance, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx, serialize=False)
    value = await service.installation(ctx, installation_id)
    result = await service.bind(ctx, value, **payload.model_dump())
    return {
        "installation_id": result.installation_id,
        "instance_id": result.instance_id,
        "active": result.active,
        "package_id": result.package_id,
        "revision": result.revision,
    }
