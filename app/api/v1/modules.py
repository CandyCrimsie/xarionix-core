from collections.abc import AsyncIterator
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.api.v1.dependencies import Ctx, Limit, Offset
from app.api.v1.module_schemas import (
    Acknowledgement,
    CheckIn,
    CheckInView,
    CommandCreate,
    CommandView,
    CompanyMetadata,
    InstanceCreate,
    InstanceView,
    ScopePut,
    ServiceCreate,
    ServiceView,
)
from app.api.v1.schemas import Page
from app.api.v1.tenants import page
from app.core.access import audit, fail, require_platform
from app.core.authentication import verified_machine_claims
from app.domains.modules import authorization as machine
from app.domains.modules import service
from app.domains.modules.model import ModuleCommand, ModuleCompanyScope, ModuleInstance, ModuleService

router = APIRouter(prefix="/api/v1")


async def machine_context(
    request: Request, claims: Annotated[dict[str, Any], Depends(verified_machine_claims)]
) -> AsyncIterator[machine.MachineContext]:
    try:
        async with request.app.state.sessions() as session, session.begin():
            yield machine.MachineContext(
                session, request.app.state.settings, claims, request.state.request_id
            )
    except IntegrityError:
        raise HTTPException(409, detail={"code": "data_conflict"}) from None
    except DBAPIError as error:
        if getattr(error.orig, "sqlstate", None) in {"40P01", "40001", "55P03", "57014"}:
            raise HTTPException(409, detail={"code": "transaction_conflict"}) from None
        raise


Machine = Annotated[machine.MachineContext, Depends(machine_context, scope="function")]


@router.post("/platform/module-services", response_model=ServiceView, status_code=201)
async def register(payload: ServiceCreate, ctx: Ctx) -> ModuleService:
    return await service.register(ctx, payload)


@router.get("/platform/module-services", response_model=Page[ServiceView])
async def services(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx)
    return await page(
        ctx, select(ModuleService).order_by(ModuleService.created_at, ModuleService.id), limit, offset
    )


@router.get("/platform/module-services/{service_id}", response_model=ServiceView)
async def service_detail(service_id: UUID, ctx: Ctx) -> ModuleService:
    await require_platform(ctx)
    return await service.get_service(ctx, service_id)


@router.post("/platform/module-services/{service_id}/enable", response_model=ServiceView)
async def enable_service(service_id: UUID, ctx: Ctx) -> ModuleService:
    return await service.set_service_status(ctx, service_id, "active")


@router.post("/platform/module-services/{service_id}/disable", response_model=ServiceView)
async def disable_service(service_id: UUID, ctx: Ctx) -> ModuleService:
    return await service.set_service_status(ctx, service_id, "disabled")


@router.post("/platform/module-services/{service_id}/revoke", response_model=ServiceView)
async def revoke_service(service_id: UUID, ctx: Ctx) -> ModuleService:
    return await service.set_service_status(ctx, service_id, "revoked")


@router.post("/platform/module-services/{service_id}/instances", response_model=InstanceView, status_code=201)
async def instance_create(service_id: UUID, payload: InstanceCreate, ctx: Ctx) -> InstanceView:
    value = await service.create_instance(ctx, service_id, payload.installation_key)
    return service.instance_view(ctx, await service.get_service(ctx, service_id), value)


@router.get("/platform/module-instances", response_model=Page[InstanceView])
async def instances(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx)
    values = await page(
        ctx, select(ModuleInstance).order_by(ModuleInstance.created_at, ModuleInstance.id), limit, offset
    )
    # One bounded bulk query for services, not one query per instance.
    service_rows = list(
        (
            await ctx.session.scalars(
                select(ModuleService).where(
                    ModuleService.id.in_([item.service_id for item in values["items"]])
                )
            )
        ).all()
    )
    by_id = {item.id: item for item in service_rows}
    values["items"] = [service.instance_view(ctx, by_id[item.service_id], item) for item in values["items"]]
    return values


@router.get("/platform/module-instances/{instance_id}", response_model=InstanceView)
async def instance_detail(instance_id: UUID, ctx: Ctx) -> InstanceView:
    await require_platform(ctx)
    parent, value = await service.get_instance(ctx, instance_id)
    return service.instance_view(ctx, parent, value)


@router.post("/platform/module-instances/{instance_id}/{action}", response_model=InstanceView)
async def instance_status(
    instance_id: UUID, action: Literal["enable", "disable", "revoke"], ctx: Ctx
) -> InstanceView:
    await require_platform(ctx)
    parent, value = await service.get_instance(ctx, instance_id, write=True)
    if value.status == "revoked":
        fail(409, "module_revocation_terminal")
    value.status = {"enable": "active", "disable": "disabled", "revoke": "revoked"}[action]
    audit(ctx, "module.instance_" + value.status, "module_instance", value.id)
    await ctx.session.flush()
    return service.instance_view(ctx, parent, value)


@router.put("/platform/module-instances/{instance_id}/companies/{company_id}", response_model=ScopePut)
async def company_scope(
    instance_id: UUID, company_id: UUID, payload: ScopePut, ctx: Ctx
) -> ModuleCompanyScope:
    return await service.scope(ctx, instance_id, company_id, payload.status, list(payload.operations))


@router.post(
    "/platform/module-instances/{instance_id}/commands/{operation}",
    response_model=CommandView,
    status_code=201,
)
async def command_create(
    instance_id: UUID, operation: Literal["ping", "get_status"], payload: CommandCreate, ctx: Ctx
) -> ModuleCommand:
    return await service.queue(ctx, instance_id, operation, payload.expires_in_seconds)


@router.get("/platform/module-instances/{instance_id}/commands", response_model=Page[CommandView])
async def commands(instance_id: UUID, ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx)
    await service.get_instance(ctx, instance_id)
    return await page(
        ctx,
        select(ModuleCommand)
        .where(ModuleCommand.instance_id == instance_id)
        .order_by(ModuleCommand.created_at.desc(), ModuleCommand.id),
        limit,
        offset,
    )


@router.post("/module-agent/check-in", response_model=CheckInView)
async def check_in(payload: CheckIn, ctx: Machine) -> CheckInView:
    return await service.check_in(ctx, payload)


@router.post("/module-agent/commands/{command_id}/ack", response_model=CommandView)
async def acknowledge(command_id: UUID, payload: Acknowledgement, ctx: Machine) -> ModuleCommand:
    return await service.acknowledge(ctx, command_id, payload)


@router.get("/module-agent/instances/{instance_id}/companies/{company_id}", response_model=CompanyMetadata)
async def metadata(instance_id: UUID, company_id: UUID, ctx: Machine) -> CompanyMetadata:
    value = await machine.company(ctx, instance_id, company_id, "core.modules.metadata.read")
    return CompanyMetadata(company_id=value.id, name=value.name)
