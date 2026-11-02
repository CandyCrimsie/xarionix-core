import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, func, or_, select, text, update

from app.api.v1.module_schemas import (
    Acknowledgement,
    CheckIn,
    CheckInView,
    CommandDelivery,
    InstanceView,
    ServiceCreate,
)
from app.core import locking
from app.core.access import Context, audit, fail, require_platform
from app.domains.companies.model import Company
from app.domains.identity.model import Identity
from app.domains.modules import authorization as machine
from app.domains.modules.model import ModuleCommand, ModuleCompanyScope, ModuleInstance, ModuleService


def connection_state(service: ModuleService, instance: ModuleInstance, stale: int, now: datetime) -> str:
    if service.status == "revoked" or instance.status == "revoked":
        return "revoked"
    if service.status != "active" or instance.status != "active":
        return "disabled"
    if instance.last_seen is None or (now - instance.last_seen).total_seconds() > stale:
        return "stale"
    return "connected" if instance.health == "healthy" else "error"


def instance_view(ctx: Context, service: ModuleService, instance: ModuleInstance) -> InstanceView:
    values = {key: getattr(instance, key) for key in InstanceView.model_fields if key != "connection_state"}
    values["connection_state"] = connection_state(
        service, instance, ctx.config.modules_stale_seconds, datetime.now(UTC)
    )
    return InstanceView.model_validate(values)


async def get_service(ctx: Context, identifier: UUID, *, write: bool = False) -> ModuleService:
    value = await ctx.session.scalar(
        select(ModuleService)
        .where(ModuleService.id == identifier)
        .with_for_update(read=not write)
        .execution_options(populate_existing=True)
    )
    if value is None:
        fail(404, "module_service_not_found")
    return value


async def get_instance(
    ctx: Context, identifier: UUID, *, write: bool = False
) -> tuple[ModuleService, ModuleInstance]:
    preliminary = await ctx.session.get(ModuleInstance, identifier)
    if preliminary is None:
        fail(404, "module_instance_not_found")
    service = await get_service(ctx, preliminary.service_id)
    instance = await ctx.session.scalar(
        select(ModuleInstance)
        .where(ModuleInstance.id == identifier)
        .with_for_update(read=not write)
        .execution_options(populate_existing=True)
    )
    if instance is None:
        fail(404, "module_instance_not_found")
    return service, instance


async def register(ctx: Context, payload: ServiceCreate) -> ModuleService:
    await require_platform(ctx)
    if payload.issuer != ctx.config.oidc_issuer:
        fail(422, "module_issuer_not_trusted")
    key = int.from_bytes(
        hashlib.sha256((payload.issuer + "\0" + payload.subject).encode()).digest()[:8], signed=True
    )
    await ctx.session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
    if await ctx.session.scalar(
        select(Identity.id).where(Identity.issuer == payload.issuer, Identity.subject == payload.subject)
    ):
        fail(409, "legacy_identity_cannot_be_machine_binding")
    value = ModuleService(**payload.model_dump(), registered_by_user_id=ctx.user.id, status="active")
    ctx.session.add(value)
    await ctx.session.flush()
    audit(ctx, "module.service_registered", "module_service", value.id)
    return value


async def set_service_status(ctx: Context, identifier: UUID, status: str) -> ModuleService:
    await require_platform(ctx)
    value = await get_service(ctx, identifier, write=True)
    if value.status == "revoked" and status != "revoked":
        fail(409, "module_revocation_terminal")
    value.status = status
    audit(ctx, "module.service_" + status, "module_service", value.id)
    await ctx.session.flush()
    return value


async def create_instance(ctx: Context, identifier: UUID, installation_key: str) -> ModuleInstance:
    await require_platform(ctx)
    service = await get_service(ctx, identifier, write=True)
    if service.status != "active":
        fail(409, "module_service_unavailable")
    value = ModuleInstance(service_id=service.id, installation_key=installation_key, status="active")
    ctx.session.add(value)
    await ctx.session.flush()
    audit(ctx, "module.instance_registered", "module_instance", value.id)
    return value


async def scope(
    ctx: Context, instance_id: UUID, company_id: UUID, status: str, operations: list[str]
) -> ModuleCompanyScope:
    await require_platform(ctx)
    await locking.company(ctx.session, company_id, shared=True)
    await get_instance(ctx, instance_id, write=True)
    company = await ctx.session.get(Company, company_id, populate_existing=True)
    if company is None or company.status != "active":
        fail(404, "company_not_found")
    value = await ctx.session.get(ModuleCompanyScope, (instance_id, company_id))
    if value is None:
        value = ModuleCompanyScope(instance_id=instance_id, company_id=company_id)
        ctx.session.add(value)
    value.status, value.operations = status, operations
    audit(ctx, "module.scope_changed", "module_instance", instance_id, company_id, status=status)
    await ctx.session.flush()
    return value


async def queue(ctx: Context, instance_id: UUID, operation: str, expires: int) -> ModuleCommand:
    await require_platform(ctx)
    service, instance = await get_instance(ctx, instance_id, write=True)
    if service.status != "active" or instance.status != "active":
        fail(409, "module_instance_unavailable")
    if not {"core.modules.commands.read", "core.modules.commands.ack"} <= set(service.operations):
        fail(409, "module_command_capabilities_missing")
    now = datetime.now(UTC)
    count = await ctx.session.scalar(
        select(func.count())
        .select_from(ModuleCommand)
        .where(
            ModuleCommand.instance_id == instance_id,
            ModuleCommand.state.in_(["pending", "delivered"]),
            ModuleCommand.expires_at > now,
        )
    )
    if (count or 0) >= 100:
        fail(409, "module_command_queue_full")
    value = ModuleCommand(
        instance_id=instance_id,
        operation=operation,
        expires_at=now + timedelta(seconds=expires),
        request_id=ctx.request_id or "operator",
        created_by_user_id=ctx.user.id,
    )
    ctx.session.add(value)
    await ctx.session.flush()
    audit(
        ctx,
        "module.command_created",
        "module_command",
        value.id,
        instance_id=str(instance_id),
        operation=operation,
    )
    return value


async def check_in(ctx: machine.MachineContext, payload: CheckIn) -> CheckInView:
    service, instance = await machine.require(ctx, payload.instance_id, "core.modules.connect")
    if "core.modules.heartbeat" not in service.operations:
        fail(403, "machine_operation_denied")
    now = datetime.now(UTC)
    if instance.next_check_in_at is not None and now < instance.next_check_in_at:
        fail(429, "module_check_in_rate_limited")
    first = instance.last_seen is None
    instance.last_seen, instance.health = now, payload.health
    instance.agent_version, instance.protocol_version = payload.agent_version, payload.protocol_version
    instance.next_check_in_at = now + timedelta(seconds=ctx.config.modules_check_in_seconds)
    if first:
        machine.audit(ctx, "module.connected", instance)
    deliveries: list[CommandDelivery] = []
    if "core.modules.commands.read" in service.operations:
        await ctx.session.execute(
            update(ModuleCommand)
            .where(
                ModuleCommand.instance_id == instance.id,
                ModuleCommand.state.in_(["pending", "delivered"]),
                or_(
                    ModuleCommand.expires_at <= now,
                    and_(ModuleCommand.attempts >= 5, ModuleCommand.lease_until <= now),
                ),
            )
            .values(state="expired")
        )
        commands = list(
            (
                await ctx.session.scalars(
                    select(ModuleCommand)
                    .where(
                        ModuleCommand.instance_id == instance.id,
                        ModuleCommand.state.in_(["pending", "delivered"]),
                        ModuleCommand.expires_at > now,
                        ModuleCommand.attempts < 5,
                        or_(ModuleCommand.lease_until.is_(None), ModuleCommand.lease_until <= now),
                    )
                    .order_by(ModuleCommand.created_at, ModuleCommand.id)
                    .limit(10)
                    .with_for_update()
                )
            ).all()
        )
        for value in commands:
            if value.lease_until is None or value.lease_until <= now:
                value.attempts += 1
                value.state, value.lease_until = (
                    "delivered",
                    now + timedelta(seconds=ctx.config.modules_lease_seconds),
                )
                deliveries.append(
                    CommandDelivery(
                        id=value.id,
                        operation=value.operation,
                        expires_at=value.expires_at,
                        attempt=value.attempts,
                        request_id=value.request_id,
                    )
                )
                machine.audit(ctx, "module.command_delivered", instance, value.id)
    await ctx.session.flush()
    return CheckInView(
        instance_id=instance.id,
        connection_state="connected" if payload.health == "healthy" else "error",
        check_in_seconds=ctx.config.modules_check_in_seconds,
        server_time=now,
        commands=deliveries,
    )


async def acknowledge(
    ctx: machine.MachineContext, command_id: UUID, payload: Acknowledgement
) -> ModuleCommand:
    _, instance = await machine.require(ctx, payload.instance_id, "core.modules.commands.ack")
    value = await ctx.session.scalar(
        select(ModuleCommand)
        .where(ModuleCommand.id == command_id, ModuleCommand.instance_id == instance.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if value is None:
        fail(404, "module_command_not_found")
    result = payload.result.model_dump()
    if value.state == "completed":
        if result != value.result:
            fail(409, "module_ack_conflict")
        return value
    if value.expires_at <= datetime.now(UTC) or value.state != "delivered":
        fail(409, "module_command_not_deliverable")
    if result["kind"] not in ({"pong", "error"} if value.operation == "ping" else {"status", "error"}):
        fail(422, "module_result_operation_mismatch")
    value.result, value.state, value.completed_at = result, "completed", datetime.now(UTC)
    machine.audit(ctx, "module.command_completed", instance, value.id)
    await ctx.session.flush()
    return value
