"""Verified machine binding, never JIT User/Membership or human delegation."""

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access import fail
from app.core.config import Settings
from app.domains.audit.model import AuditEvent
from app.domains.companies.model import Company
from app.domains.modules.model import ModuleCompanyScope, ModuleInstance, ModuleService


@dataclass
class MachineContext:
    session: AsyncSession = field(repr=False)
    config: Settings = field(repr=False)
    claims: dict[str, Any] = field(repr=False)
    request_id: str


def binding(claims: dict[str, Any]) -> tuple[str, str, str]:
    issuer, subject, client_id = claims.get("iss"), claims.get("sub"), claims.get("azp")
    if (
        claims.get("xarionix_principal") != "machine"
        or not isinstance(issuer, str)
        or not 1 <= len(issuer) <= 512
        or not isinstance(subject, str)
        or not 1 <= len(subject) <= 255
        or not isinstance(client_id, str)
        or not 1 <= len(client_id) <= 120
        or ("client_id" in claims and claims["client_id"] != client_id)
    ):
        fail(403, "machine_binding_invalid")
    return issuer, subject, client_id


async def require(
    ctx: MachineContext, instance_id: UUID, operation: str, *, write: bool = True
) -> tuple[ModuleService, ModuleInstance]:
    issuer, subject, client_id = binding(ctx.claims)
    service = await ctx.session.scalar(
        select(ModuleService)
        .where(
            ModuleService.issuer == issuer,
            ModuleService.subject == subject,
            ModuleService.client_id == client_id,
        )
        .with_for_update(read=True)
        .execution_options(populate_existing=True)
    )
    if service is None or service.status != "active":
        fail(403, "machine_service_unavailable")
    instance = await ctx.session.scalar(
        select(ModuleInstance)
        .where(ModuleInstance.id == instance_id, ModuleInstance.service_id == service.id)
        .with_for_update(read=not write)
        .execution_options(populate_existing=True)
    )
    if instance is None:
        fail(404, "module_instance_not_found")
    if instance.status != "active":
        fail(403, "module_instance_unavailable")
    if operation not in service.operations:
        fail(403, "machine_operation_denied")
    return service, instance


async def company(ctx: MachineContext, instance_id: UUID, company_id: UUID, operation: str) -> Company:
    await require(ctx, instance_id, operation, write=False)
    scope = await ctx.session.scalar(
        select(ModuleCompanyScope)
        .where(ModuleCompanyScope.instance_id == instance_id, ModuleCompanyScope.company_id == company_id)
        .with_for_update(read=True)
        .execution_options(populate_existing=True)
    )
    if scope is None or scope.status != "active" or operation not in scope.operations:
        fail(404, "module_company_scope_not_found")
    value = await ctx.session.get(Company, company_id, populate_existing=True)
    if value is None or value.status != "active":
        fail(404, "module_company_scope_not_found")
    return value


def audit(ctx: MachineContext, action: str, instance: ModuleInstance, command_id: UUID | None = None) -> None:
    ctx.session.add(
        AuditEvent(
            action=action,
            resource_type="module_instance",
            resource_id=instance.id,
            request_id=ctx.request_id,
            details={
                "service_id": str(instance.service_id),
                "instance_id": str(instance.id),
                **({"command_id": str(command_id)} if command_id else {}),
            },
        )
    )
