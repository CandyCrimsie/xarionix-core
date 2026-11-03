from typing import Any
from uuid import UUID

from fastapi import APIRouter, Response
from sqlalchemy import func, select

from app.api.v1.dependencies import Ctx, Limit, Offset
from app.api.v1.rbac_schemas import (
    PermissionSet,
    PermissionView,
    RoleAssignment,
    RoleCreate,
    RolePatch,
    RolePermissionsPatch,
    RoleView,
    TemplateView,
)
from app.api.v1.schemas import Page
from app.api.v1.tenants import page
from app.core.access import require_human
from app.domains.rbac import authorization, service
from app.domains.rbac.model import (
    MembershipRole,
    Permission,
    PermissionDelegation,
    PermissionNamespace,
    Role,
    RoleTemplate,
)

router = APIRouter(prefix="/api/v1")


@router.get("/permissions", response_model=Page[PermissionView])
async def catalog(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    require_human(ctx)
    return await page(
        ctx,
        select(Permission)
        .join(PermissionNamespace)
        .where(
            Permission.active.is_(True),
            PermissionNamespace.state == "active",
            func.core_module_available(Permission.namespace, ctx.config.modules_stale_seconds),
        )
        .order_by(Permission.key),
        limit,
        offset,
    )


@router.get("/role-templates", response_model=Page[TemplateView])
async def templates(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    require_human(ctx)
    return await page(
        ctx, select(RoleTemplate).order_by(RoleTemplate.key, RoleTemplate.version), limit, offset
    )


@router.get("/companies/{company_id}/roles", response_model=Page[RoleView])
async def roles(company_id: UUID, ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await authorization.require(ctx, company_id, "core.roles.read")
    return await page(
        ctx, select(Role).where(Role.company_id == company_id).order_by(Role.code, Role.id), limit, offset
    )


@router.post("/companies/{company_id}/roles", response_model=RoleView, status_code=201)
async def create_role(company_id: UUID, payload: RoleCreate, ctx: Ctx) -> Role:
    return await service.create_role(
        ctx,
        company_id,
        code=payload.code,
        name=payload.name,
        description=payload.description,
        requested=set(payload.permissions),
        template_key=payload.template_key,
        template_version=payload.template_version,
    )


@router.get("/companies/{company_id}/roles/{role_id}", response_model=RoleView)
async def role_detail(company_id: UUID, role_id: UUID, ctx: Ctx) -> Role:
    await authorization.require(ctx, company_id, "core.roles.read")
    return await service.role(ctx, company_id, role_id)


@router.patch("/companies/{company_id}/roles/{role_id}", response_model=RoleView)
async def edit_role(company_id: UUID, role_id: UUID, payload: RolePatch, ctx: Ctx) -> Role:
    return await service.update_role(
        ctx,
        company_id,
        role_id,
        payload.model_dump(exclude_unset=True, exclude={"expected_version"}),
        payload.expected_version,
    )


@router.delete("/companies/{company_id}/roles/{role_id}", status_code=204)
async def delete_role(company_id: UUID, role_id: UUID, ctx: Ctx) -> Response:
    await service.delete_role(ctx, company_id, role_id)
    return Response(status_code=204)


@router.get("/companies/{company_id}/roles/{role_id}/permissions")
async def role_permissions(company_id: UUID, role_id: UUID, ctx: Ctx) -> dict[str, Any]:
    await authorization.require(ctx, company_id, "core.roles.read")
    value = await service.role(ctx, company_id, role_id)
    return {"permissions": sorted(await service.permissions(ctx, value)), "version": value.version}


@router.put("/companies/{company_id}/roles/{role_id}/permissions", response_model=RoleView)
async def change_role_permissions(
    company_id: UUID, role_id: UUID, payload: RolePermissionsPatch, ctx: Ctx
) -> Role:
    return await service.set_permissions(
        ctx, company_id, role_id, set(payload.permissions), payload.expected_version
    )


@router.get("/companies/{company_id}/members/{membership_id}/roles", response_model=Page[RoleView])
async def member_roles(
    company_id: UUID, membership_id: UUID, ctx: Ctx, limit: Limit = 20, offset: Offset = 0
) -> dict[str, Any]:
    await authorization.require(ctx, company_id, "core.roles.read")
    await service.member(ctx, company_id, membership_id)
    return await page(
        ctx,
        select(Role)
        .join(
            MembershipRole,
            (MembershipRole.role_id == Role.id) & (MembershipRole.company_id == Role.company_id),
        )
        .where(Role.company_id == company_id, MembershipRole.membership_id == membership_id)
        .order_by(Role.code, Role.id),
        limit,
        offset,
    )


@router.post("/companies/{company_id}/members/{membership_id}/roles", status_code=204)
async def assign_role(company_id: UUID, membership_id: UUID, payload: RoleAssignment, ctx: Ctx) -> Response:
    await service.assign(ctx, company_id, membership_id, payload.role_id)
    return Response(status_code=204)


@router.delete("/companies/{company_id}/members/{membership_id}/roles/{role_id}", status_code=204)
async def revoke_role(company_id: UUID, membership_id: UUID, role_id: UUID, ctx: Ctx) -> Response:
    await service.assign(ctx, company_id, membership_id, role_id, revoke=True)
    return Response(status_code=204)


@router.get("/companies/{company_id}/members/{membership_id}/delegation", response_model=PermissionSet)
async def delegation(company_id: UUID, membership_id: UUID, ctx: Ctx) -> PermissionSet:
    await authorization.require(ctx, company_id, "core.permissions.delegate")
    await service.member(ctx, company_id, membership_id)
    keys = await ctx.session.scalars(
        select(PermissionDelegation.permission_key).where(
            PermissionDelegation.company_id == company_id, PermissionDelegation.membership_id == membership_id
        )
    )
    return PermissionSet(permissions=sorted(keys.all()))


@router.put("/companies/{company_id}/members/{membership_id}/delegation", status_code=204)
async def update_delegation(
    company_id: UUID, membership_id: UUID, payload: PermissionSet, ctx: Ctx
) -> Response:
    await service.set_delegation(ctx, company_id, membership_id, set(payload.permissions))
    return Response(status_code=204)


@router.get("/companies/{company_id}/me/permissions")
async def my_permissions(company_id: UUID, ctx: Ctx) -> dict[str, Any]:
    result = await authorization.effective(ctx, company_id)
    return {
        "company_id": company_id,
        "membership_id": result.member.id,
        "owner": result.member.role == "owner",
        "permissions": sorted(result.permissions),
    }
