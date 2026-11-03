"""One deny-by-default engine. Database state, not IdP roles, grants authority."""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, select

from app.core import locking
from app.core.access import Context, fail, require_human
from app.domains.companies.model import Company
from app.domains.memberships.model import Membership
from app.domains.rbac.catalog_v1 import MEMBER
from app.domains.rbac.model import (
    MembershipRole,
    Permission,
    PermissionDelegation,
    PermissionNamespace,
    Role,
    RolePermission,
)


@dataclass(frozen=True)
class Decision:
    company: Company
    member: Membership
    permissions: frozenset[str]


async def effective(ctx: Context, company_id: UUID, *, allow_inactive: bool = False) -> Decision:
    await locking.company(ctx.session, company_id, shared=not ctx.mutating)
    await ctx.session.refresh(ctx.user)
    require_human(ctx)
    member = await ctx.session.scalar(
        select(Membership)
        .where(
            Membership.company_id == company_id,
            Membership.user_id == ctx.user.id,
            Membership.status == "active",
        )
        .execution_options(populate_existing=True)
    )
    company = await ctx.session.get(Company, company_id, populate_existing=True) if member else None
    if company is None or member is None:
        fail(404, "company_not_found")
    if company.status != "active" and not (allow_inactive and member.role == "owner"):
        fail(403, "company_not_active")
    permissions = await ctx.session.scalars(
        select(Permission.key)
        .join(PermissionNamespace, PermissionNamespace.name == Permission.namespace)
        .join(RolePermission, RolePermission.permission_key == Permission.key)
        .join(Role, (Role.id == RolePermission.role_id) & (Role.company_id == RolePermission.company_id))
        .join(
            MembershipRole,
            (MembershipRole.role_id == Role.id) & (MembershipRole.company_id == Role.company_id),
        )
        .where(
            MembershipRole.company_id == company_id,
            MembershipRole.membership_id == member.id,
            Role.active.is_(True),
            Permission.active.is_(True),
            PermissionNamespace.state == "active",
            Permission.scope == "company",
            RolePermission.permission_generation == Permission.definition_generation,
            func.core_module_available(Permission.namespace, ctx.config.modules_stale_seconds),
        )
    )
    return Decision(company, member, frozenset(permissions.all()))


async def require(
    ctx: Context, company_id: UUID, permission: str, *, allow_inactive: bool = False
) -> Decision:
    decision = await effective(ctx, company_id, allow_inactive=allow_inactive)
    if permission not in decision.permissions:
        fail(403, "company_permission_denied")
    if (
        permission in {"core.company.manage", "core.ownership.transfer", "core.permissions.delegate"}
        and decision.member.role != "owner"
    ):
        fail(403, "owner_required")
    return decision


async def require_grantable(
    ctx: Context, company_id: UUID, requested: set[str], *, legacy_member_invitation: bool = False
) -> Decision:
    decision = await effective(ctx, company_id)
    available = (
        list(
            (
                await ctx.session.scalars(
                    select(Permission)
                    .join(PermissionNamespace, PermissionNamespace.name == Permission.namespace)
                    .where(
                        Permission.key.in_(requested),
                        Permission.active.is_(True),
                        Permission.scope == "company",
                        PermissionNamespace.state == "active",
                        func.core_module_available(Permission.namespace, ctx.config.modules_stale_seconds),
                    )
                )
            ).all()
        )
        if requested
        else []
    )
    if {item.key for item in available} != requested:
        fail(422, "unknown_or_unavailable_permission")
    if any(item.protected for item in available):
        fail(403, "protected_permission")
    if decision.member.role == "owner":
        allowed = {item.key for item in available if item.owner_grantable}
    else:
        grants = await ctx.session.scalars(
            select(PermissionDelegation.permission_key)
            .join(Permission, Permission.key == PermissionDelegation.permission_key)
            .where(
                PermissionDelegation.company_id == company_id,
                PermissionDelegation.membership_id == decision.member.id,
                PermissionDelegation.permission_generation == Permission.definition_generation,
            )
        )
        allowed = set(grants.all()) & decision.permissions
        # Explicit Sprint 2 compatibility: Admin can still invite a standard
        # Member. This does NOT authorize custom grants or role administration.
        if legacy_member_invitation and decision.member.role == "admin" and requested <= MEMBER:
            allowed |= MEMBER & decision.permissions
    if not requested <= allowed:
        fail(403, "permission_not_grantable")
    return decision
