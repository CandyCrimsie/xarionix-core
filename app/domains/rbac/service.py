from typing import Any
from uuid import UUID

from sqlalchemy import delete, func, select

from app.core.access import Context, audit, fail, human_user
from app.domains.memberships.model import Membership
from app.domains.rbac import authorization
from app.domains.rbac.model import (
    MembershipRole,
    Permission,
    PermissionDelegation,
    Role,
    RolePermission,
    RoleTemplate,
)


async def role(ctx: Context, company_id: UUID, role_id: UUID) -> Role:
    value = await ctx.session.scalar(
        select(Role)
        .where(Role.company_id == company_id, Role.id == role_id)
        .execution_options(populate_existing=True)
    )
    if value is None:
        fail(404, "role_not_found")
    return value


async def member(ctx: Context, company_id: UUID, member_id: UUID) -> Membership:
    value = await ctx.session.scalar(
        select(Membership)
        .where(Membership.company_id == company_id, Membership.id == member_id)
        .execution_options(populate_existing=True)
    )
    if value is None:
        fail(404, "membership_not_found")
    return value


async def permissions(ctx: Context, value: Role) -> set[str]:
    return set(
        (
            await ctx.session.scalars(
                select(RolePermission.permission_key).where(
                    RolePermission.company_id == value.company_id, RolePermission.role_id == value.id
                )
            )
        ).all()
    )


def editable(value: Role, expected_version: int | None = None) -> None:
    if value.is_system:
        fail(403, "system_role_protected")
    if expected_version is not None and expected_version != value.version:
        fail(409, "role_version_conflict")


async def replace_permissions(ctx: Context, value: Role, requested: set[str]) -> None:
    await ctx.session.execute(
        delete(RolePermission).where(
            RolePermission.company_id == value.company_id, RolePermission.role_id == value.id
        )
    )
    for key in sorted(requested):
        permission = await ctx.session.get(Permission, key)
        if permission is None:
            fail(422, "unknown_or_unavailable_permission")
        ctx.session.add(
            RolePermission(
                company_id=value.company_id,
                role_id=value.id,
                permission_key=key,
                permission_generation=permission.definition_generation,
            )
        )


async def create_role(
    ctx: Context,
    company_id: UUID,
    *,
    code: str,
    name: str,
    description: str | None,
    requested: set[str],
    template_key: str | None = None,
    template_version: int = 1,
) -> Role:
    await authorization.require(ctx, company_id, "core.roles.create")
    if template_key:
        if requested:
            fail(422, "template_or_permissions_required")
        template = await ctx.session.get(RoleTemplate, (template_key, template_version))
        if template is None:
            fail(404, "role_template_not_found")
        requested = set(template.permissions)
    await authorization.require_grantable(ctx, company_id, requested)
    if (
        await ctx.session.scalar(select(func.count()).select_from(Role).where(Role.company_id == company_id))
        or 0
    ) >= 200:
        fail(409, "company_role_limit_reached")
    if await ctx.session.scalar(select(Role.id).where(Role.company_id == company_id, Role.code == code)):
        fail(409, "role_code_unavailable")
    value = Role(
        company_id=company_id,
        code=code,
        name=name,
        description=description,
        created_by_user_id=ctx.user.id,
        is_system=False,
        active=True,
        version=1,
        definition_version=1,
    )
    ctx.session.add(value)
    await ctx.session.flush()
    await replace_permissions(ctx, value, requested)
    audit(
        ctx,
        "role.created",
        "role",
        value.id,
        company_id,
        template=template_key,
        permission_count=len(requested),
    )
    await ctx.session.flush()
    return value


async def update_role(
    ctx: Context, company_id: UUID, role_id: UUID, fields: dict[str, Any], expected_version: int
) -> Role:
    await authorization.require(ctx, company_id, "core.roles.manage")
    value = await role(ctx, company_id, role_id)
    editable(value, expected_version)
    await authorization.require_grantable(ctx, company_id, await permissions(ctx, value))
    if not fields or set(fields) - {"name", "description", "active"}:
        fail(422, "invalid_role_fields")
    for key, item in fields.items():
        setattr(value, key, item)
    value.version += 1
    audit(ctx, "role.updated", "role", value.id, company_id, version=value.version)
    await ctx.session.flush()
    return value


async def set_permissions(
    ctx: Context, company_id: UUID, role_id: UUID, requested: set[str], expected_version: int
) -> Role:
    decision = await authorization.require(ctx, company_id, "core.roles.manage")
    value = await role(ctx, company_id, role_id)
    editable(value, expected_version)
    current = await permissions(ctx, value)
    # Stale/inactive module grants can be removed, but cannot be silently re-approved.
    available_current = set(
        (
            await ctx.session.scalars(
                select(Permission.key).where(
                    Permission.key.in_(current),
                    Permission.active.is_(True),
                    func.core_module_available(Permission.namespace, ctx.config.modules_stale_seconds),
                )
            )
        ).all()
    )
    await authorization.require_grantable(ctx, company_id, available_current | requested)
    if requested - current:
        own = await ctx.session.scalar(
            select(MembershipRole.role_id).where(
                MembershipRole.company_id == company_id,
                MembershipRole.membership_id == decision.member.id,
                MembershipRole.role_id == role_id,
            )
        )
        if own is not None and decision.member.role != "owner":
            fail(403, "self_role_expansion_denied")
    await replace_permissions(ctx, value, requested)
    value.version += 1
    audit(
        ctx,
        "role.permissions_changed",
        "role",
        value.id,
        company_id,
        permission_count=len(requested),
        version=value.version,
    )
    await ctx.session.flush()
    return value


async def delete_role(ctx: Context, company_id: UUID, role_id: UUID) -> None:
    await authorization.require(ctx, company_id, "core.roles.manage")
    value = await role(ctx, company_id, role_id)
    editable(value)
    await authorization.require_grantable(ctx, company_id, await permissions(ctx, value))
    if await ctx.session.scalar(
        select(MembershipRole.role_id)
        .where(MembershipRole.company_id == company_id, MembershipRole.role_id == role_id)
        .limit(1)
    ):
        fail(409, "role_has_assignments")
    # Invitation FK also deliberately blocks deletion while a saved invitation
    # refers to this role. Revocation can instead deactivate its definition.
    await replace_permissions(ctx, value, set())
    await ctx.session.delete(value)
    audit(ctx, "role.deleted", "role", role_id, company_id)
    await ctx.session.flush()


async def assign(
    ctx: Context, company_id: UUID, member_id: UUID, role_id: UUID, *, revoke: bool = False
) -> None:
    decision = await authorization.require(
        ctx, company_id, "core.roles.revoke" if revoke else "core.roles.assign"
    )
    await authorization.require(ctx, company_id, "core.members.roles.assign")
    target = await member(ctx, company_id, member_id)
    if target.role == "owner" and decision.member.role != "owner":
        fail(403, "owner_required")
    if target.status != "active":
        fail(409, "active_membership_required")
    await human_user(ctx.session, target.user_id)
    value = await role(ctx, company_id, role_id)
    editable(value)
    if not revoke and not value.active:
        fail(409, "role_unavailable")
    await authorization.require_grantable(ctx, company_id, await permissions(ctx, value))
    identity = (company_id, member_id, role_id)
    existing = await ctx.session.get(MembershipRole, identity)
    if revoke:
        if existing is None:
            fail(409, "role_not_assigned")
        await ctx.session.delete(existing)
    else:
        if existing is not None:
            fail(409, "role_already_assigned")
        count = await ctx.session.scalar(
            select(func.count())
            .select_from(MembershipRole)
            .where(MembershipRole.company_id == company_id, MembershipRole.membership_id == member_id)
        )
        if (count or 0) >= 50:
            fail(409, "membership_role_limit_reached")
        ctx.session.add(
            MembershipRole(company_id=company_id, membership_id=member_id, role_id=role_id, origin="custom")
        )
    audit(
        ctx,
        "role.revoked" if revoke else "role.assigned",
        "role",
        role_id,
        company_id,
        membership_id=str(member_id),
    )
    await ctx.session.flush()


async def set_delegation(ctx: Context, company_id: UUID, member_id: UUID, requested: set[str]) -> None:
    await authorization.require(ctx, company_id, "core.permissions.delegate")
    target = await member(ctx, company_id, member_id)
    if target.status != "active" or target.role == "owner":
        fail(409, "delegation_requires_active_non_owner")
    await human_user(ctx.session, target.user_id)
    await authorization.require_grantable(ctx, company_id, requested)
    await ctx.session.execute(
        delete(PermissionDelegation).where(
            PermissionDelegation.company_id == company_id, PermissionDelegation.membership_id == member_id
        )
    )
    for key in sorted(requested):
        permission = await ctx.session.get(Permission, key)
        if permission is None:
            fail(422, "unknown_or_unavailable_permission")
        ctx.session.add(
            PermissionDelegation(
                company_id=company_id,
                membership_id=member_id,
                permission_key=key,
                permission_generation=permission.definition_generation,
            )
        )
    audit(
        ctx,
        "permission.delegation_changed",
        "membership",
        member_id,
        company_id,
        permission_count=len(requested),
    )
    await ctx.session.flush()
