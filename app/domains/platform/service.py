from typing import Any
from uuid import UUID

from sqlalchemy import func, select

from app.core import locking
from app.core.access import Context, audit, fail, human_user, mutation_gate, require_platform
from app.domains.identity.model import Identity
from app.domains.platform.model import PlatformAdmin, PlatformSettings
from app.domains.users.model import User


async def update_settings(ctx: Context, fields: dict[str, Any]) -> PlatformSettings:
    value = await mutation_gate(ctx.session)
    await require_platform(ctx)
    for key, item in fields.items():
        setattr(value, key, item)
    audit(ctx, "platform.settings_changed", "platform_settings", changed_fields=",".join(sorted(fields)))
    await ctx.session.flush()
    return value


async def assign_admin(ctx: Context, user_id: UUID, active: bool) -> PlatformAdmin:
    await locking.administration(ctx.session)
    await require_platform(ctx)
    await human_user(ctx.session, user_id)
    admin = await ctx.session.get(PlatformAdmin, user_id)
    if not active and admin and admin.active:
        count = await ctx.session.scalar(
            select(func.count())
            .select_from(PlatformAdmin)
            .join(User, User.id == PlatformAdmin.user_id)
            .where(PlatformAdmin.active.is_(True), User.status == "active")
        )
        if (count or 0) <= 1:
            fail(409, "last_platform_admin")
    if admin is None:
        if not active:
            fail(404, "platform_admin_not_found")
        admin = PlatformAdmin(user_id=user_id, active=True, granted_by_user_id=ctx.user.id)
        ctx.session.add(admin)
    else:
        admin.active = active
        if active:
            admin.granted_by_user_id = ctx.user.id
    audit(ctx, "platform_admin.granted" if active else "platform_admin.revoked", "user", user_id)
    await ctx.session.flush()
    return admin


async def classify(ctx: Context, identity_id: UUID, principal_type: str) -> Identity:
    await locking.administration(ctx.session)
    value = await ctx.session.get(Identity, identity_id)
    if value is None:
        fail(404, "identity_not_found")
    if principal_type != "human" and value.principal_type == "human":
        # Changing admission cannot silently strand owners or the last global admin.
        fail(409, "human_reclassification_requires_operator_review")
    value.principal_type = principal_type
    audit(ctx, "identity.classified", "identity", value.id, principal_type=principal_type)
    await ctx.session.flush()
    return value


async def set_user_status(ctx: Context, user_id: UUID, status: str) -> User:
    await locking.administration(ctx.session)
    await require_platform(ctx)
    value = await ctx.session.get(User, user_id)
    if value is None:
        fail(404, "user_not_found")
    value.status = status
    audit(ctx, "user.status_changed", "user", user_id, status=status)
    await ctx.session.flush()
    # Last usable owner/admin constraints run at the outer transaction COMMIT.
    return value
