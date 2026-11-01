import math
import time
from dataclasses import dataclass, field
from typing import Any, Never
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.domains.audit.model import AuditEvent
from app.domains.companies.model import Company
from app.domains.identity.model import Identity
from app.domains.memberships.model import Membership
from app.domains.platform.model import PlatformAdmin, PlatformSettings
from app.domains.users.model import User


def fail(status: int, code: str) -> Never:
    raise HTTPException(status, detail={"code": code})


@dataclass
class Context:
    session: AsyncSession = field(repr=False)
    identity: Identity
    user: User
    config: Settings = field(repr=False)
    claims: dict[str, Any] = field(repr=False)
    request_id: str | None = None
    operator: bool = False


async def mutation_gate(session: AsyncSession) -> PlatformSettings:
    value = await session.scalar(select(PlatformSettings).where(PlatformSettings.id == 1).with_for_update())
    if value is None:
        fail(503, "platform_migration_required")
    return value


def require_human(ctx: Context) -> None:
    if ctx.user.status != "active":
        fail(403, "user_suspended")
    if ctx.identity.principal_type != "human":
        fail(403, "human_principal_required")


def require_mfa(ctx: Context) -> None:
    acr, authenticated = ctx.claims.get("acr"), ctx.claims.get("auth_time")
    if (
        not ctx.config.admin_acr_values
        or not isinstance(acr, str)
        or acr not in ctx.config.admin_acr_values
        or not isinstance(authenticated, (int, float))
        or isinstance(authenticated, bool)
        or not math.isfinite(authenticated)
        or not -ctx.config.oidc_leeway_seconds
        <= time.time() - authenticated
        <= ctx.config.admin_auth_max_age_seconds
    ):
        fail(403, "configured_recent_mfa_required")


async def require_platform(ctx: Context) -> None:
    require_human(ctx)
    admin = await ctx.session.get(PlatformAdmin, ctx.user.id)
    if admin is None or not admin.active:
        fail(403, "platform_admin_required")
    require_mfa(ctx)


PERMISSIONS: dict[str, set[str]] = {
    "company.read": {"owner", "admin", "member"},
    "company.manage": {"owner"},
    "members.read": {"owner", "admin", "member"},
    "members.manage": {"owner", "admin"},
    "employees.read": {"owner", "admin", "member"},
    "employees.manage": {"owner", "admin"},
    "invitations.manage": {"owner", "admin"},
    "ownership.transfer": {"owner"},
}


async def require_company(
    ctx: Context, company_id: UUID, permission: str, *, allow_inactive: bool = False
) -> tuple[Company, Membership]:
    require_human(ctx)
    member = await ctx.session.scalar(
        select(Membership).where(
            Membership.company_id == company_id,
            Membership.user_id == ctx.user.id,
            Membership.status == "active",
        )
    )
    company = await ctx.session.get(Company, company_id) if member else None
    if company is None or member is None:
        fail(404, "company_not_found")
    if member.role not in PERMISSIONS.get(permission, set()):
        fail(403, "company_permission_denied")
    if company.status != "active" and not allow_inactive:
        fail(403, "company_not_active")
    return company, member


async def human_user(session: AsyncSession, user_id: UUID) -> User:
    user = await session.get(User, user_id)
    human = await session.scalar(
        select(Identity.id).where(Identity.user_id == user_id, Identity.principal_type == "human").limit(1)
    )
    if user is None or user.status != "active" or human is None:
        fail(409, "active_human_user_required")
    return user


def audit(
    ctx: Context,
    action: str,
    resource_type: str,
    resource_id: UUID | None = None,
    company_id: UUID | None = None,
    **details: str | int | bool | None,
) -> None:
    # Call sites pass only a small, explicit metadata allowlist; never request bodies/claims.
    ctx.session.add(
        AuditEvent(
            actor_user_id=None if ctx.operator else ctx.user.id,
            actor_identity_id=None if ctx.operator else ctx.identity.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            company_id=company_id,
            request_id=ctx.request_id,
            details=details | {"actor_kind": "operator" if ctx.operator else "user"},
        )
    )
