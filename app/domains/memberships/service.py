from uuid import UUID

from sqlalchemy import func, select

from app.core.access import Context, audit, fail, human_user, mutation_gate, require_company
from app.domains.companies.service import check_quota
from app.domains.memberships.model import Membership


async def scoped_member(ctx: Context, company_id: UUID, member_id: UUID) -> Membership:
    member = await ctx.session.scalar(
        select(Membership).where(Membership.id == member_id, Membership.company_id == company_id)
    )
    if member is None:
        fail(404, "membership_not_found")
    return member


async def protect_owner(ctx: Context, target: Membership, role: str, status: str) -> None:
    if target.role == "owner" and target.status == "active" and (role != "owner" or status != "active"):
        count = await ctx.session.scalar(
            select(func.count())
            .select_from(Membership)
            .where(
                Membership.company_id == target.company_id,
                Membership.role == "owner",
                Membership.status == "active",
            )
        )
        if (count or 0) <= 1:
            fail(409, "last_company_owner")


async def update_member(
    ctx: Context,
    company_id: UUID,
    member_id: UUID,
    *,
    role: str | None = None,
    status: str | None = None,
    leaving: bool = False,
) -> Membership:
    await mutation_gate(ctx.session)
    _, actor = await require_company(ctx, company_id, "company.read" if leaving else "members.manage")
    target = await scoped_member(ctx, company_id, member_id)
    if leaving:
        if target.user_id != ctx.user.id:
            fail(404, "membership_not_found")
        status = "removed"
    elif actor.role != "owner" and (target.role in {"owner", "admin"} or role in {"owner", "admin"}):
        fail(403, "owner_required")
    next_role, next_status = role or target.role, status or target.status
    if next_status != "removed":
        await human_user(ctx.session, target.user_id)
    await protect_owner(ctx, target, next_role, next_status)
    if (
        next_role == "owner"
        and next_status != "removed"
        and (target.role != "owner" or target.status == "removed")
    ):
        await check_quota(ctx, target.user_id)
    target.role, target.status = next_role, next_status
    audit(ctx, "membership.changed", "membership", target.id, company_id, role=next_role, status=next_status)
    await ctx.session.flush()
    return target


async def transfer(ctx: Context, company_id: UUID, target_id: UUID) -> Membership:
    await mutation_gate(ctx.session)
    _, actor = await require_company(ctx, company_id, "ownership.transfer")
    target = await scoped_member(ctx, company_id, target_id)
    if target.id == actor.id or target.status != "active":
        fail(409, "invalid_ownership_target")
    await human_user(ctx.session, target.user_id)
    if target.role != "owner":
        await check_quota(ctx, target.user_id)
    target.role, actor.role = "owner", "admin"
    audit(ctx, "ownership.transferred", "membership", target.id, company_id)
    await ctx.session.flush()
    return target
