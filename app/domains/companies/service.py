from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select

from app.core import locking
from app.core.access import Context, audit, fail, human_user, require_human, require_platform
from app.domains.companies.model import Company, CompanyRequest
from app.domains.memberships.model import Membership


async def check_quota(ctx: Context, user_id: UUID, *, excluding: UUID | None = None) -> None:
    settings = await locking.policy(ctx.session)
    await locking.quota(ctx.session, user_id)
    query = (
        select(func.count())
        .select_from(Membership)
        .join(Company, Company.id == Membership.company_id)
        .where(
            Membership.user_id == user_id,
            Membership.role == "owner",
            Membership.status != "removed",
            Company.status != "archived",
        )
    )
    if excluding:
        query = query.where(Company.id != excluding)
    if (await ctx.session.scalar(query) or 0) >= settings.max_owned_companies_per_user:
        fail(409, "owned_company_limit_reached")


async def create_company(
    ctx: Context, name: str, slug: str, owner_id: UUID | None = None, *, approved: bool = False
) -> Company:
    settings = await locking.policy(ctx.session)
    require_human(ctx)
    owner_id = owner_id or ctx.user.id
    await human_user(ctx.session, owner_id)
    if not approved and settings.company_creation_policy != "open":
        await require_platform(ctx)
    await check_quota(ctx, owner_id)
    if await ctx.session.scalar(select(Company.id).where(Company.slug == slug)):
        fail(409, "company_slug_unavailable")
    company = Company(name=name, slug=slug, created_by_user_id=ctx.user.id)
    ctx.session.add(company)
    await ctx.session.flush()
    ctx.session.add(Membership(company_id=company.id, user_id=owner_id, role="owner", status="active"))
    audit(ctx, "company.created", "company", company.id, company.id)
    await ctx.session.flush()
    return company


async def request_company(ctx: Context, name: str, slug: str) -> CompanyRequest:
    require_human(ctx)
    settings = await locking.policy(ctx.session)
    if settings.company_creation_policy != "approval":
        fail(403, "company_requests_not_enabled")
    await check_quota(ctx, ctx.user.id)
    if await ctx.session.scalar(
        select(CompanyRequest.id).where(
            CompanyRequest.requested_by_user_id == ctx.user.id,
            CompanyRequest.status == "pending",
            CompanyRequest.requested_slug == slug,
        )
    ):
        fail(409, "request_already_pending")
    if await ctx.session.scalar(select(Company.id).where(Company.slug == slug)):
        fail(409, "company_slug_unavailable")
    value = CompanyRequest(name=name, requested_slug=slug, requested_by_user_id=ctx.user.id)
    ctx.session.add(value)
    await ctx.session.flush()
    audit(ctx, "company_request.created", "company_request", value.id)
    return value


async def review_request(
    ctx: Context, request_id: UUID, operation: str, comment: str | None = None
) -> CompanyRequest:
    await locking.policy(ctx.session)
    if operation != "cancel":
        await require_platform(ctx)
    else:
        require_human(ctx)
    value = await ctx.session.scalar(
        select(CompanyRequest).where(CompanyRequest.id == request_id).with_for_update()
    )
    if value is None or (operation == "cancel" and value.requested_by_user_id != ctx.user.id):
        fail(404, "request_not_found")
    if value.status != "pending":
        fail(409, "request_not_pending")
    if operation == "approve":
        # Authorization checked above; approval remains valid if policy subsequently closed.
        company = await create_company(
            ctx, value.name, value.requested_slug, value.requested_by_user_id, approved=True
        )
        value.company_id = company.id
    value.status = {"approve": "approved", "reject": "rejected", "cancel": "cancelled"}[operation]
    value.reviewed_at = datetime.now(UTC)
    value.reviewed_by_user_id = ctx.user.id
    value.review_comment = comment
    audit(ctx, "company_request." + value.status, "company_request", value.id, value.company_id)
    await ctx.session.flush()
    return value
