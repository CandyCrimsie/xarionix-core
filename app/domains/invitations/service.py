import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from app.core.access import Context, audit, fail, human_user, mutation_gate, require_company, require_human
from app.domains.companies.model import Company
from app.domains.invitations.model import Invitation
from app.domains.memberships.model import Membership


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


async def issue(
    ctx: Context,
    company_id: UUID,
    *,
    role: str,
    hours: int,
    recipient_user_id: UUID | None,
    recipient_email: str | None,
) -> tuple[Invitation, str]:
    settings = await mutation_gate(ctx.session)
    _, actor = await require_company(ctx, company_id, "invitations.manage")
    if not settings.invitations_enabled:
        fail(403, "invitations_disabled")
    if role not in {"admin", "member"} or (role == "admin" and actor.role != "owner"):
        fail(403, "invitation_role_denied")
    if recipient_user_id:
        await human_user(ctx.session, recipient_user_id)
    secret = secrets.token_urlsafe(32)
    invitation = Invitation(
        company_id=company_id,
        created_by_user_id=ctx.user.id,
        role=role,
        token_hash=digest(secret),
        expires_at=datetime.now(UTC) + timedelta(hours=hours),
        recipient_user_id=recipient_user_id,
        recipient_email=recipient_email,
    )
    ctx.session.add(invitation)
    await ctx.session.flush()
    audit(ctx, "invitation.issued", "invitation", invitation.id, company_id, role=role)
    return invitation, secret


async def accept(ctx: Context, company_id: UUID, secret: str) -> Membership:
    require_human(ctx)
    settings = await mutation_gate(ctx.session)
    if not settings.invitations_enabled:
        fail(403, "invitations_disabled")
    invitation = await ctx.session.scalar(
        select(Invitation)
        .where(Invitation.company_id == company_id, Invitation.token_hash == digest(secret))
        .with_for_update()
    )
    if invitation is None:
        fail(404, "invitation_not_found")
    now = datetime.now(UTC)
    if invitation.status != "pending" or invitation.expires_at <= now:
        fail(409, "invitation_unavailable")
    if invitation.recipient_user_id and invitation.recipient_user_id != ctx.user.id:
        fail(403, "invitation_recipient_mismatch")
    if invitation.recipient_email:
        email = ctx.claims.get("email")
        if (
            ctx.claims.get("email_verified") is not True
            or not isinstance(email, str)
            or email.strip().casefold() != invitation.recipient_email
        ):
            fail(403, "verified_recipient_email_required")
    company = await ctx.session.get(Company, company_id)
    if company is None or company.status != "active":
        fail(409, "company_not_active")
    # Revoked/demoted issuers cannot leave a latent privilege-escalation invitation.
    issuer = await ctx.session.scalar(
        select(Membership).where(
            Membership.company_id == company_id,
            Membership.user_id == invitation.created_by_user_id,
            Membership.status == "active",
        )
    )
    if (
        issuer is None
        or issuer.role not in {"owner", "admin"}
        or (invitation.role == "admin" and issuer.role != "owner")
    ):
        fail(409, "invitation_issuer_no_longer_authorized")
    await human_user(ctx.session, invitation.created_by_user_id)
    member = await ctx.session.scalar(
        select(Membership).where(Membership.company_id == company_id, Membership.user_id == ctx.user.id)
    )
    if member is not None and member.status != "removed":
        fail(409, "membership_already_exists")
    if member is None:
        member = Membership(company_id=company_id, user_id=ctx.user.id, role=invitation.role, status="active")
        ctx.session.add(member)
    else:
        member.role, member.status, member.joined_at = invitation.role, "active", now
    invitation.status, invitation.used_at, invitation.used_by_user_id = "accepted", now, ctx.user.id
    await ctx.session.flush()
    audit(ctx, "invitation.accepted", "invitation", invitation.id, company_id)
    audit(ctx, "membership.joined", "membership", member.id, company_id, role=member.role)
    return member


async def revoke(ctx: Context, company_id: UUID, invitation_id: UUID) -> Invitation:
    await mutation_gate(ctx.session)
    await require_company(ctx, company_id, "invitations.manage")
    invitation = await ctx.session.scalar(
        select(Invitation).where(Invitation.id == invitation_id, Invitation.company_id == company_id)
    )
    if invitation is None:
        fail(404, "invitation_not_found")
    if invitation.status != "pending":
        fail(409, "invitation_unavailable")
    invitation.status = "revoked"
    audit(ctx, "invitation.revoked", "invitation", invitation.id, company_id)
    await ctx.session.flush()
    return invitation
