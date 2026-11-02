import hashlib
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, select

from app.core import locking
from app.core.access import Context, audit, fail, human_user, require_company, require_human
from app.domains.companies.model import Company
from app.domains.identity.model import Identity
from app.domains.invitations.model import Invitation
from app.domains.memberships.model import Membership
from app.domains.rbac import authorization
from app.domains.rbac.model import InvitationRole, MembershipRole, Role, RolePermission
from app.domains.users.model import User


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
    role_ids: list[UUID] | None = None,
) -> tuple[Invitation, str]:
    settings = await locking.policy(ctx.session)
    _, actor = await require_company(ctx, company_id, "invitations.manage")
    if not settings.invitations_enabled:
        fail(403, "invitations_disabled")
    if role not in {"admin", "member"} or (role == "admin" and actor.role != "owner"):
        fail(403, "invitation_role_denied")
    requested = await invitation_permissions(ctx, company_id, role, role_ids or [])
    await authorization.require(ctx, company_id, "core.members.invite")
    await authorization.require_grantable(
        ctx, company_id, requested, legacy_member_invitation=role == "member" and not role_ids
    )
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
        permission_snapshot=sorted(requested),
    )
    ctx.session.add(invitation)
    await ctx.session.flush()
    for role_id in role_ids or []:
        ctx.session.add(InvitationRole(company_id=company_id, invitation_id=invitation.id, role_id=role_id))
    audit(ctx, "invitation.issued", "invitation", invitation.id, company_id, role=role)
    return invitation, secret


async def invitation_permissions(
    ctx: Context, company_id: UUID, legacy_role: str, role_ids: list[UUID]
) -> set[str]:
    base = await ctx.session.scalar(
        select(Role).where(Role.company_id == company_id, Role.code == legacy_role, Role.is_system.is_(True))
    )
    if base is None:
        fail(503, "rbac_migration_required")
    selected = [base.id]
    if role_ids:
        custom = list(
            (
                await ctx.session.scalars(
                    select(Role).where(Role.company_id == company_id, Role.id.in_(role_ids))
                )
            ).all()
        )
        if len(custom) != len(set(role_ids)):
            fail(404, "role_not_found")
        if any(item.is_system or not item.active for item in custom):
            fail(409, "invitation_role_unavailable")
        selected += [item.id for item in custom]
    return set(
        (
            await ctx.session.scalars(
                select(RolePermission.permission_key).where(
                    RolePermission.company_id == company_id, RolePermission.role_id.in_(selected)
                )
            )
        ).all()
    )


async def accept(ctx: Context, company_id: UUID, secret: str) -> Membership:
    require_human(ctx)
    settings = await locking.policy(ctx.session)
    await locking.quota(ctx.session, ctx.user.id)
    await locking.company(ctx.session, company_id)
    await ctx.session.refresh(ctx.user)
    require_human(ctx)
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
    if issuer is None or (invitation.role == "admin" and issuer.role != "owner"):
        fail(409, "invitation_issuer_no_longer_authorized")
    await human_user(ctx.session, invitation.created_by_user_id)
    issuer_user = await ctx.session.get(User, invitation.created_by_user_id, populate_existing=True)
    issuer_identity = await ctx.session.scalar(
        select(Identity)
        .where(Identity.user_id == invitation.created_by_user_id, Identity.principal_type == "human")
        .limit(1)
    )
    if issuer_user is None or issuer_identity is None:
        fail(409, "invitation_issuer_no_longer_authorized")
    issuer_context = replace(ctx, user=issuer_user, identity=issuer_identity)
    await authorization.require(issuer_context, company_id, "core.members.invite")
    await authorization.require(issuer_context, company_id, "core.invitations.manage")
    custom_role_ids = list(
        (
            await ctx.session.scalars(
                select(InvitationRole.role_id).where(
                    InvitationRole.company_id == company_id, InvitationRole.invitation_id == invitation.id
                )
            )
        ).all()
    )
    requested = await invitation_permissions(ctx, company_id, invitation.role, custom_role_ids)
    if invitation.permission_snapshot is not None and set(invitation.permission_snapshot) != requested:
        fail(409, "invitation_roles_changed")
    await authorization.require_grantable(
        issuer_context,
        company_id,
        requested,
        legacy_member_invitation=invitation.role == "member" and not custom_role_ids,
    )
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
    await ctx.session.execute(
        delete(MembershipRole).where(
            MembershipRole.company_id == company_id,
            MembershipRole.membership_id == member.id,
            MembershipRole.origin == "custom",
        )
    )
    for role_id in custom_role_ids:
        ctx.session.add(
            MembershipRole(company_id=company_id, membership_id=member.id, role_id=role_id, origin="custom")
        )
        audit(
            ctx,
            "role.assigned",
            "role",
            role_id,
            company_id,
            membership_id=str(member.id),
            invitation_id=str(invitation.id),
        )
    audit(ctx, "invitation.accepted", "invitation", invitation.id, company_id)
    audit(ctx, "membership.joined", "membership", member.id, company_id, role=member.role)
    return member


async def revoke(ctx: Context, company_id: UUID, invitation_id: UUID) -> Invitation:
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
