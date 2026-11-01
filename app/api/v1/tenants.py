from typing import Any
from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import Select, func, select

from app.api.v1.dependencies import Ctx, Limit, Offset
from app.api.v1.schemas import (
    AdminAssignment,
    AdminView,
    AuditView,
    CompanyCreate,
    CompanyPatch,
    CompanyView,
    EmployeeCreate,
    EmployeePatch,
    EmployeeView,
    InvitationAccept,
    InvitationCreate,
    InvitationIssued,
    InvitationView,
    MemberPatch,
    MemberView,
    OwnershipTransfer,
    Page,
    PrincipalPatch,
    RequestView,
    Review,
    SettingsPatch,
    SettingsView,
    UserStatusPatch,
    UserView,
)
from app.core.access import audit, fail, require_company, require_human, require_platform
from app.domains.audit.model import AuditEvent
from app.domains.companies.model import Company, CompanyRequest
from app.domains.companies.service import check_quota, create_company, request_company, review_request
from app.domains.employees.model import Employee
from app.domains.employees.service import get_employee, save_employee
from app.domains.invitations.model import Invitation
from app.domains.invitations.service import accept, issue, revoke
from app.domains.memberships.model import Membership
from app.domains.memberships.service import transfer, update_member
from app.domains.platform.model import PlatformAdmin, PlatformSettings
from app.domains.platform.service import assign_admin, classify, set_user_status, update_settings
from app.domains.users.model import User

router = APIRouter(prefix="/api/v1")


async def page[T](ctx: Ctx, query: Select[tuple[T]], limit: int, offset: int) -> dict[str, Any]:
    total = await ctx.session.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
    return {
        "items": list((await ctx.session.scalars(query.limit(limit).offset(offset))).all()),
        "total": total or 0,
        "limit": limit,
        "offset": offset,
    }


@router.get("/me/companies", response_model=Page[CompanyView])
@router.get("/companies", response_model=Page[CompanyView])
async def my_companies(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    require_human(ctx)
    return await page(
        ctx,
        select(Company)
        .join(Membership, Membership.company_id == Company.id)
        .where(Membership.user_id == ctx.user.id, Membership.status == "active")
        .order_by(Company.created_at, Company.id),
        limit,
        offset,
    )


@router.post("/companies", response_model=CompanyView, status_code=201)
async def new_company(payload: CompanyCreate, ctx: Ctx) -> Company:
    return await create_company(ctx, payload.name, payload.slug)


@router.get("/companies/{company_id}", response_model=CompanyView)
async def company_detail(company_id: UUID, ctx: Ctx) -> Company:
    value, _ = await require_company(ctx, company_id, "company.read")
    return value


@router.patch("/companies/{company_id}", response_model=CompanyView)
async def company_edit(company_id: UUID, payload: CompanyPatch, ctx: Ctx) -> Company:
    value, _ = await require_company(ctx, company_id, "company.manage", allow_inactive=True)
    if value.status == "archived" and payload.status and payload.status != "archived":
        owners = await ctx.session.scalars(
            select(Membership.user_id).where(
                Membership.company_id == company_id,
                Membership.role == "owner",
                Membership.status != "removed",
            )
        )
        for owner in owners:
            await check_quota(ctx, owner, excluding=company_id)
    for key, item in payload.model_dump(exclude_unset=True).items():
        setattr(value, key, item)
    audit(ctx, "company.changed", "company", company_id, company_id, status=value.status)
    await ctx.session.flush()
    return value


@router.post("/company-requests", response_model=RequestView, status_code=201)
async def new_request(payload: CompanyCreate, ctx: Ctx) -> CompanyRequest:
    return await request_company(ctx, payload.name, payload.slug)


@router.get("/company-requests/me", response_model=Page[RequestView])
async def my_requests(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    require_human(ctx)
    return await page(
        ctx,
        select(CompanyRequest)
        .where(CompanyRequest.requested_by_user_id == ctx.user.id)
        .order_by(CompanyRequest.created_at, CompanyRequest.id),
        limit,
        offset,
    )


@router.post("/company-requests/{request_id}/cancel", response_model=RequestView)
async def cancel_request(request_id: UUID, ctx: Ctx) -> CompanyRequest:
    return await review_request(ctx, request_id, "cancel")


@router.get("/companies/{company_id}/members", response_model=Page[MemberView])
async def members(company_id: UUID, ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_company(ctx, company_id, "members.read")
    return await page(
        ctx,
        select(Membership)
        .where(Membership.company_id == company_id)
        .order_by(Membership.created_at, Membership.id),
        limit,
        offset,
    )


@router.patch("/companies/{company_id}/members/{member_id}", response_model=MemberView)
async def edit_member(company_id: UUID, member_id: UUID, payload: MemberPatch, ctx: Ctx) -> Membership:
    return await update_member(ctx, company_id, member_id, **payload.model_dump(exclude_unset=True))


@router.delete("/companies/{company_id}/members/{member_id}", response_model=MemberView)
async def remove_member(company_id: UUID, member_id: UUID, ctx: Ctx) -> Membership:
    return await update_member(ctx, company_id, member_id, status="removed")


@router.post("/companies/{company_id}/leave", response_model=MemberView)
async def leave(company_id: UUID, ctx: Ctx) -> Membership:
    _, member = await require_company(ctx, company_id, "company.read")
    return await update_member(ctx, company_id, member.id, leaving=True)


@router.post("/companies/{company_id}/transfer-ownership", response_model=MemberView)
async def transfer_owner(company_id: UUID, payload: OwnershipTransfer, ctx: Ctx) -> Membership:
    return await transfer(ctx, company_id, payload.target_membership_id)


@router.get("/companies/{company_id}/employees", response_model=Page[EmployeeView])
async def employees(company_id: UUID, ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_company(ctx, company_id, "employees.read")
    return await page(
        ctx,
        select(Employee).where(Employee.company_id == company_id).order_by(Employee.created_at, Employee.id),
        limit,
        offset,
    )


@router.get("/companies/{company_id}/employees/{employee_id}", response_model=EmployeeView)
async def employee_detail(company_id: UUID, employee_id: UUID, ctx: Ctx) -> Employee:
    await require_company(ctx, company_id, "employees.read")
    return await get_employee(ctx, company_id, employee_id)


@router.post("/companies/{company_id}/employees", response_model=EmployeeView, status_code=201)
async def new_employee(company_id: UUID, payload: EmployeeCreate, ctx: Ctx) -> Employee:
    return await save_employee(ctx, company_id, payload.model_dump())


@router.patch("/companies/{company_id}/employees/{employee_id}", response_model=EmployeeView)
async def edit_employee(company_id: UUID, employee_id: UUID, payload: EmployeePatch, ctx: Ctx) -> Employee:
    return await save_employee(ctx, company_id, payload.model_dump(exclude_unset=True), employee_id)


@router.post("/companies/{company_id}/invitations", response_model=InvitationIssued, status_code=201)
async def new_invitation(company_id: UUID, payload: InvitationCreate, ctx: Ctx) -> InvitationIssued:
    value, secret = await issue(
        ctx,
        company_id,
        role=payload.role,
        hours=payload.expires_in_hours,
        recipient_user_id=payload.recipient_user_id,
        recipient_email=payload.recipient_email,
    )
    return InvitationIssued(invitation=InvitationView.model_validate(value), secret=secret)


@router.get("/companies/{company_id}/invitations", response_model=Page[InvitationView])
async def invitations(company_id: UUID, ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_company(ctx, company_id, "invitations.manage")
    return await page(
        ctx,
        select(Invitation)
        .where(Invitation.company_id == company_id)
        .order_by(Invitation.created_at, Invitation.id),
        limit,
        offset,
    )


@router.delete("/companies/{company_id}/invitations/{invitation_id}", response_model=InvitationView)
async def revoke_invitation(company_id: UUID, invitation_id: UUID, ctx: Ctx) -> Invitation:
    return await revoke(ctx, company_id, invitation_id)


@router.post("/invitations/accept", response_model=MemberView)
async def accept_invitation(payload: InvitationAccept, ctx: Ctx) -> Membership:
    return await accept(ctx, payload.company_id, payload.secret.get_secret_value())


@router.get("/platform/settings", response_model=SettingsView)
async def platform_settings(ctx: Ctx) -> PlatformSettings:
    await require_platform(ctx)
    value = await ctx.session.get(PlatformSettings, 1)
    if value is None:
        fail(503, "platform_migration_required")
    return value


@router.patch("/platform/settings", response_model=SettingsView)
async def edit_platform_settings(payload: SettingsPatch, ctx: Ctx) -> PlatformSettings:
    return await update_settings(ctx, payload.model_dump(exclude_unset=True))


@router.get("/platform/companies", response_model=Page[CompanyView])
async def platform_companies(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx)
    return await page(ctx, select(Company).order_by(Company.created_at, Company.id), limit, offset)


@router.get("/platform/company-requests", response_model=Page[RequestView])
async def platform_requests(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx)
    return await page(
        ctx, select(CompanyRequest).order_by(CompanyRequest.created_at, CompanyRequest.id), limit, offset
    )


@router.post("/platform/company-requests/{request_id}/approve", response_model=RequestView)
async def approve_request(request_id: UUID, payload: Review, ctx: Ctx) -> CompanyRequest:
    return await review_request(ctx, request_id, "approve", payload.comment)


@router.post("/platform/company-requests/{request_id}/reject", response_model=RequestView)
async def reject_request(request_id: UUID, payload: Review, ctx: Ctx) -> CompanyRequest:
    return await review_request(ctx, request_id, "reject", payload.comment)


@router.get("/platform/admins", response_model=Page[AdminView])
async def admins(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx)
    return await page(
        ctx, select(PlatformAdmin).order_by(PlatformAdmin.created_at, PlatformAdmin.user_id), limit, offset
    )


@router.post("/platform/admins", response_model=AdminView, status_code=201)
async def add_admin(payload: AdminAssignment, ctx: Ctx) -> PlatformAdmin:
    return await assign_admin(ctx, payload.user_id, True)


@router.delete("/platform/admins/{user_id}", response_model=AdminView)
async def remove_admin(user_id: UUID, ctx: Ctx) -> PlatformAdmin:
    return await assign_admin(ctx, user_id, False)


@router.patch("/platform/identities/{identity_id}")
async def classify_identity(identity_id: UUID, payload: PrincipalPatch, ctx: Ctx) -> dict[str, str]:
    await require_platform(ctx)
    value = await classify(ctx, identity_id, payload.principal_type)
    return {"identity_id": str(value.id), "principal_type": value.principal_type}


@router.get("/platform/audit", response_model=Page[AuditView])
async def platform_audit(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx)
    return await page(
        ctx, select(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()), limit, offset
    )


@router.get("/platform/users", response_model=Page[UserView])
async def platform_users(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx)
    return await page(ctx, select(User).order_by(User.created_at, User.id), limit, offset)


@router.patch("/platform/users/{user_id}", response_model=UserView)
async def user_status(user_id: UUID, payload: UserStatusPatch, ctx: Ctx) -> User:
    return await set_user_status(ctx, user_id, payload.status)
