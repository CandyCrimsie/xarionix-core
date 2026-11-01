from typing import Any
from uuid import UUID

from sqlalchemy import select

from app.core.access import Context, audit, fail, mutation_gate, require_company
from app.domains.employees.model import Employee
from app.domains.memberships.model import Membership


async def get_employee(ctx: Context, company_id: UUID, employee_id: UUID) -> Employee:
    value = await ctx.session.scalar(
        select(Employee).where(Employee.id == employee_id, Employee.company_id == company_id)
    )
    if value is None:
        fail(404, "employee_not_found")
    return value


async def save_employee(
    ctx: Context, company_id: UUID, fields: dict[str, Any], employee_id: UUID | None = None
) -> Employee:
    await mutation_gate(ctx.session)
    await require_company(ctx, company_id, "employees.manage")
    if fields.get("user_id"):
        member = await ctx.session.scalar(
            select(Membership.id).where(
                Membership.company_id == company_id,
                Membership.user_id == fields["user_id"],
                Membership.status == "active",
            )
        )
        if member is None:
            fail(409, "employee_requires_active_membership")
    if employee_id:
        value = await get_employee(ctx, company_id, employee_id)
        for key, item in fields.items():
            setattr(value, key, item)
    else:
        value = Employee(company_id=company_id, **fields)
        ctx.session.add(value)
    await ctx.session.flush()
    audit(ctx, "employee.changed" if employee_id else "employee.created", "employee", value.id, company_id)
    return value
