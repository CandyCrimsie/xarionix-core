import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access import Context
from app.domains.companies.model import Company
from app.domains.identity.model import Identity
from app.domains.memberships.model import Membership
from app.domains.rbac import authorization, registration, service
from app.domains.rbac.catalog_v1 import OWNER
from app.domains.rbac.model import MembershipRole, Permission, PermissionNamespace, Role, RoleTemplate
from app.domains.registry import load_models
from app.domains.users.model import User


def rows(*items):
    result = MagicMock()
    result.all.return_value = list(items)
    return result


@pytest.fixture
def auth(settings):
    load_models()
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.refresh = AsyncMock()
    session.scalar = AsyncMock()
    session.scalars = AsyncMock()
    session.get = AsyncMock()
    session.flush = AsyncMock()
    session.delete = AsyncMock()
    session.added = []

    def add(value):
        if hasattr(value, "id") and value.id is None:
            value.id = uuid.uuid4()
        session.added.append(value)

    session.add.side_effect = add
    user = User(id=uuid.uuid4(), status="active")
    company = Company(id=uuid.uuid4(), status="active")
    member = Membership(
        id=uuid.uuid4(), company_id=company.id, user_id=user.id, status="active", role="member"
    )
    session.scalar.return_value = member
    session.get.return_value = company
    session.scalars.return_value = rows("core.company.read", "core.employees.read")
    ctx = Context(
        session,
        Identity(id=uuid.uuid4(), user_id=user.id, principal_type="human"),
        user,
        settings,
        {},
        mutating=True,
    )
    return ctx, company, member


async def test_effective_permissions_are_union_not_names_or_jwt_roles(auth):
    ctx, company, member = auth
    ctx.claims = {"realm_access": {"roles": ["admin"]}, "permissions": ["core.company.manage"]}
    ctx.session.scalars.return_value = rows("core.company.read", "core.employees.read", "core.company.read")
    decision = await authorization.effective(ctx, company.id)
    assert decision.permissions == {"core.company.read", "core.employees.read"}
    assert decision.member is member
    ctx.session.scalars.assert_awaited_once()
    sql = str(ctx.session.scalars.call_args.args[0])
    assert "membership_roles.company_id" in sql and "roles.active" in sql and "permissions.active" in sql
    with pytest.raises(HTTPException, match="company_permission_denied"):
        await authorization.require(ctx, company.id, "core.company.manage")


@pytest.mark.parametrize(
    "state", ["service", "unclassified", "suspended_user", "no_membership", "suspended_company"]
)
async def test_authentication_and_tenant_lifecycle_are_not_bypassed(auth, state):
    ctx, company, _ = auth
    if state in {"service", "unclassified"}:
        ctx.identity.principal_type = state
    elif state == "suspended_user":
        ctx.user.status = "suspended"
    elif state == "no_membership":
        ctx.session.scalar.return_value = None
    else:
        company.status = "suspended"
    with pytest.raises(HTTPException) as error:
        await authorization.effective(ctx, company.id)
    assert error.value.status_code == (404 if state == "no_membership" else 403)


@pytest.mark.parametrize(
    "owner,effective,delegated,protected,available,allowed",
    [
        (True, True, False, False, True, True),
        (True, True, True, True, True, False),
        (True, True, True, False, False, False),
        (False, True, True, False, True, True),
        (False, False, True, False, True, False),
        (False, True, False, False, True, False),
    ],
)
async def test_grantability_is_intersection_and_never_protected_authority(
    auth, owner, effective, delegated, protected, available, allowed
):
    ctx, company, member = auth
    member.role = "owner" if owner else "member"
    key = "core.employees.manage"
    permission = Permission(
        key=key, namespace="core", protected=protected, owner_grantable=True, active=True, scope="company"
    )
    ctx.session.scalars.side_effect = [
        rows(*([key] if effective else [])),
        rows(*([permission] if available else [])),
        rows(*([key] if delegated else [])),
    ]
    if allowed:
        await authorization.require_grantable(ctx, company.id, {key})
    else:
        with pytest.raises(HTTPException):
            await authorization.require_grantable(ctx, company.id, {key})


async def test_owner_marker_is_required_even_if_permissions_are_tampered(auth):
    ctx, company, _ = auth
    ctx.session.scalars.return_value = rows("core.ownership.transfer")
    with pytest.raises(HTTPException, match="owner_required"):
        await authorization.require(ctx, company.id, "core.ownership.transfer")


@pytest.fixture
def administrator(auth, monkeypatch):
    ctx, company, member = auth
    member.role = "owner"
    decision = authorization.Decision(company, member, OWNER)
    monkeypatch.setattr(authorization, "require", AsyncMock(return_value=decision))
    monkeypatch.setattr(authorization, "require_grantable", AsyncMock(return_value=decision))
    monkeypatch.setattr(service, "human_user", AsyncMock(return_value=ctx.user))
    value = Role(
        id=uuid.uuid4(),
        company_id=company.id,
        code="engineer",
        name="Инженер",
        is_system=False,
        active=True,
        version=1,
    )
    ctx.session.scalar.return_value = value
    ctx.session.scalars.return_value = rows("core.employees.read")
    return ctx, company, member, value


async def test_role_creation_template_copy_and_audit(administrator):
    ctx, company, _, _ = administrator
    ctx.session.scalar.side_effect = [0, None]
    template = RoleTemplate(
        key="core.template.field_engineer", version=1, name="Инженер", permissions=["core.employees.read"]
    )
    ctx.session.get.return_value = template
    value = await service.create_role(
        ctx,
        company.id,
        code="custom_engineer",
        name="Инженер",
        description=None,
        requested=set(),
        template_key=template.key,
    )
    assert not value.is_system and value.version == 1
    assert template.permissions == ["core.employees.read"]
    assert any(getattr(item, "action", None) == "role.created" for item in ctx.session.added)
    authorization.require_grantable.assert_awaited_once_with(ctx, company.id, {"core.employees.read"})


@pytest.mark.parametrize(
    "limit,existing,error",
    [(200, None, "company_role_limit_reached"), (0, uuid.uuid4(), "role_code_unavailable")],
)
async def test_role_creation_conflicts_have_no_staged_changes(administrator, limit, existing, error):
    ctx, company, _, _ = administrator
    ctx.session.scalar.side_effect = [limit, existing]
    with pytest.raises(HTTPException, match=error):
        await service.create_role(
            ctx, company.id, code="engineer", name="Инженер", description=None, requested=set()
        )
    assert not ctx.session.added


@pytest.mark.parametrize(
    "system,version,error", [(True, 1, "system_role_protected"), (False, 9, "role_version_conflict")]
)
async def test_system_role_and_optimistic_version_are_fail_closed(administrator, system, version, error):
    ctx, company, _, value = administrator
    value.is_system = system
    with pytest.raises(HTTPException, match=error):
        await service.set_permissions(ctx, company.id, value.id, {"core.employees.read"}, version)
    assert not ctx.session.added
    assert value.version == 1


async def test_self_assigned_role_cannot_expand_even_with_grantable_permissions(administrator):
    ctx, company, member, value = administrator
    member.role = "member"
    ctx.session.scalar.side_effect = [value, value.id]
    with pytest.raises(HTTPException, match="self_role_expansion_denied"):
        await service.set_permissions(
            ctx, company.id, value.id, {"core.employees.read", "core.employees.manage"}, 1
        )
    assert not ctx.session.added
    assert value.version == 1


async def test_role_permission_removal_and_metadata_update_are_audited(administrator):
    ctx, company, _, value = administrator
    await service.set_permissions(ctx, company.id, value.id, set(), 1)
    assert value.version == 2
    await service.update_role(ctx, company.id, value.id, {"name": "Новое имя", "active": False}, 2)
    assert value.name == "Новое имя" and not value.active and value.version == 3
    assert {item.action for item in ctx.session.added} == {"role.permissions_changed", "role.updated"}


@pytest.mark.parametrize("fields", [{}, {"company_id": uuid.uuid4()}, {"is_system": True}, {"code": "owner"}])
async def test_role_update_has_explicit_field_allowlist(administrator, fields):
    ctx, company, _, value = administrator
    with pytest.raises(HTTPException, match="invalid_role_fields"):
        await service.update_role(ctx, company.id, value.id, fields, 1)
    assert value.version == 1 and not ctx.session.added


async def test_role_deletion_rejects_existing_assignments_then_cleans_links(administrator):
    ctx, company, _, value = administrator
    ctx.session.scalar.side_effect = [value, value.id]
    with pytest.raises(HTTPException, match="role_has_assignments"):
        await service.delete_role(ctx, company.id, value.id)
    ctx.session.scalar.side_effect = [value, None]
    await service.delete_role(ctx, company.id, value.id)
    ctx.session.delete.assert_awaited_once_with(value)
    assert ctx.session.added[-1].action == "role.deleted"


async def test_assignment_and_revocation_use_same_grantability_and_audit(administrator):
    ctx, company, member, value = administrator
    member.role = "member"
    ctx.session.scalar.side_effect = [member, value, 1]
    ctx.session.get.return_value = None
    await service.assign(ctx, company.id, member.id, value.id)
    assert any(isinstance(item, MembershipRole) for item in ctx.session.added)
    assignment = MembershipRole(
        company_id=company.id, membership_id=member.id, role_id=value.id, origin="custom"
    )
    ctx.session.scalar.side_effect = [member, value]
    ctx.session.get.return_value = assignment
    await service.assign(ctx, company.id, member.id, value.id, revoke=True)
    ctx.session.delete.assert_awaited_once_with(assignment)
    assert {item.action for item in ctx.session.added if hasattr(item, "action")} == {
        "role.assigned",
        "role.revoked",
    }
    assert authorization.require_grantable.await_count == 2


@pytest.mark.parametrize(
    "state,error",
    [
        ("suspended", "active_membership_required"),
        ("system", "system_role_protected"),
        ("inactive", "role_unavailable"),
        ("duplicate", "role_already_assigned"),
        ("limit", "membership_role_limit_reached"),
    ],
)
async def test_assignment_denials_do_not_mutate_state(administrator, state, error):
    ctx, company, member, value = administrator
    member.role = "member"
    if state == "suspended":
        member.status = "suspended"
    if state == "system":
        value.is_system = True
    if state == "inactive":
        value.active = False
    ctx.session.scalar.side_effect = [member, value, 50 if state == "limit" else 1]
    ctx.session.get.return_value = object() if state == "duplicate" else None
    with pytest.raises(HTTPException, match=error):
        await service.assign(ctx, company.id, member.id, value.id)
    assert not ctx.session.added


async def test_delegation_is_audited_and_owned_by_protected_authority(administrator):
    ctx, company, member, _ = administrator
    member.role = "member"
    ctx.session.scalar.return_value = member
    await service.set_delegation(ctx, company.id, member.id, {"core.employees.read"})
    assert ctx.session.added[-1].action == "permission.delegation_changed"
    authorization.require.assert_awaited_once_with(ctx, company.id, "core.permissions.delegate")
    member.role = "owner"
    with pytest.raises(HTTPException, match="delegation_requires_active_non_owner"):
        await service.set_delegation(ctx, company.id, member.id, set())


@pytest.mark.parametrize(
    "payload",
    [
        {"key": "core.platform.admin", "description": "Invalid"},
        {"key": "billing.payments.refund", "description": "Wrong namespace"},
        {"key": "core.*", "description": "Wildcard"},
        {"key": "core.example.read", "description": "Global", "scope": "platform"},
        {
            "key": "core.example.read",
            "description": "Protected grant",
            "protected": True,
            "owner_grantable": True,
        },
    ],
)
def test_registration_contract_rejects_privileged_or_cross_namespace_definitions(payload):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        registration.NamespaceManifest(namespace="core", version=1, permissions=[payload])


@pytest.mark.parametrize(
    "owner,state,allowed",
    [
        ("xarionix-core", "active", True),
        ("other-module", "active", False),
        ("xarionix-core", "reserved", False),
        ("xarionix-core", "disabled", False),
    ],
)
async def test_namespace_ownership_requires_trusted_active_catalog(auth, owner, state, allowed):
    ctx, _, _ = auth
    ctx.session.get.return_value = PermissionNamespace(name="core", owner=owner, state=state)
    manifest = registration.NamespaceManifest(
        namespace="core", version=1, permissions=[{"key": "core.example.read", "description": "Example"}]
    )
    if allowed:
        assert (
            await registration.validate_registration(
                ctx.session, registration.DeploymentAuthority("xarionix-core"), manifest
            )
            is manifest
        )
    else:
        with pytest.raises(HTTPException):
            await registration.validate_registration(
                ctx.session, registration.DeploymentAuthority("xarionix-core"), manifest
            )
