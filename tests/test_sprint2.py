import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import schemas
from app.core import access, locking
from app.domains.audit.model import AuditEvent
from app.domains.companies import service as companies
from app.domains.companies.model import Company
from app.domains.employees import service as employees
from app.domains.identity import service as identities
from app.domains.identity.model import Identity
from app.domains.invitations import service as invitations
from app.domains.invitations.model import Invitation
from app.domains.memberships import service as memberships
from app.domains.memberships.model import Membership
from app.domains.platform import service as platform
from app.domains.platform.model import PlatformAdmin, PlatformSettings
from app.domains.registry import load_models
from app.domains.users.model import User


@pytest.fixture
def ctx(settings):
    load_models()
    session = MagicMock(spec=AsyncSession)
    session.scalar = AsyncMock()
    scalar_result = MagicMock()
    scalar_result.all.return_value = []
    session.scalars = AsyncMock(return_value=scalar_result)
    session.get = AsyncMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    added = []

    def add(value):
        if hasattr(value, "id") and value.id is None:
            value.id = uuid.uuid4()
        added.append(value)

    session.add.side_effect = add
    session.added = added
    user = User(
        id=uuid.uuid4(),
        status="active",
        display_name=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    identity = Identity(
        id=uuid.uuid4(),
        issuer=settings.oidc_issuer,
        subject="fixture-human",
        user_id=user.id,
        principal_type="human",
    )
    return access.Context(
        session,
        identity,
        user,
        settings.model_copy(update={"admin_acr_values": ["test-step-up"]}),
        {"acr": "test-step-up", "auth_time": 1000},
        "test-correlation-123",
        clock=lambda: 1000,
    )


@pytest.fixture
def allowed(ctx, monkeypatch):
    settings = PlatformSettings(
        id=1, company_creation_policy="open", max_owned_companies_per_user=3, invitations_enabled=True
    )
    company = Company(
        id=uuid.uuid4(), name="Company", slug="company", status="active", created_by_user_id=ctx.user.id
    )
    actor = Membership(
        id=uuid.uuid4(), company_id=company.id, user_id=ctx.user.id, role="owner", status="active"
    )
    monkeypatch.setattr(locking, "policy", AsyncMock(return_value=settings))
    monkeypatch.setattr(locking, "quota", AsyncMock())
    monkeypatch.setattr(locking, "company", AsyncMock())
    monkeypatch.setattr(invitations.authorization, "require", AsyncMock())
    monkeypatch.setattr(invitations.authorization, "require_grantable", AsyncMock())
    monkeypatch.setattr(invitations, "invitation_permissions", AsyncMock(return_value={"core.company.read"}))
    for module in (companies, employees, invitations, memberships, platform):
        if hasattr(module, "mutation_gate"):
            monkeypatch.setattr(module, "mutation_gate", AsyncMock(return_value=settings))
        if hasattr(module, "require_company"):
            monkeypatch.setattr(module, "require_company", AsyncMock(return_value=(company, actor)))
        if hasattr(module, "require_platform"):
            monkeypatch.setattr(module, "require_platform", AsyncMock())
        if hasattr(module, "human_user"):
            monkeypatch.setattr(module, "human_user", AsyncMock(return_value=ctx.user))
    return settings, company, actor


@pytest.mark.parametrize("kind", ["service", "unclassified"])
def test_machine_and_unclassified_principals_have_no_human_permissions(ctx, kind):
    ctx.identity.principal_type = kind
    with pytest.raises(HTTPException, match="human_principal_required"):
        access.require_human(ctx)


def test_suspended_user_fails_even_with_a_verified_jwt(ctx):
    ctx.user.status = "suspended"
    with pytest.raises(HTTPException, match="user_suspended"):
        access.require_human(ctx)


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"acr": "test-step-up"},
        {"acr": "1", "auth_time": 1000},
        {"acr": "bogus", "auth_time": 0},
        {"acr": "test-step-up", "auth_time": True},
        {"acr": "test-step-up", "auth_time": float("nan")},
        {"acr": "test-step-up", "auth_time": 0},
        {"acr": "test-step-up", "auth_time": 2000},
    ],
)
def test_mfa_does_not_trust_missing_arbitrary_stale_or_boolean_claims(ctx, claims):
    ctx.claims = claims
    with pytest.raises(HTTPException, match="configured_recent_mfa_required"):
        access.require_mfa(ctx)


def test_mfa_requires_explicit_idp_configuration(ctx):
    access.require_mfa(ctx)
    ctx.config = ctx.config.model_copy(update={"admin_acr_values": []})
    with pytest.raises(HTTPException):
        access.require_mfa(ctx)


async def test_platform_admin_is_explicit_database_privilege_not_realm_roles(ctx):
    ctx.claims["realm_access"] = {"roles": ["admin", "realm-admin"]}
    ctx.session.get.return_value = None
    with pytest.raises(HTTPException, match="platform_admin_required"):
        await access.require_platform(ctx)
    ctx.session.get.return_value = PlatformAdmin(user_id=ctx.user.id, active=True)
    await access.require_platform(ctx)


async def test_company_scope_and_roles_have_no_platform_bypass(ctx):
    company_id = uuid.uuid4()
    ctx.session.scalar.return_value = None
    with pytest.raises(HTTPException) as denied:
        await access.require_company(ctx, company_id, "employees.read")
    assert denied.value.status_code == 404
    statement = str(ctx.session.scalar.call_args.args[0])
    assert "memberships.company_id" in statement and "memberships.user_id" in statement
    member = Membership(role="member", status="active")
    ctx.session.scalar.return_value = member
    company = Company(id=company_id, status="active")
    ctx.session.get.return_value = company
    ctx.session.scalars.return_value.all.return_value = ["core.company.read", "core.employees.read"]
    assert (await access.require_company(ctx, company_id, "employees.read"))[1] is member
    with pytest.raises(HTTPException, match="company_permission_denied"):
        await access.require_company(ctx, company_id, "employees.manage")
    company.status = "suspended"
    with pytest.raises(HTTPException, match="company_not_active"):
        await access.require_company(ctx, company_id, "employees.read")


async def test_mutation_gate_is_a_database_row_lock_and_requires_migration(ctx):
    ctx.session.scalar.return_value = PlatformSettings(id=1)
    await access.mutation_gate(ctx.session)
    assert "FOR UPDATE" in str(ctx.session.scalar.call_args.args[0])
    ctx.session.scalar.return_value = None
    with pytest.raises(HTTPException, match="platform_migration_required"):
        await access.mutation_gate(ctx.session)


async def test_target_user_must_have_an_explicit_active_human_identity(ctx):
    ctx.session.get.return_value = ctx.user
    ctx.session.scalar.return_value = None
    with pytest.raises(HTTPException):
        await access.human_user(ctx.session, ctx.user.id)
    ctx.session.scalar.return_value = ctx.identity.id
    assert await access.human_user(ctx.session, ctx.user.id) is ctx.user


@pytest.mark.parametrize(
    "value", ["api", "admin", "a", "a--b", "123", "has space", "русский", "a/../b", "a" * 64]
)
def test_slug_rejects_reserved_path_unicode_and_invalid_shape(value):
    with pytest.raises(ValidationError):
        schemas.CompanyCreate(name="Company", slug=value)


def test_strict_patch_and_slug_normalization():
    assert schemas.CompanyCreate(name=" Company ", slug=" ISP-North ").slug == "isp-north"
    for payload in (
        {},
        {"status": None},
        {"company_id": str(uuid.uuid4())},
        {"max_owned_companies_per_user": "5"},
        {"invitations_enabled": 1},
    ):
        with pytest.raises(ValidationError):
            schemas.SettingsPatch.model_validate(payload)
    assert schemas.EmployeePatch(user_id=None).model_dump(exclude_unset=True) == {"user_id": None}
    with pytest.raises(ValidationError):
        schemas.ProfilePatch(status="active")
    assert (
        schemas.InvitationCreate(recipient_email="Person@Example.test").recipient_email
        == "person@example.test"
    )
    with pytest.raises(ValidationError):
        schemas.InvitationCreate(recipient_email="broken")


async def test_identity_jit_is_atomic_and_preserves_existing_ids(ctx):
    ctx.session.scalar.return_value = ctx.identity
    assert (
        await identities.resolve_identity(ctx.session, ctx.identity.issuer, ctx.identity.subject)
        == ctx.identity.id
    )
    ctx.session.commit.assert_awaited_once()
    ctx.session.scalar.side_effect = [None, None]
    new = await identities.identity_in_transaction(ctx.session, "https://other.test/realm", "new-sub")
    assert new.principal_type == "unclassified"
    assert new.id != ctx.identity.id
    assert any(isinstance(row, User) and row.id == new.user_id for row in ctx.session.added)
    assert any("pg_advisory_xact_lock" in str(call.args[0]) for call in ctx.session.execute.await_args_list)


async def test_company_and_owner_are_staged_together_and_audited(ctx, allowed):
    ctx.session.scalar.side_effect = [0, None]
    company = await companies.create_company(ctx, "ISP", "isp-company")
    assert company.created_by_user_id == ctx.user.id
    assert any(
        isinstance(row, Membership)
        and row.company_id == company.id
        and row.user_id == ctx.user.id
        and row.role == "owner"
        for row in ctx.session.added
    )
    assert any(isinstance(row, AuditEvent) and row.action == "company.created" for row in ctx.session.added)
    ctx.session.commit.assert_not_awaited()  # transaction belongs to request boundary


async def test_company_limit_and_slug_conflicts(ctx, allowed):
    ctx.session.scalar.return_value = 3
    with pytest.raises(HTTPException, match="owned_company_limit_reached"):
        await companies.create_company(ctx, "ISP", "isp-company")
    ctx.session.scalar.side_effect = [0, uuid.uuid4()]
    with pytest.raises(HTTPException, match="company_slug_unavailable"):
        await companies.create_company(ctx, "ISP", "isp-company")


async def test_request_lifecycle_rejects_replay_and_foreign_cancellation(ctx, allowed):
    settings, _, _ = allowed
    with pytest.raises(HTTPException):
        await companies.request_company(ctx, "ISP", "request-isp")
    settings.company_creation_policy = "approval"
    ctx.session.scalar.side_effect = [0, None, None]
    value = await companies.request_company(ctx, "ISP", "request-isp")
    value.status = "pending"
    ctx.session.scalar.side_effect = None
    ctx.session.scalar.return_value = value
    result = await companies.review_request(ctx, value.id, "reject", "No")
    assert result.status == "rejected" and result.review_comment == "No"
    with pytest.raises(HTTPException, match="request_not_pending"):
        await companies.review_request(ctx, value.id, "approve")
    value.requested_by_user_id = uuid.uuid4()
    with pytest.raises(HTTPException) as denied:
        await companies.review_request(ctx, value.id, "cancel")
    assert denied.value.status_code == 404


async def test_last_owner_and_role_escalation_are_blocked(ctx, allowed):
    _, company, actor = allowed
    ctx.session.scalar.side_effect = [actor, actor, 1]
    with pytest.raises(HTTPException, match="last_company_owner"):
        await memberships.update_member(ctx, company.id, actor.id, status="removed")
    actor.role = "admin"
    target = Membership(
        id=uuid.uuid4(), company_id=company.id, user_id=uuid.uuid4(), role="owner", status="active"
    )
    ctx.session.scalar.side_effect = [target, target]
    with pytest.raises(HTTPException, match="owner_required"):
        await memberships.update_member(ctx, company.id, target.id, role="member")


async def test_transfer_changes_both_ends_and_audits(ctx, allowed):
    _, company, actor = allowed
    target = Membership(
        id=uuid.uuid4(), company_id=company.id, user_id=uuid.uuid4(), role="member", status="active"
    )
    ctx.session.scalar.side_effect = [target, target, 0]
    await memberships.transfer(ctx, company.id, target.id)
    assert actor.role == "admin" and target.role == "owner"
    assert any(row.action == "ownership.transferred" for row in ctx.session.added)


async def test_employee_is_independent_and_links_only_explicit_members(ctx, allowed):
    _, company, _ = allowed
    employee = await employees.save_employee(ctx, company.id, {"display_name": "Engineer"})
    assert employee.user_id is None
    ctx.session.scalar.return_value = None
    with pytest.raises(HTTPException, match="employee_requires_active_membership"):
        await employees.save_employee(ctx, company.id, {"display_name": "Engineer", "user_id": uuid.uuid4()})
    ctx.session.scalar.side_effect = [uuid.uuid4(), employee]
    await employees.save_employee(ctx, company.id, {"user_id": ctx.user.id}, employee.id)
    assert employee.user_id == ctx.user.id


async def test_invitation_secret_is_one_time_output_never_audit_or_list(ctx, allowed):
    _, company, _ = allowed
    invitation, secret = await invitations.issue(
        ctx, company.id, role="member", hours=72, recipient_user_id=None, recipient_email=None
    )
    assert invitation.token_hash == invitations.digest(secret) and secret != invitation.token_hash
    assert secret not in str([event.details for event in ctx.session.added if isinstance(event, AuditEvent)])
    invitation.status, invitation.created_at = "pending", datetime.now(UTC)
    view = schemas.InvitationView.model_validate(invitation).model_dump_json()
    assert secret not in view and invitation.token_hash not in view
    assert "secret" not in repr(schemas.InvitationAccept(company_id=company.id, secret=secret))


async def test_invitation_role_policy_and_switch(ctx, allowed):
    settings, company, actor = allowed
    actor.role = "admin"
    with pytest.raises(HTTPException, match="invitation_role_denied"):
        await invitations.issue(
            ctx, company.id, role="admin", hours=1, recipient_user_id=None, recipient_email=None
        )
    settings.invitations_enabled = False
    with pytest.raises(HTTPException, match="invitations_disabled"):
        await invitations.issue(
            ctx, company.id, role="member", hours=1, recipient_user_id=None, recipient_email=None
        )


async def test_invitation_acceptance_checks_recipient_expiry_and_existing_access(ctx, allowed):
    _, company, actor = allowed
    invitation = Invitation(
        id=uuid.uuid4(),
        company_id=company.id,
        created_by_user_id=ctx.user.id,
        role="member",
        status="pending",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        recipient_user_id=uuid.uuid4(),
    )
    ctx.session.scalar.return_value = invitation
    with pytest.raises(HTTPException, match="invitation_recipient_mismatch"):
        await invitations.accept(ctx, company.id, "opaque-secret")
    invitation.recipient_user_id, invitation.recipient_email = None, "person@example.test"
    ctx.claims |= {"email": "person@example.test", "email_verified": False}
    with pytest.raises(HTTPException, match="verified_recipient_email_required"):
        await invitations.accept(ctx, company.id, "opaque-secret")
    ctx.claims["email_verified"] = True
    ctx.session.get.side_effect = lambda model, *args, **kwargs: company if model is Company else ctx.user
    ctx.session.scalar.side_effect = [invitation, actor, ctx.identity, None]
    member = await invitations.accept(ctx, company.id, "opaque-secret")
    assert member.status == "active" and invitation.status == "accepted"
    ctx.session.scalar.side_effect = None
    ctx.session.scalar.return_value = invitation
    with pytest.raises(HTTPException, match="invitation_unavailable"):
        await invitations.accept(ctx, company.id, "opaque-secret")


async def test_invitation_revocation_and_scope(ctx, allowed):
    _, company, _ = allowed
    value = Invitation(id=uuid.uuid4(), company_id=company.id, status="pending")
    ctx.session.scalar.return_value = value
    assert (await invitations.revoke(ctx, company.id, value.id)).status == "revoked"
    assert "invitations.company_id" in str(ctx.session.scalar.call_args.args[0])


async def test_platform_settings_and_last_admin(ctx, allowed):
    settings, _, _ = allowed
    result = await platform.update_settings(ctx, {"company_creation_policy": "closed"})
    assert result is settings and settings.company_creation_policy == "closed"
    admin = PlatformAdmin(user_id=ctx.user.id, active=True)
    ctx.session.get.return_value = admin
    ctx.session.scalar.return_value = 1
    with pytest.raises(HTTPException, match="last_platform_admin"):
        await platform.assign_admin(ctx, ctx.user.id, False)
    ctx.session.scalar.return_value = 2
    assert not (await platform.assign_admin(ctx, ctx.user.id, False)).active
    assert (await platform.assign_admin(ctx, ctx.user.id, True)).active


async def test_principal_admission_is_not_inferred_and_cannot_strand_humans(ctx, allowed):
    ctx.session.get.return_value = ctx.identity
    with pytest.raises(HTTPException):
        await platform.classify(ctx, ctx.identity.id, "service")
    ctx.identity.principal_type = "unclassified"
    assert (await platform.classify(ctx, ctx.identity.id, "human")).principal_type == "human"


async def test_global_user_status_is_explicit_and_audited(ctx, allowed):
    target = User(id=uuid.uuid4(), status="active")
    ctx.session.get.return_value = target
    assert (await platform.set_user_status(ctx, target.id, "suspended")).status == "suspended"
    assert any(
        event.action == "user.status_changed" and event.resource_id == target.id
        for event in ctx.session.added
    )


@pytest.fixture
async def api2(ctx, provider):
    from typing import Annotated, Any

    import httpx
    from fastapi import Depends

    from app.api.v1.dependencies import context
    from app.core.authentication import verified_claims
    from app.integrations.keycloak.oidc import OIDCVerifier
    from app.main import create_app

    app = create_app(provider.settings)

    async def admitted(claims: Annotated[dict[str, Any], Depends(verified_claims)]):
        yield ctx

    app.dependency_overrides[context] = admitted
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as oidc:
        app.state.oidc = OIDCVerifier(provider.settings, oidc)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://core.example.test",
            headers={"Authorization": "Bearer " + provider.token()},
        ) as client:
            yield client


async def test_api_profile_allows_only_safe_fields_and_preserves_identity(api2, ctx):
    response = await api2.patch("/api/v1/me", json={"display_name": "Engineer"})
    assert response.status_code == 200 and response.json()["display_name"] == "Engineer"
    assert response.json()["id"] == str(ctx.identity.id)
    for payload in (
        {"user_id": str(uuid.uuid4())},
        {"issuer": "https://evil.test"},
        {"principal_type": "human"},
        {"display_name": " "},
    ):
        assert (await api2.patch("/api/v1/me", json=payload)).status_code == 422


async def test_api_validation_never_echoes_secret_input(api2):
    response = await api2.post(
        "/api/v1/invitations/accept",
        json={"company_id": "not-a-uuid", "secret": "secret-should-not-be-reflected"},
    )
    assert response.status_code == 422
    assert "secret-should-not-be-reflected" not in response.text
    assert "input" not in response.text
    assert (await api2.get("/api/v1/companies?limit=101")).status_code == 422


@pytest.mark.parametrize("kind", ["unclassified", "service"])
async def test_api_user_operations_reject_machine_principals(api2, ctx, kind):
    ctx.identity.principal_type = kind
    for path in (
        "/api/v1/companies",
        "/api/v1/company-requests/me",
        "/api/v1/me/companies",
        "/api/v1/platform/settings",
    ):
        assert (await api2.get(path)).status_code == 403
    assert (
        await api2.post("/api/v1/company-requests", json={"name": "ISP", "slug": "test-isp"})
    ).status_code == 403


@pytest.mark.parametrize(
    "operation,existing,active,confirmed",
    [
        ("bootstrap", False, 0, False),
        ("bootstrap", True, 1, False),
        ("bootstrap", False, 1, False),
        ("recover", False, 1, True),
        ("recover", False, 1, False),
    ],
)
async def test_operator_bootstrap_is_explicit_audited_and_idempotent(
    ctx, monkeypatch, operation, existing, active, confirmed
):
    import argparse
    from contextlib import asynccontextmanager

    from scripts import platform_admin

    @asynccontextmanager
    async def transaction():
        yield

    @asynccontextmanager
    async def sessions():
        yield ctx.session

    ctx.session.begin = transaction
    ctx.session.get.side_effect = [
        ctx.identity,
        ctx.user,
        PlatformAdmin(user_id=ctx.user.id, active=True) if existing else None,
    ]
    ctx.session.scalar.return_value = active
    engine = MagicMock()
    engine.dispose = AsyncMock()
    monkeypatch.setattr(platform_admin, "Settings", lambda: ctx.config)
    monkeypatch.setattr(platform_admin, "create_database", lambda config: (engine, sessions))
    monkeypatch.setattr(platform_admin.locking, "administration", AsyncMock())
    monkeypatch.setattr(platform_admin, "human_user", AsyncMock(return_value=ctx.user))
    arguments = argparse.Namespace(
        command=operation,
        identity_id=ctx.identity.id,
        confirm_recovery=confirmed,
        reason="Verified offline recovery",
    )
    if (operation == "bootstrap" and active and not existing) or (operation == "recover" and not confirmed):
        with pytest.raises(HTTPException if operation == "bootstrap" else ValueError):
            await platform_admin.execute(arguments)
        assert ctx.session.added == []
        engine.dispose.assert_awaited_once()
        return
    await platform_admin.execute(arguments)
    events = [row for row in ctx.session.added if isinstance(row, AuditEvent)]
    if not existing:
        assert len(events) == 1
        assert events[0].details["operator"] is True
        assert events[0].actor_user_id is None and events[0].actor_identity_id is None
        assert events[0].details["actor_kind"] == "operator"
    else:
        assert events == []
    engine.dispose.assert_awaited_once()


def test_dev_up_builds_shared_core_migration_image_before_starting():
    from pathlib import Path

    makefile = (Path(__file__).resolve().parents[1] / "Makefile").read_text()
    section = makefile.split("dev-up: dev-config\n", 1)[1].split("dev-down:", 1)[0]
    assert section.index("build core") < section.index("up -d --no-build")
    assert "down" not in section
