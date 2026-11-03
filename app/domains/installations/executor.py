"""Trusted operator path. No HTTP entry point and no subprocess/package execution."""

import re
from collections.abc import Callable
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core import locking
from app.core.access import Context, audit, fail, require_platform
from app.core.config import Settings
from app.domains.identity.model import Identity
from app.domains.installations import service
from app.domains.installations.model import (
    ModuleDependencyPin,
    ModuleInstallation,
    ModuleInstallationHistory,
    ModuleInstallOperation,
    ModuleInstallPlan,
    ModuleInstanceBinding,
)
from app.domains.installations.policy import digest, policy
from app.domains.packages.archive import Limits
from app.domains.packages.codec import PackageError
from app.domains.packages.service import trust_store
from app.domains.packages.storage import Storage
from app.domains.packages.work import file_work
from app.domains.users.model import User

Sessions = async_sessionmaker[AsyncSession]
Fault = Callable[[str], None]


def no_fault(phase: str) -> None:
    """Test injection seam, never selected through HTTP/env/CLI arguments."""


async def capability(session: AsyncSession) -> None:
    allowed = await session.scalar(
        text("""SELECT
      coalesce(pg_has_role(current_user,to_regrole('xarionix_module_executor'),'MEMBER'),false)
      AND NOT coalesce(pg_has_role(current_user,to_regrole('xarionix_module_catalog'),'MEMBER'),false)
      AND has_function_privilege(current_user,'core_apply_module_catalog(uuid,text,uuid)','EXECUTE')
      AND (SELECT r.rolname='xarionix_module_catalog' AND NOT r.rolcanlogin AND NOT r.rolsuper
        FROM pg_proc f JOIN pg_roles r ON r.oid=f.proowner
        WHERE f.oid='core_apply_module_catalog(uuid,text,uuid)'::regprocedure)
    """)
    )
    if not allowed:
        fail(403, "installation_executor_not_provisioned")


async def approved_context(session: AsyncSession, config: Settings, value: ModuleInstallPlan) -> Context:
    await locking.administration(session, shared=True)
    if (
        value.state != "approved"
        or value.approved_by is None
        or value.approved_identity_id is None
        or value.approval is None
        or value.approval.get("digest") != value.digest
        or value.approval.get("policy") != policy(config)
        or digest(value.body) != value.digest
    ):
        fail(409, "installation_approval_invalid")
    identity = await session.get(Identity, value.approved_identity_id, populate_existing=True)
    user = await session.get(User, value.approved_by, populate_existing=True)
    if not identity or not user or identity.user_id != user.id or identity.issuer != config.oidc_issuer:
        fail(403, "installation_approver_unavailable")
    ctx = Context(
        session,
        identity,
        user,
        config,
        value.approval,
        "module-install-operator",
        operator=True,
        mutating=True,
    )
    await require_platform(ctx, serialize=False)
    if (
        value.expires_at <= service.now(ctx)
        or not value.approved_until
        or value.approved_until <= service.now(ctx)
    ):
        fail(409, "installation_approval_expired")
    return ctx


async def claim(
    sessions: Sessions, config: Settings, plan_id: UUID, expected_digest: str
) -> tuple[dict[str, Any], Any, UUID, dict[str, Any] | None]:
    async with sessions() as session, session.begin():
        await capability(session)
        value = await session.get(ModuleInstallPlan, plan_id)
        if not value:
            fail(404, "module_install_plan_not_found")
        if value.digest != expected_digest:
            fail(409, "installation_plan_digest_conflict")
        # A completed operation is an immutable receipt; expiry/revocation doesn't erase it.
        completed = await session.get(ModuleInstallOperation, plan_id, populate_existing=True)
        if completed and completed.state == "succeeded":
            return value.body, None, UUID(int=0), service.operation_view(completed)
        ctx = await approved_context(session, config, value)
        await service.locks(ctx, value.body)
        value = await service.plan(ctx, plan_id, lock=True)
        await approved_context(session, config, value)
        current = await session.get(ModuleInstallOperation, plan_id, populate_existing=True)
        if current is not None and current.state == "succeeded":
            return value.body, None, UUID(int=0), service.operation_view(current)
        other = await session.scalar(
            select(ModuleInstallOperation)
            .where(
                ModuleInstallOperation.module_id == value.module_id,
                ModuleInstallOperation.state == "applying",
                ModuleInstallOperation.id != plan_id,
            )
            .with_for_update()
        )
        if other:
            if other.lease_until and other.lease_until > service.now(ctx):
                fail(409, "installation_operation_in_progress")
            other.state, other.safe_error_code, other.lease_until = (
                "failed",
                "installation_lease_expired",
                None,
            )
            other.completed_at = service.now(ctx)
            other.failures = [
                *other.failures[-31:],
                {
                    "attempt": other.attempts,
                    "code": "installation_lease_expired",
                    "at": service.now(ctx).isoformat(),
                },
            ]
            audit(ctx, "module.operation_abandoned", "module_install_operation", other.id)
            await session.flush()
        if (
            current
            and current.state == "applying"
            and current.lease_until
            and current.lease_until > service.now(ctx)
        ):
            fail(409, "installation_operation_in_progress")
        if current is None:
            current = ModuleInstallOperation(
                id=plan_id,
                plan_id=plan_id,
                module_id=value.module_id,
                state="prepared",
                attempts=0,
                failures=[],
                correlation_id=uuid4(),
            )
            session.add(current)
        if current.attempts >= 32:
            fail(409, "installation_retry_limit")
        current.attempts += 1
        current.state, current.fence = "applying", uuid4()
        current.started_at, current.completed_at = service.now(ctx), None
        current.lease_until = service.now(ctx) + timedelta(seconds=180)
        current.safe_error_code = None
        audit(
            ctx,
            "module.operation_started",
            "module_install_operation",
            current.id,
            attempt=current.attempts,
            plan_digest=value.digest,
        )
        store = await trust_store(ctx)
        await session.flush()
        return value.body, store, current.fence, None


async def commit(
    sessions: Sessions, config: Settings, plan_id: UUID, fence: UUID, body: dict[str, Any], fault: Fault
) -> dict[str, Any]:
    async with sessions() as session, session.begin():
        value = await session.get(ModuleInstallPlan, plan_id)
        if not value:
            fail(404, "module_install_plan_not_found")
        ctx = await approved_context(session, config, value)
        await service.locks(ctx, body)
        value = await service.plan(ctx, plan_id, lock=True)
        ctx = await approved_context(session, config, value)
        operation = await service.operation(ctx, plan_id, lock=True)
        if (
            operation.state != "applying"
            or operation.fence != fence
            or not operation.lease_until
            or operation.lease_until <= service.now(ctx)
        ):
            fail(409, "installation_operation_fence_conflict")
        fresh, _ = await service.snapshot(ctx, value.action, value.package_id, value.expected_generation)
        if fresh != body or not fresh["ready"]:
            fail(409, "installation_plan_stale")
        target = await service.package(ctx, value.package_id)
        inst = await session.scalar(
            select(ModuleInstallation).where(ModuleInstallation.module_id == value.module_id)
        )
        old_package, old_state = (inst.package_id, inst.status) if inst else (None, None)
        fault("before_catalog")
        if inst is None:
            inst = ModuleInstallation(
                id=uuid4(),
                module_id=value.module_id,
                publisher_id=target.publisher_id,
                package_id=target.id,
                namespace=body["namespace"],
                module_type=body["module_type"],
                status=body["next_state"],
                generation=1,
                installed_by_user_id=value.approved_by,
            )
            session.add(inst)
        else:
            inst.generation += 1
            inst.status = body["next_state"]
            if target.id != inst.package_id:
                inst.previous_package_id, inst.package_id = inst.package_id, target.id
            inst.updated_at = service.now(ctx)
        await session.flush()
        if value.action in {"install", "update", "rollback", "uninstall"}:
            await session.execute(
                delete(ModuleDependencyPin).where(ModuleDependencyPin.installation_id == inst.id)
            )
            if value.action != "uninstall":
                for pin in body["dependency_pins"]:
                    session.add(
                        ModuleDependencyPin(
                            installation_id=inst.id,
                            dependency_id=UUID(pin["installation_id"]),
                            package_id=UUID(pin["package_id"]),
                            generation=pin["generation"],
                        )
                    )
            binding = await session.get(ModuleInstanceBinding, inst.id)
            if binding and binding.active:
                binding.active = False
                binding.revision += 1
        await session.flush()
        await session.execute(
            text("SELECT core_apply_module_catalog(:plan,:digest,:fence)"),
            {"plan": value.id, "digest": value.digest, "fence": fence},
        )
        fault("after_catalog")
        session.add(
            ModuleInstallationHistory(
                installation_id=inst.id,
                operation_id=operation.id,
                previous_package_id=old_package,
                package_id=inst.package_id,
                previous_state=old_state,
                state=inst.status,
                generation=inst.generation,
                performed_by=value.approved_by,
            )
        )
        value.state = "applied"
        operation.state, operation.completed_at, operation.lease_until = "succeeded", service.now(ctx), None
        audit(
            ctx,
            "module." + value.action + "_committed",
            "module_installation",
            inst.id,
            operation_id=str(operation.id),
            generation=inst.generation,
            package_sha256=target.package_sha256,
            approved_by=str(value.approved_by),
            plan_digest=value.digest,
        )
        await session.flush()
        fault("before_commit")
        result = service.operation_view(operation)
    fault("after_commit")
    return result


async def record_failure(sessions: Sessions, config: Settings, plan_id: UUID, fence: UUID, code: str) -> None:
    async with sessions() as session, session.begin():
        value = await session.get(ModuleInstallPlan, plan_id)
        operation = await session.scalar(
            select(ModuleInstallOperation).where(ModuleInstallOperation.id == plan_id).with_for_update()
        )
        if not value or not operation or operation.state != "applying" or operation.fence != fence:
            return
        # Diagnostic recording must work even when the approval expired/revoked during verification.
        user = await session.get(User, value.created_by)
        identity = (
            await session.get(Identity, value.approved_identity_id) if value.approved_identity_id else None
        )
        if not user or not identity:
            return
        ctx = Context(session, identity, user, config, {}, "module-install-operator", operator=True)
        operation.state, operation.safe_error_code = "failed", code
        operation.completed_at, operation.lease_until = service.now(ctx), None
        operation.failures = [
            *operation.failures[-31:],
            {"attempt": operation.attempts, "code": code, "at": service.now(ctx).isoformat()},
        ]
        audit(
            ctx,
            "module.operation_failed",
            "module_install_operation",
            operation.id,
            safe_error_code=code,
            attempt=operation.attempts,
        )


async def apply(
    sessions: Sessions,
    config: Settings,
    storage: Storage,
    plan_id: UUID,
    expected_digest: str,
    *,
    fault: Fault = no_fault,
) -> dict[str, Any]:
    body, store, fence, receipt = await claim(sessions, config, plan_id, expected_digest)
    if receipt:
        return receipt
    try:
        fault("after_claim")
        lease = storage.lease()
        try:
            await file_work(service.verify_blobs, body, store, storage, Limits.configured(config))
            fault("after_verification")
            return await commit(sessions, config, plan_id, fence, body, fault)
        finally:
            lease.close()
    except Exception as error:
        code = "installation_apply_failed"
        if isinstance(error, PackageError):
            code = str(error)
        elif isinstance(error, HTTPException) and isinstance(error.detail, dict):
            code = str(error.detail.get("code", code))
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code):
            code = "installation_apply_failed"
        await record_failure(sessions, config, plan_id, fence, code)
        raise
