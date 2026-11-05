"""Short control-plane transactions. All external artifact/engine work is outside DB locks."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import func, select, text

from app.core import locking
from app.core.access import Context, audit, fail, require_platform
from app.domains.audit.model import AuditEvent
from app.domains.deployments.contracts import PROFILES, SAFETY, CheckIn, PlanCreate, Receipt, digest
from app.domains.deployments.model import (
    DeploymentHost,
    DeploymentJob,
    DeploymentPlan,
    ModuleRetirement,
    RuntimeDeployment,
)
from app.domains.identity.model import Identity
from app.domains.installations import service as installations
from app.domains.installations.model import ModuleInstallation
from app.domains.installations.policy import policy
from app.domains.modules.authorization import MachineContext
from app.domains.packages.model import (
    ModulePackage,
    PackagePublisher,
    PublisherNamespaceGrant,
    PublisherSigningKey,
)
from app.domains.packages.schema import TrustKey, TrustStore
from app.domains.packages.semver import Range
from app.domains.rbac.model import PermissionNamespace
from app.domains.users.model import User
from app.version import VERSION


def now() -> datetime:
    return datetime.now(UTC)


async def module_lock(session: Any, installation: Any) -> None:
    await session.execute(
        text("SELECT core_lock('module_installation', :id, false)"), {"id": installation.module_id}
    )


async def trusted(session: Any, package: ModulePackage) -> bool:
    namespace = await session.get(PermissionNamespace, package.manifest["permissions"]["namespace"])
    if (
        namespace is None
        or namespace.owner != package.module_id
        or namespace.state not in {"active", "disabled"}
        or not Range.parse(package.manifest["compatibility"]["core"]).contains(VERSION)
    ):
        return False
    return (
        bool(
            await session.scalar(
                select(PackagePublisher.id)
                .join(PublisherSigningKey, PublisherSigningKey.publisher_id == PackagePublisher.id)
                .join(PublisherNamespaceGrant, PublisherNamespaceGrant.publisher_id == PackagePublisher.id)
                .where(
                    PackagePublisher.id == package.publisher_id,
                    PackagePublisher.status == "active",
                    PublisherSigningKey.id == package.signing_key_id,
                    PublisherSigningKey.status == "active",
                    PublisherNamespaceGrant.namespace == package.manifest["permissions"]["namespace"],
                    PublisherNamespaceGrant.status == "active",
                )
            )
        )
        and package.state == "available"
    )


async def trust(session: Any, package: ModulePackage) -> dict[str, Any]:
    if not await trusted(session, package):
        fail(409, "deployment_package_untrusted")
    key = await session.get(PublisherSigningKey, package.signing_key_id)
    publisher = await session.get(PackagePublisher, package.publisher_id)
    if key is None or publisher is None:
        fail(409, "deployment_package_untrusted")
    return TrustStore(
        schema_version=1,
        keys=[
            TrustKey(
                publisher_id=publisher.publisher_id,
                key_id=key.key_id,
                public_key=key.public_key,
                namespaces=[package.manifest["permissions"]["namespace"]],
            )
        ],
    ).model_dump()


async def host(ctx: MachineContext, identifier: UUID) -> DeploymentHost:
    claims = ctx.claims
    if claims.get("xarionix_principal") != "deployment":
        fail(403, "deployment_principal_required")
    await locking.administration(ctx.session, shared=True)
    value = await ctx.session.scalar(
        select(DeploymentHost)
        .where(
            DeploymentHost.id == identifier,
            DeploymentHost.issuer == claims.get("iss"),
            DeploymentHost.subject == claims.get("sub"),
            DeploymentHost.client_id == claims.get("azp"),
        )
        .with_for_update()
    )
    if value is None or value.status == "revoked":
        fail(403, "deployment_host_unavailable")
    return value


async def snapshot(ctx: Context, payload: PlanCreate, runtime: dict[str, Any]) -> dict[str, Any]:
    value = await installations.installation(ctx, payload.installation_id)
    await module_lock(ctx.session, value)
    await ctx.session.refresh(value)
    target_host = await ctx.session.get(DeploymentHost, payload.host_id, populate_existing=True)
    current = await ctx.session.get(RuntimeDeployment, value.id, populate_existing=True)
    if (
        target_host is None
        or target_host.status == "revoked"
        or (target_host.status != "active" and payload.operation not in SAFETY)
    ):
        fail(409, "deployment_host_unavailable")
    if value.module_type != "standard" or (value.status == "removed" and payload.operation not in SAFETY):
        fail(409, "deployment_standard_installation_required")
    if (
        value.generation != payload.expected_installation_generation
        or (current.generation if current else 0) != payload.expected_deployment_generation
    ):
        fail(409, "deployment_generation_conflict")
    if current and current.host_id != target_host.id:
        fail(409, "deployment_host_reassignment_not_supported")
    if (
        current is None
        and (
            await ctx.session.scalar(
                select(func.count())
                .select_from(RuntimeDeployment)
                .where(RuntimeDeployment.host_id == target_host.id)
            )
            or 0
        )
        >= 32
    ):
        fail(409, "deployment_host_capacity")
    if not current and payload.operation not in {"provision", "start"}:
        fail(409, "deployment_not_provisioned")
    if current and payload.operation == "provision" and current.desired != "absent":
        fail(409, "deployment_already_provisioned")
    package = await installations.package(
        ctx, current.package_id if current and payload.operation in SAFETY else value.package_id
    )
    if runtime["platform"] != target_host.platform:
        fail(409, "deployment_platform_incompatible")
    api_metadata: dict[str, Any] = {}
    selected_profile = current.profile if current and payload.operation in SAFETY else payload.profile
    if selected_profile == "module-api-private-v1":
        from app.domains.module_gateway.model import ModuleAPIContract

        api = await ctx.session.get(ModuleAPIContract, package.id)
        if api is None and payload.operation not in SAFETY:
            fail(409, "signed_module_api_required")
        if api is not None:
            api_metadata = {
                "api_contract": api.document,
                "api_contract_sha256": api.sha256,
                "gateway_protocol": "module-gateway-poll-v1",
            }
    if payload.operation not in SAFETY and (
        not await trusted(ctx.session, package)
        or await ctx.session.get(ModuleRetirement, value.id) is not None
    ):
        fail(409, "deployment_package_untrusted_or_retired")
    if (
        current
        and current.package_id != package.id
        and payload.operation not in {"upgrade", "rollback", *SAFETY}
    ):
        fail(409, "deployment_upgrade_required")
    if (
        payload.operation == "deprovision"
        and current
        and current.observed not in {"stopped", "not_provisioned"}
    ):
        fail(409, "deployment_stop_before_deprovision")
    return {
        **api_metadata,
        "schema_version": 1,
        "installation_id": str(value.id),
        "host_id": str(target_host.id),
        "operation": payload.operation,
        "installation_generation": value.generation,
        "expected_deployment_generation": payload.expected_deployment_generation,
        "package_id": str(package.id),
        "package_sha256": package.package_sha256,
        "package_size": package.size,
        "runtime": runtime,
        "engine_id": target_host.engine_id,
        "host_revision": target_host.revision,
        "profile": current.profile if current and payload.operation in SAFETY else payload.profile,
        "resource_policy": PROFILES[
            current.profile if current and payload.operation in SAFETY else payload.profile
        ],
        "policy": policy(ctx.config),
    }


def plan_view(value: DeploymentPlan) -> dict[str, Any]:
    return {
        "id": value.id,
        "state": value.state,
        "digest": value.digest,
        "body": value.body,
        "expires_at": value.expires_at,
        "approved_until": value.approved_until,
    }


async def prepare(ctx: Context, payload: PlanCreate, runtime: dict[str, Any]) -> DeploymentPlan:
    body = await snapshot(ctx, payload, runtime)
    old = await ctx.session.get(DeploymentPlan, payload.idempotency_key)
    if old:
        if old.digest != digest(body) or old.created_by != ctx.user.id:
            fail(409, "deployment_idempotency_conflict")
        return old
    value = DeploymentPlan(
        id=payload.idempotency_key,
        installation_id=payload.installation_id,
        host_id=payload.host_id,
        body=body,
        digest=digest(body),
        state="pending",
        created_by=ctx.user.id,
        expires_at=now() + timedelta(seconds=600),
    )
    ctx.session.add(value)
    audit(ctx, "deployment.plan_prepared", "deployment_plan", value.id)
    await ctx.session.flush()
    return value


async def approved(ctx: MachineContext, plan: DeploymentPlan) -> None:
    if (
        plan.state != "applied"
        or plan.approved_by is None
        or plan.approved_identity_id is None
        or plan.approval is None
        or plan.approval.get("digest") != plan.digest
        or plan.approval.get("policy") != policy(ctx.config)
        or digest(plan.body) != plan.digest
        or not plan.approved_until
        or plan.approved_until <= now()
        or plan.expires_at <= now()
    ):
        fail(409, "deployment_approval_expired_or_invalid")
    identity = await ctx.session.get(Identity, plan.approved_identity_id)
    user = await ctx.session.get(User, plan.approved_by)
    if not identity or not user or identity.user_id != user.id or identity.issuer != ctx.config.oidc_issuer:
        fail(403, "deployment_approver_unavailable")
    await require_platform(
        Context(ctx.session, identity, user, ctx.config, plan.approval, operator=True), serialize=False
    )


async def queue(ctx: Context, plan: DeploymentPlan, expected_digest: str) -> DeploymentJob:
    if digest(plan.body) != plan.digest or expected_digest != plan.digest:
        fail(409, "deployment_plan_digest_conflict")
    # Same order as agent check-in: administration SHARE -> host -> module.
    # This serializes generation changes with reports/quarantine on this host,
    # not with unrelated hosts or the long artifact/engine work.
    await ctx.session.get(DeploymentHost, plan.host_id, with_for_update=True)
    await module_lock(ctx.session, await installations.installation(ctx, plan.installation_id))
    await ctx.session.refresh(plan, with_for_update={"read": False})
    if plan.state == "applied":
        old = await ctx.session.get(DeploymentJob, plan.id)
        if old is None:
            fail(409, "deployment_plan_corrupt")
        return old
    if plan.state != "pending" or plan.expires_at <= now():
        fail(409, "deployment_plan_expired")
    body = plan.body
    payload = PlanCreate(
        idempotency_key=plan.id,
        installation_id=plan.installation_id,
        host_id=plan.host_id,
        operation=body["operation"],
        profile=body["profile"],
        expected_installation_generation=body["installation_generation"],
        expected_deployment_generation=body["expected_deployment_generation"],
    )
    if await snapshot(ctx, payload, body["runtime"]) != body:
        fail(409, "deployment_plan_stale")
    active = await ctx.session.scalar(
        select(DeploymentJob).where(
            DeploymentJob.installation_id == plan.installation_id,
            DeploymentJob.state.in_(["queued", "leased"]),
        )
    )
    if active:
        fail(409, "deployment_operation_in_progress")
    count = await ctx.session.scalar(
        select(func.count())
        .select_from(DeploymentJob)
        .where(DeploymentJob.host_id == plan.host_id, DeploymentJob.state.in_(["queued", "leased"]))
    )
    if (count or 0) >= 32:
        fail(409, "deployment_host_queue_full")
    until = min(
        plan.expires_at,
        datetime.fromtimestamp(float(ctx.claims["auth_time"]), UTC)
        + timedelta(seconds=ctx.config.admin_auth_max_age_seconds),
    )
    plan.state, plan.approved_by, plan.approved_identity_id, plan.approved_until = (
        "applied",
        ctx.user.id,
        ctx.identity.id,
        until,
    )
    plan.approval = {
        "digest": plan.digest,
        "policy": policy(ctx.config),
        "acr": ctx.claims["acr"],
        "auth_time": ctx.claims["auth_time"],
    }
    desired = {
        "provision": "provisioned",
        "stop": "stopped",
        "deprovision": "absent",
        "quarantine": "quarantined",
        "retire": "retired",
    }.get(body["operation"], "running")
    current = await ctx.session.get(RuntimeDeployment, plan.installation_id)
    if current and body["operation"] == "inspect":
        desired = current.desired
    generation = body["expected_deployment_generation"] + 1
    if current is None:
        current = RuntimeDeployment(
            installation_id=plan.installation_id,
            host_id=plan.host_id,
            package_id=UUID(body["package_id"]),
            installation_generation=body["installation_generation"],
            generation=generation,
            desired=desired,
            image_digest=body["runtime"]["image_digest"],
            profile=body["profile"],
        )
        ctx.session.add(current)
    else:
        current.generation, current.desired = generation, desired
        if body["operation"] not in SAFETY:
            current.package_id, current.installation_generation = (
                UUID(body["package_id"]),
                body["installation_generation"],
            )
            current.image_digest, current.profile = body["runtime"]["image_digest"], body["profile"]
        current.health = "unknown"
    job = DeploymentJob(
        id=plan.id,
        plan_id=plan.id,
        installation_id=plan.installation_id,
        host_id=plan.host_id,
        generation=generation,
        operation=body["operation"],
        body=body,
        expires_at=until,
        state="queued",
        attempts=0,
    )
    ctx.session.add(job)
    audit(
        ctx, "deployment.approved", "deployment_job", job.id, generation=generation, operation=job.operation
    )
    await ctx.session.flush()
    return job


async def authorize(
    ctx: MachineContext, host_value: DeploymentHost, job_id: UUID, fence: UUID
) -> DeploymentJob:
    job = await ctx.session.get(DeploymentJob, job_id, populate_existing=True)
    if not job or job.host_id != host_value.id:
        fail(404, "deployment_job_not_found")
    runtime = await ctx.session.get(RuntimeDeployment, job.installation_id, populate_existing=True)
    if (
        job.state != "leased"
        or job.fence != fence
        or not job.lease_until
        or job.lease_until <= now()
        or job.expires_at <= now()
        or runtime is None
        or runtime.generation != job.generation
    ):
        fail(409, "deployment_job_fenced")
    if job.operation not in SAFETY:
        if host_value.status != "active" or host_value.revision != job.body["host_revision"]:
            fail(403, "deployment_host_disabled")
        plan = await ctx.session.get(DeploymentPlan, job.plan_id)
        if plan is None:
            fail(409, "deployment_approval_missing")
        await approved(ctx, plan)
        installation = await ctx.session.get(ModuleInstallation, job.installation_id)
        package = await ctx.session.get(ModulePackage, UUID(job.body["package_id"]))
        if (
            not installation
            or not package
            or installation.status == "removed"
            or installation.generation != job.body["installation_generation"]
            or installation.package_id != package.id
            or not await trusted(ctx.session, package)
            or (await ctx.session.get(ModuleRetirement, job.installation_id)) is not None
        ):
            fail(409, "deployment_policy_changed")
    return job


async def check_in(ctx: MachineContext, value: DeploymentHost, payload: CheckIn) -> dict[str, Any]:
    if payload.sequence <= value.sequence:
        fail(409, "deployment_replay_rejected")
    value.sequence, value.last_seen = payload.sequence, now()
    await safety_reconciliation(ctx, value)
    for report in payload.reports:
        runtime = await ctx.session.get(RuntimeDeployment, report.installation_id)
        if runtime is None or runtime.host_id != value.id:
            fail(404, "deployment_runtime_not_found")
        if runtime.generation != report.generation or runtime.image_digest != report.image_digest:
            continue
        # An initial report cannot replace ACK/fencing. Only already acknowledged generations refresh health.
        job = await ctx.session.scalar(
            select(DeploymentJob).where(
                DeploymentJob.installation_id == runtime.installation_id,
                DeploymentJob.generation == runtime.generation,
                DeploymentJob.state == "succeeded",
            )
        )
        if job is not None:
            apply_report(runtime, report)
    rows = list(
        (
            await ctx.session.scalars(
                select(DeploymentJob)
                .where(DeploymentJob.host_id == value.id, DeploymentJob.state.in_(["queued", "leased"]))
                .order_by(DeploymentJob.created_at, DeploymentJob.id)
                .limit(32)
                .with_for_update()
            )
        ).all()
    )
    deliveries = []
    for job in rows:
        if job.expires_at <= now() or job.attempts >= 8:
            job.state = "expired"
            if job.operation not in SAFETY:
                runtime = await ctx.session.get(RuntimeDeployment, job.installation_id)
                if runtime and runtime.generation == job.generation:
                    # Execution may have succeeded before a lost ACK. Expiry is
                    # not permission to leave that unacknowledged process running.
                    await security_stop(ctx, value, runtime, job.body, "quarantined")
            continue
        if job.state == "leased" and job.lease_until and job.lease_until > now():
            continue
        if value.status != "active" and job.operation not in SAFETY:
            job.state = "cancelled"
            continue
        job.state, job.fence, job.lease_until = "leased", uuid4(), now() + timedelta(seconds=120)
        job.attempts += 1
        await ctx.session.flush()
        try:
            await authorize(ctx, value, job.id, job.fence)
        except HTTPException:
            job.state = "cancelled"
            continue
        package = await ctx.session.get(ModulePackage, UUID(job.body["package_id"]))
        if package is None:
            fail(409, "deployment_package_missing")
        deliveries.append(
            {
                **({"api_contract": job.body["api_contract"]} if "api_contract" in job.body else {}),
                "id": job.id,
                "fence": job.fence,
                "host_id": value.id,
                "installation_id": job.installation_id,
                "generation": job.generation,
                "operation": job.operation,
                "lease_until": job.lease_until,
                "runtime": job.body["runtime"],
                "profile": job.body["profile"],
                "engine_id": value.engine_id,
                "package_sha256": package.package_sha256,
                "package_size": package.size,
                "trust": await trust(ctx.session, package)
                if job.operation not in SAFETY
                else {"schema_version": 1, "keys": []},
            }
        )
        break
    await ctx.session.flush()
    return {"jobs": deliveries, "poll_seconds": 2}


async def safety_reconciliation(ctx: MachineContext, host_value: DeploymentHost) -> None:
    runtimes = list(
        (
            await ctx.session.scalars(
                select(RuntimeDeployment)
                .where(RuntimeDeployment.host_id == host_value.id)
                .order_by(RuntimeDeployment.installation_id)
                .limit(33)
            )
        ).all()
    )
    if len(runtimes) > 32:
        fail(409, "deployment_host_capacity")
    for runtime in runtimes:
        installation = await ctx.session.get(ModuleInstallation, runtime.installation_id)
        if installation:
            await module_lock(ctx.session, installation)
            await ctx.session.refresh(installation)
            await ctx.session.refresh(runtime)
        package = await ctx.session.get(ModulePackage, runtime.package_id)
        retirement = await ctx.session.get(ModuleRetirement, runtime.installation_id)
        unsafe = (
            host_value.status != "active"
            or installation is None
            or installation.status == "removed"
            or package is None
            or not await trusted(ctx.session, package)
            or retirement is not None
            or (
                installation.status == "installed_disabled"
                and installation.generation > runtime.installation_generation
            )
        )
        terminal = "retired" if retirement and retirement.state == "retired" else "quarantined"
        if (
            not unsafe
            or runtime.desired in {"absent", "retired"}
            or (runtime.desired == "quarantined" and terminal == "quarantined")
        ):
            continue
        # Security stop is a narrow policy operation: no artifact access, trust restoration or catalog writes.
        latest = await ctx.session.scalar(
            select(DeploymentJob)
            .where(DeploymentJob.installation_id == runtime.installation_id)
            .order_by(DeploymentJob.generation.desc())
            .limit(1)
        )
        if latest is None:
            fail(409, "deployment_history_missing")
        await security_stop(ctx, host_value, runtime, latest.body, terminal)


async def security_stop(
    ctx: MachineContext,
    host_value: DeploymentHost,
    runtime: RuntimeDeployment,
    source: dict[str, Any],
    terminal: str,
) -> None:
    installation = await ctx.session.get(ModuleInstallation, runtime.installation_id)
    if installation:
        await module_lock(ctx.session, installation)
    active = list(
        (
            await ctx.session.scalars(
                select(DeploymentJob)
                .where(
                    DeploymentJob.installation_id == runtime.installation_id,
                    DeploymentJob.state.in_(["queued", "leased"]),
                )
                .with_for_update()
            )
        ).all()
    )
    for job in active:
        job.state = "cancelled"
    await ctx.session.flush()
    runtime.generation += 1
    runtime.desired, runtime.health = terminal, "unknown"
    body = dict(source)
    body["operation"] = "retire" if terminal == "retired" else "quarantine"
    ctx.session.add(
        DeploymentJob(
            id=uuid4(),
            installation_id=runtime.installation_id,
            host_id=host_value.id,
            generation=runtime.generation,
            operation=body["operation"],
            body=body,
            state="queued",
            attempts=0,
            expires_at=now() + timedelta(hours=24),
        )
    )
    ctx.session.add(
        AuditEvent(
            action="deployment.policy_quarantine",
            resource_type="module_installation",
            resource_id=runtime.installation_id,
            request_id=ctx.request_id,
            details={"generation": runtime.generation, "host_id": str(host_value.id)},
        )
    )
    await ctx.session.flush()


def apply_report(runtime: RuntimeDeployment, report: Any) -> None:
    runtime.observed_generation, runtime.observed_image_digest = report.generation, report.image_digest
    runtime.observed, runtime.container_id = report.state, report.container_id
    runtime.health = (
        "healthy"
        if report.state == "running" and report.health == "healthy" and report.live and report.ready
        else "unhealthy"
        if report.health == "unhealthy"
        else "unknown"
    )
    runtime.last_seen, runtime.restart_count, runtime.safe_error_code = (
        now(),
        report.restart_count,
        report.safe_error_code,
    )
    if report.live:
        runtime.last_live = now()
    if report.ready and runtime.health == "healthy":
        runtime.last_ready = now()


async def acknowledge(
    ctx: MachineContext, value: DeploymentHost, job_id: UUID, payload: Receipt
) -> DeploymentJob:
    job = await ctx.session.get(DeploymentJob, job_id)
    if (
        job
        and job.host_id == value.id
        and job.fence == payload.fence
        and job.state in {"succeeded", "failed"}
    ):
        if job.result != payload.model_dump(mode="json"):
            fail(409, "deployment_receipt_conflict")
        return job
    job = await authorize(ctx, value, job_id, payload.fence)
    report = payload.report
    if (
        report.installation_id != job.installation_id
        or report.generation != job.generation
        or report.image_digest != job.body["runtime"]["image_digest"]
    ):
        fail(409, "deployment_receipt_generation_conflict")
    if not payload.success and (report.health == "healthy" or report.live or report.ready):
        fail(409, "deployment_failed_receipt_cannot_be_ready")
    if payload.success:
        if job.operation in {"start", "restart", "upgrade", "rollback", "reconcile"} and not (
            report.state == "running"
            and report.health == "healthy"
            and report.live
            and report.ready
            and report.container_id is not None
        ):
            fail(409, "deployment_readiness_required")
        if job.operation in {"provision", "stop", "quarantine", "retire"} and report.state != "stopped":
            fail(409, "deployment_stopped_state_required")
        if job.operation == "deprovision" and report.state != "not_provisioned":
            fail(409, "deployment_absent_state_required")
    runtime = await ctx.session.get(RuntimeDeployment, job.installation_id)
    if runtime is None:
        fail(409, "deployment_runtime_missing")
    apply_report(runtime, report)
    job.state, job.result = "succeeded" if payload.success else "failed", payload.model_dump(mode="json")
    await ctx.session.flush()
    return job
