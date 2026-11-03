"""Short DB snapshots, immutable plans, explicit agent attestation. Never executes packages."""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select, text

from app.core.access import Context, audit, fail, require_platform
from app.domains.installations.model import (
    ModuleDependencyPin,
    ModuleInstallation,
    ModuleInstallOperation,
    ModuleInstallPlan,
    ModuleInstanceBinding,
)
from app.domains.installations.policy import MAX_PINS, PLAN_SECONDS, digest, policy, runtime_mode, transition
from app.domains.modules.model import ModuleInstance, ModuleService
from app.domains.modules.service import connection_state
from app.domains.packages import reports
from app.domains.packages.archive import Limits, verify
from app.domains.packages.model import ModulePackage, PublisherNamespaceGrant, PublisherSigningKey
from app.domains.packages.schema import Manifest, TrustStore
from app.domains.packages.semver import Range, Version
from app.domains.packages.service import current_trust, namespace_owner, trust_store
from app.domains.packages.storage import Storage
from app.domains.rbac.model import Permission, PermissionNamespace
from app.version import VERSION


def now(ctx: Context) -> datetime:
    return datetime.fromtimestamp(ctx.clock(), UTC)


async def package(ctx: Context, identifier: UUID) -> ModulePackage:
    value = await ctx.session.get(ModulePackage, identifier, populate_existing=True)
    if value is None:
        fail(404, "package_not_found")
    return value


async def installation(ctx: Context, identifier: UUID) -> ModuleInstallation:
    value = await ctx.session.get(ModuleInstallation, identifier, populate_existing=True)
    if value is None:
        fail(404, "module_installation_not_found")
    return value


async def plan(ctx: Context, identifier: UUID, *, lock: bool = False) -> ModuleInstallPlan:
    query = select(ModuleInstallPlan).where(ModuleInstallPlan.id == identifier)
    if lock:
        query = query.with_for_update()
    value = await ctx.session.scalar(query.execution_options(populate_existing=True))
    if value is None:
        fail(404, "module_install_plan_not_found")
    if digest(value.body) != value.digest:
        fail(409, "module_install_plan_corrupt")
    return value


async def operation(ctx: Context, identifier: UUID, *, lock: bool = False) -> ModuleInstallOperation:
    query = select(ModuleInstallOperation).where(ModuleInstallOperation.id == identifier)
    if lock:
        query = query.with_for_update()
    value = await ctx.session.scalar(query.execution_options(populate_existing=True))
    if value is None:
        fail(404, "module_install_operation_not_found")
    return value


async def locks(ctx: Context, body: dict[str, Any]) -> None:
    # Administration SHARE -> sorted module identities -> namespace -> plan -> operation.
    # Dependency mutations acquire their own EX key; dependent operations take that key SHARE.
    identities = {body["module_id"]: False}
    identities.update({pin["module_id"]: True for pin in body["dependency_pins"]})
    for key, shared in sorted(identities.items()):
        await ctx.session.execute(
            text("SELECT core_lock('module_installation', :id, :shared)"), {"id": key, "shared": shared}
        )
    await ctx.session.execute(
        text("SELECT core_lock('module_namespace', :id, false)"), {"id": body["namespace"]}
    )


async def runtime(
    ctx: Context,
    value: ModuleInstallation,
    manifest: Manifest,
    *,
    facts: tuple[ModuleInstanceBinding | None, ModuleInstance | None, ModuleService | None] | None = None,
) -> dict[str, Any]:
    binding = (
        facts[0]
        if facts is not None
        else await ctx.session.get(ModuleInstanceBinding, value.id, populate_existing=True)
    )
    result: dict[str, Any] = {
        "mode": runtime_mode(manifest),
        "state": "not_provisioned",
        "instance_id": None,
        "binding_revision": binding.revision if binding else 0,
        "binding_active": bool(binding and binding.active and binding.package_id == value.package_id),
        "last_heartbeat": None,
        "agent_version": None,
        "protocol_version": None,
    }
    if manifest.module.type != "autonomous":
        return result
    result["state"] = "awaiting_connection"
    if binding and binding.instance_id:
        if facts is not None:
            _, agent, machine = facts
        else:
            agent = await ctx.session.get(ModuleInstance, binding.instance_id, populate_existing=True)
            machine = (
                await ctx.session.get(ModuleService, agent.service_id, populate_existing=True)
                if agent
                else None
            )
        result.update(
            {
                "instance_id": str(binding.instance_id),
                "last_heartbeat": agent.last_seen if agent else None,
                "agent_version": agent.agent_version if agent else None,
                "protocol_version": agent.protocol_version if agent else None,
            }
        )
        if agent and machine and result["binding_active"]:
            result["state"] = connection_state(machine, agent, ctx.config.modules_stale_seconds, now(ctx))
    return result


async def trusted(ctx: Context, value: ModulePackage, store: TrustStore) -> bool:
    key = await ctx.session.get(PublisherSigningKey, value.signing_key_id)
    manifest = Manifest.model_validate(value.manifest)
    return bool(
        value.state == "available"
        and key
        and current_trust(manifest, key.key_id, store, expected_fingerprint=key.fingerprint)
        and await namespace_owner(ctx, manifest)
        and Range.parse(manifest.compatibility.core).contains(VERSION)
    )


async def snapshot(
    ctx: Context, action: str, target_id: UUID, expected: int
) -> tuple[dict[str, Any], TrustStore]:
    """No blobs/ZIP work in this transaction. All collections have hard bounds."""
    target = await package(ctx, target_id)
    manifest = Manifest.model_validate(target.manifest)
    current = await ctx.session.scalar(
        select(ModuleInstallation)
        .where(ModuleInstallation.module_id == target.module_id)
        .execution_options(populate_existing=True)
    )
    if (current.generation if current else 0) != expected:
        fail(409, "installation_generation_conflict")
    try:
        next_state = transition(action, current.status if current else None)
    except ValueError:
        fail(409, "installation_transition_invalid")
    if current:
        if (
            current.publisher_id != target.publisher_id
            or current.namespace != manifest.permissions.namespace
            or current.module_type != manifest.module.type
        ):
            fail(409, "installation_identity_conflict")
        if action in {"enable", "disable", "uninstall"} and current.package_id != target.id:
            fail(409, "installation_package_conflict")
        if action == "update" and current.package_id == target.id:
            fail(409, "installation_package_unchanged")
        if action == "update" and Version.parse(target.version) <= Version.parse(
            (await package(ctx, current.package_id)).version
        ):
            fail(409, "installation_update_requires_newer_version")
        if action == "rollback" and (
            not current.previous_package_id or current.previous_package_id != target.id
        ):
            fail(409, "installation_rollback_target_invalid")
    store = await trust_store(ctx)
    if not await trusted(ctx, target, store):
        fail(422, "installation_package_untrusted_or_incompatible")
    rows = list(
        (
            await ctx.session.execute(
                select(ModuleInstallation, ModulePackage)
                .join(ModulePackage, ModulePackage.id == ModuleInstallation.package_id)
                .where(
                    ModuleInstallation.status != "removed", ModuleInstallation.module_id != target.module_id
                )
                .order_by(ModuleInstallation.module_id)
                .limit(257)
            )
        ).all()
    )
    if len(rows) > 256:
        fail(409, "installation_resolver_capacity_exceeded")
    known = [Manifest.model_validate(pkg.manifest) for inst, pkg in rows if await trusted(ctx, pkg, store)]
    resolution = reports.dependencies(manifest, known)
    pins = []
    reachable = {item["module_id"] for item in resolution["items"]}
    for inst, pkg in rows:
        if inst.module_id in reachable:
            pins.append(
                {
                    "installation_id": str(inst.id),
                    "module_id": inst.module_id,
                    "package_id": str(pkg.id),
                    "package_sha256": pkg.package_sha256,
                    "version": pkg.version,
                    "publisher_id": str(pkg.publisher_id),
                    "generation": inst.generation,
                    "state": inst.status,
                }
            )
    blockers: list[str] = []
    if not resolution["ready"]:
        blockers.append("dependencies_unresolved")
    if len(pins) > MAX_PINS:
        fail(409, "installation_dependency_limit")
    if any(p["state"] != "installed_enabled" for p in pins) and action not in {"disable", "uninstall"}:
        blockers.append("dependencies_not_enabled")
    dependents = []
    if current:
        dependents = list(
            (
                await ctx.session.execute(
                    select(
                        ModuleInstallation.module_id, ModuleInstallation.generation, ModuleInstallation.status
                    )
                    .join(ModuleDependencyPin, ModuleDependencyPin.installation_id == ModuleInstallation.id)
                    .where(
                        ModuleDependencyPin.dependency_id == current.id,
                        ModuleInstallation.status != "removed",
                    )
                    .order_by(ModuleInstallation.module_id)
                    .limit(257)
                )
            ).all()
        )
    if len(dependents) > 256:
        fail(409, "installation_dependent_limit")
    if dependents and action in {"update", "rollback", "uninstall"}:
        blockers.append("installed_dependents_require_explicit_replanning")
    if action == "disable" and any(row.status == "installed_enabled" for row in dependents):
        blockers.append("enabled_dependents_exist")
    catalog = await ctx.session.get(
        PermissionNamespace, manifest.permissions.namespace, populate_existing=True
    )
    if catalog and catalog.owner != target.module_id:
        fail(409, "installation_namespace_owner_conflict")
    before = await package(ctx, current.package_id) if current else None
    changes = (
        reports.diff(Manifest.model_validate(before.manifest), manifest)["permissions"]
        if before
        else {
            "added": sorted(p.key for p in manifest.permissions.definitions),
            "removed": [],
            "modified": [],
            "unchanged": [],
        }
    )
    if action == "install":
        changes = {
            "added": sorted(p.key for p in manifest.permissions.definitions),
            "removed": [],
            "modified": [],
            "unchanged": [],
        }
    elif action == "uninstall":
        changes = {
            "added": [],
            "removed": sorted(p.key for p in manifest.permissions.definitions),
            "modified": [],
            "unchanged": [],
        }
    permissions = list(
        (
            await ctx.session.scalars(
                select(Permission)
                .where(Permission.namespace == manifest.permissions.namespace)
                .order_by(Permission.key)
                .limit(2049)
            )
        ).all()
    )
    if len(permissions) > 2048:
        fail(409, "installation_permission_history_capacity")
    if any(p.protected or not p.owner_grantable for p in permissions):
        fail(409, "installation_permission_policy_conflict")
    runtime_info = (
        await runtime(ctx, current, manifest)
        if current
        else {
            "mode": runtime_mode(manifest),
            "state": "not_provisioned",
            "binding_revision": 0,
            "binding_active": False,
        }
    )
    if action == "enable":
        if runtime_info["mode"] == "not_supported_in_4c":
            blockers.append("runtime_not_supported_in_4c")
        if runtime_info["mode"] == "external_agent" and (
            not runtime_info["binding_active"] or runtime_info["state"] != "connected"
        ):
            blockers.append("autonomous_agent_not_ready")
    # Only relevant keys enter the digest, not unrelated publishers or changing heartbeats.
    verified_packages = [target, *[pkg for inst, pkg in rows if inst.module_id in reachable]]
    authorities = []
    for pkg in sorted(verified_packages, key=lambda p: str(p.id)):
        key = await ctx.session.get(PublisherSigningKey, pkg.signing_key_id)
        if key is None:
            fail(409, "installation_signing_key_missing")
        grant = await ctx.session.get(
            PublisherNamespaceGrant, pkg.manifest["permissions"]["namespace"], populate_existing=True
        )
        authorities.append(
            {
                "package_id": str(pkg.id),
                "sha256": pkg.package_sha256,
                "manifest_sha256": pkg.manifest_sha256,
                "size": pkg.size,
                "manifest": pkg.manifest,
                "signing_key_id": str(key.id),
                "fingerprint": key.fingerprint,
                "trusted": await trusted(ctx, pkg, store),
                "namespace_authority_revision": grant.updated_at.isoformat() if grant else None,
            }
        )
    return {
        "schema_version": 1,
        "action": action,
        "module_id": target.module_id,
        "package_id": str(target.id),
        "package_sha256": target.package_sha256,
        "publisher_id": str(target.publisher_id),
        "target_version": target.version,
        "module_type": manifest.module.type,
        "namespace": manifest.permissions.namespace,
        "expected_generation": expected,
        "current_package_id": str(current.package_id) if current else None,
        "current_version": before.version if before else None,
        "core_compatible": True,
        "protocol_supported": True,
        "installation_id": str(current.id) if current else None,
        "current_state": current.status if current else None,
        "next_state": next_state,
        "dependency_graph": resolution,
        "dependency_pins": pins,
        "dependents": [
            {"module_id": r.module_id, "generation": r.generation, "state": r.status} for r in dependents
        ],
        "permission_diff": changes,
        "catalog": {"owner": catalog.owner, "state": catalog.state} if catalog else None,
        "permission_generations": [
            {
                "key": p.key,
                "generation": p.definition_generation,
                "active": p.active,
                "description": p.description,
            }
            for p in permissions
        ],
        "policy": policy(ctx.config),
        "authorities": authorities,
        "runtime": {
            "mode": runtime_info["mode"],
            "binding_revision": runtime_info["binding_revision"],
            "binding_active": runtime_info["binding_active"],
        },
        "runtime_provisioning": "not_supported_in_4c",
        "blockers": sorted(blockers),
        "ready": not blockers,
        "warnings": [
            "No code execution, runtime deployment, role grants or module database migrations are performed"
        ],
    }, store


def verify_blobs(body: dict[str, Any], store: TrustStore, storage: Storage, limits: Limits) -> None:
    for authority in body["authorities"]:
        checked = verify(storage.blob(authority["sha256"]), store, limits)
        if (
            checked.package_sha256 != authority["sha256"]
            or checked.manifest_sha256 != authority["manifest_sha256"]
            or checked.manifest_data != authority["manifest"]
            or checked.size != authority["size"]
            or checked.key_fingerprint != authority["fingerprint"]
            or not checked.core_compatible
        ):
            fail(409, "installation_blob_registry_mismatch")


async def create_plan(ctx: Context, identifier: UUID, body: dict[str, Any]) -> ModuleInstallPlan:
    existing = await ctx.session.get(ModuleInstallPlan, identifier)
    if existing:
        if existing.digest != digest(body) or existing.created_by != ctx.user.id:
            fail(409, "installation_idempotency_conflict")
        return existing
    value = ModuleInstallPlan(
        id=identifier,
        action=body["action"],
        module_id=body["module_id"],
        package_id=UUID(body["package_id"]),
        expected_generation=body["expected_generation"],
        digest=digest(body),
        body=body,
        state="pending",
        created_by=ctx.user.id,
        expires_at=now(ctx) + timedelta(seconds=PLAN_SECONDS),
    )
    ctx.session.add(value)
    audit(
        ctx,
        "module.plan_created",
        "module_install_plan",
        identifier,
        plan_digest=value.digest,
        operation_action=value.action,
    )
    await ctx.session.flush()
    return value


async def approve(ctx: Context, value: ModuleInstallPlan, expected_digest: str) -> ModuleInstallPlan:
    if value.digest != expected_digest:
        fail(409, "installation_plan_digest_conflict")
    if value.state == "approved":
        return value
    if value.state != "pending" or value.expires_at <= now(ctx) or not value.body["ready"]:
        fail(409, "installation_plan_not_approvable")
    body, _ = await snapshot(ctx, value.action, value.package_id, value.expected_generation)
    if body != value.body:
        fail(409, "installation_plan_stale")
    value.state, value.approved_by, value.approved_identity_id = "approved", ctx.user.id, ctx.identity.id
    value.approved_at = now(ctx)
    value.approved_until = min(
        value.expires_at,
        datetime.fromtimestamp(float(ctx.claims["auth_time"]), UTC)
        + timedelta(seconds=ctx.config.admin_auth_max_age_seconds),
    )
    value.approval = {
        "digest": value.digest,
        "policy": policy(ctx.config),
        "acr": ctx.claims["acr"],
        "auth_time": ctx.claims["auth_time"],
    }
    audit(ctx, "module.plan_approved", "module_install_plan", value.id, plan_digest=value.digest)
    await ctx.session.flush()
    return value


async def cancel(ctx: Context, value: ModuleInstallPlan) -> ModuleInstallPlan:
    if value.state == "cancelled":
        return value
    if value.state == "applied":
        fail(409, "installation_plan_already_applied")
    value.state = "cancelled"
    audit(ctx, "module.plan_cancelled", "module_install_plan", value.id)
    await ctx.session.flush()
    return value


async def bind(
    ctx: Context,
    value: ModuleInstallation,
    instance_id: UUID | None,
    package_sha256: str,
    expected_generation: int,
    expected_revision: int,
) -> ModuleInstanceBinding:
    await require_platform(ctx, serialize=False)
    await ctx.session.execute(
        text("SELECT core_lock('module_installation', :id, false)"), {"id": value.module_id}
    )
    await ctx.session.refresh(value)
    pkg = await package(ctx, value.package_id)
    if (
        value.status == "removed"
        or value.module_type != "autonomous"
        or value.generation != expected_generation
        or pkg.package_sha256 != package_sha256
    ):
        fail(409, "installation_binding_conflict")
    if not await trusted(ctx, pkg, await trust_store(ctx)):
        fail(409, "installation_binding_package_untrusted")
    agent: ModuleInstance | None = None
    if instance_id:
        # Match the existing service/instance lock order. Binding to an equal module key is
        # necessary but never sufficient: the admin explicitly attests the exact package SHA.
        agent = await ctx.session.get(ModuleInstance, instance_id)
        if agent is None:
            fail(404, "module_instance_not_found")
        machine = await ctx.session.scalar(
            select(ModuleService).where(ModuleService.id == agent.service_id).with_for_update(read=True)
        )
        await ctx.session.refresh(agent, with_for_update={"read": False})
        if (
            machine is None
            or machine.status != "active"
            or agent.status != "active"
            or machine.module_key != value.module_id
            or agent.protocol_version not in {None, 1}
        ):
            fail(409, "installation_instance_incompatible")
        await ctx.session.execute(
            text("SELECT core_lock('module_instance_binding', :id, false)"), {"id": str(instance_id)}
        )
        other = await ctx.session.scalar(
            select(ModuleInstanceBinding).where(
                ModuleInstanceBinding.instance_id == instance_id,
                ModuleInstanceBinding.installation_id != value.id,
            )
        )
        if other:
            fail(409, "installation_instance_already_bound")
    old = await ctx.session.get(ModuleInstanceBinding, value.id, populate_existing=True)
    if (old.revision if old else 0) != expected_revision:
        fail(409, "installation_binding_revision_conflict")
    if old:
        old.instance_id, old.package_id, old.active = instance_id, pkg.id, instance_id is not None
        old.revision += 1
        old.bound_by = ctx.user.id
    else:
        old = ModuleInstanceBinding(
            installation_id=value.id,
            instance_id=instance_id,
            package_id=pkg.id,
            active=instance_id is not None,
            revision=1,
            bound_by=ctx.user.id,
        )
        ctx.session.add(old)
    audit(
        ctx,
        "module.instance_bound" if instance_id else "module.instance_unbound",
        "module_installation",
        value.id,
        instance_id=str(instance_id) if instance_id else None,
        package_sha256=package_sha256,
        binding_revision=old.revision,
    )
    await ctx.session.flush()
    if agent and not agent.installation_managed:
        agent.installation_managed = True
        await ctx.session.flush()
    return old


async def view(ctx: Context, value: ModuleInstallation) -> dict[str, Any]:
    return (await views(ctx, [value]))[0]


async def views(ctx: Context, values: Sequence[ModuleInstallation]) -> list[dict[str, Any]]:
    """Constant query count for a bounded page, including missing bindings (no negative-cache N+1)."""
    if not values:
        return []
    packages = {
        p.id: p
        for p in (
            await ctx.session.scalars(
                select(ModulePackage).where(ModulePackage.id.in_([v.package_id for v in values]))
            )
        ).all()
    }
    keys = {
        k.id: k
        for k in (
            await ctx.session.scalars(
                select(PublisherSigningKey).where(
                    PublisherSigningKey.id.in_([p.signing_key_id for p in packages.values()])
                )
            )
        ).all()
    }
    namespaces = {
        n.name: n
        for n in (
            await ctx.session.scalars(
                select(PermissionNamespace).where(PermissionNamespace.name.in_([v.namespace for v in values]))
            )
        ).all()
    }
    bindings = {
        b.installation_id: b
        for b in (
            await ctx.session.scalars(
                select(ModuleInstanceBinding).where(
                    ModuleInstanceBinding.installation_id.in_([v.id for v in values])
                )
            )
        ).all()
    }
    agents = {
        a.id: a
        for a in (
            await ctx.session.scalars(
                select(ModuleInstance).where(
                    ModuleInstance.id.in_([b.instance_id for b in bindings.values() if b.instance_id])
                )
            )
        ).all()
    }
    machines = {
        m.id: m
        for m in (
            await ctx.session.scalars(
                select(ModuleService).where(ModuleService.id.in_([a.service_id for a in agents.values()]))
            )
        ).all()
    }
    store = await trust_store(ctx)
    result = []
    for value in values:
        pkg = packages.get(value.package_id)
        key = keys.get(pkg.signing_key_id) if pkg else None
        if pkg is None or key is None:
            fail(503, "installation_registry_reference_missing")
        manifest = Manifest.model_validate(pkg.manifest)
        ns = namespaces.get(value.namespace)
        trusted_now = bool(
            pkg.state == "available"
            and (ns is None or ns.owner == value.module_id)
            and current_trust(manifest, key.key_id, store, expected_fingerprint=key.fingerprint)
            and Range.parse(manifest.compatibility.core).contains(VERSION)
        )
        binding = bindings.get(value.id)
        agent = agents.get(binding.instance_id) if binding and binding.instance_id else None
        machine = machines.get(agent.service_id) if agent else None
        result.append(
            {
                "id": value.id,
                "module_id": value.module_id,
                "publisher_id": value.publisher_id,
                "package_id": pkg.id,
                "package_sha256": pkg.package_sha256,
                "version": pkg.version,
                "module_type": value.module_type,
                "namespace": value.namespace,
                "status": value.status,
                "generation": value.generation,
                "previous_package_id": value.previous_package_id,
                "created_at": value.created_at,
                "updated_at": value.updated_at,
                "current_trust": trusted_now,
                "runtime": await runtime(ctx, value, manifest, facts=(binding, agent, machine)),
            }
        )
    return result


def plan_view(value: ModuleInstallPlan) -> dict[str, Any]:
    return {
        "id": value.id,
        "digest": value.digest,
        "state": value.state,
        "created_at": value.created_at,
        "expires_at": value.expires_at,
        "approved_by": value.approved_by,
        "approved_at": value.approved_at,
        "approved_until": value.approved_until,
        "plan": value.body,
    }


def operation_view(value: ModuleInstallOperation) -> dict[str, Any]:
    return {
        "id": value.id,
        "plan_id": value.plan_id,
        "state": value.state,
        "attempts": value.attempts,
        "lease_until": value.lease_until,
        "started_at": value.started_at,
        "completed_at": value.completed_at,
        "safe_error_code": value.safe_error_code,
        "failures": value.failures,
        "correlation_id": value.correlation_id,
    }
