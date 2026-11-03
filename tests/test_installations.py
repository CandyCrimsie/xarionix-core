"""Pure contracts and decision tests; actual privilege/transaction tests live in integration."""

import asyncio
import copy
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from package_helpers import manifest_data, package
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.installation_schemas import BindInstance, PlanCreate, PlanDigest
from app.core.access import Context
from app.domains.identity.model import Identity
from app.domains.installations import executor, policy, service
from app.domains.installations.model import (
    ModuleInstallation,
    ModuleInstallPlan,
)
from app.domains.packages.archive import Limits
from app.domains.packages.codec import PackageError
from app.domains.packages.model import ModulePackage, PublisherSigningKey
from app.domains.packages.schema import TrustStore
from app.domains.packages.storage import Storage
from app.domains.rbac.model import PermissionNamespace
from app.domains.registry import load_models
from app.domains.users.model import User


def result(*rows):
    value = MagicMock()
    value.all.return_value = list(rows)
    return value


@pytest.fixture
def context(settings, monkeypatch):
    load_models()
    session = MagicMock(spec=AsyncSession)
    for name in ("get", "scalar", "scalars", "execute", "flush", "refresh"):
        setattr(session, name, AsyncMock())
    session.get.return_value = None
    session.scalar.return_value = None
    session.scalars.return_value = result()
    session.execute.return_value = result()
    user = User(id=uuid.uuid4(), status="active")
    identity = Identity(
        id=uuid.uuid4(),
        user_id=user.id,
        issuer=settings.oidc_issuer,
        subject="subject",
        principal_type="human",
    )
    ctx = Context(session, identity, user, settings, {"acr": "mfa", "auth_time": 100}, clock=lambda: 100)
    monkeypatch.setattr(service, "trust_store", AsyncMock(return_value=TrustStore(schema_version=1, keys=[])))
    monkeypatch.setattr(service, "trusted", AsyncMock(return_value=True))
    monkeypatch.setattr(service, "require_platform", AsyncMock())
    return ctx


def pkg(data=None):
    data = data or manifest_data()
    return ModulePackage(
        id=uuid.uuid4(),
        module_id=data["module"]["id"],
        version=data["module"]["version"],
        publisher_id=uuid.uuid4(),
        signing_key_id=uuid.uuid4(),
        package_sha256="a" * 64,
        manifest_sha256="b" * 64,
        size=100,
        state="available",
        manifest=data,
    )


def inst(package, **kw):
    values = {
        "id": uuid.uuid4(),
        "module_id": package.module_id,
        "publisher_id": package.publisher_id,
        "package_id": package.id,
        "namespace": package.manifest["permissions"]["namespace"],
        "module_type": package.manifest["module"]["type"],
        "status": "installed_disabled",
        "generation": 1,
    }
    return ModuleInstallation(**(values | kw))


def prepare_context(ctx, target, current=None):
    key = PublisherSigningKey(id=target.signing_key_id, key_id="test-key", fingerprint="c" * 64)

    async def get(model, identifier, **kwargs):
        if model is ModulePackage:
            return target
        if model is PublisherSigningKey:
            return key
        return None

    ctx.session.get.side_effect = get
    ctx.session.scalar.return_value = current


@pytest.mark.parametrize(
    "action,state,expected",
    [
        ("install", None, "installed_disabled"),
        ("install", "removed", "installed_disabled"),
        ("enable", "installed_disabled", "installed_enabled"),
        ("disable", "installed_enabled", "installed_disabled"),
        ("update", "installed_enabled", "installed_disabled"),
        ("rollback", "installed_disabled", "installed_disabled"),
        ("uninstall", "installed_disabled", "removed"),
    ],
)
def test_state_machine(action, state, expected):
    assert policy.transition(action, state) == expected


@pytest.mark.parametrize(
    "action,state",
    [
        ("install", "installed_enabled"),
        ("enable", None),
        ("uninstall", "installed_enabled"),
        ("execute", None),
    ],
)
def test_invalid_transitions(action, state):
    with pytest.raises(ValueError):
        policy.transition(action, state)


def test_digest_binds_all_security_references_and_is_canonical(settings):
    body = {
        "module": "one",
        "action": "install",
        "pins": [{"sha": "a" * 64}],
        "policy": policy.policy(settings),
    }
    assert policy.digest(body) == policy.digest(dict(reversed(list(body.items()))))
    for name in body:
        changed = copy.deepcopy(body)
        changed[name] = None
        assert policy.digest(changed) != policy.digest(body)


@pytest.mark.parametrize(
    "model,payload",
    [
        (PlanCreate, {"action": "install", "package_id": str(uuid.uuid4()), "company_id": str(uuid.uuid4())}),
        (PlanCreate, {"action": "install", "package_id": str(uuid.uuid4()), "expected_generation": True}),
        (PlanDigest, {"digest": "unsigned"}),
        (
            BindInstance,
            {
                "instance_id": None,
                "package_sha256": "a" * 64,
                "expected_generation": 1,
                "expected_revision": 0,
                "owner_user_id": "inject",
            },
        ),
    ],
)
def test_strict_inputs_reject_authority_injection(model, payload):
    with pytest.raises(ValueError):
        model.model_validate(payload)


@pytest.mark.parametrize(
    "action,status",
    [
        ("install", None),
        ("enable", "installed_disabled"),
        ("disable", "installed_enabled"),
        ("uninstall", "installed_disabled"),
    ],
)
async def test_snapshot_has_explicit_identity_policy_and_no_automatic_runtime(context, action, status):
    target = pkg()
    current = inst(target, status=status) if status else None
    prepare_context(context, target, current)
    body, _ = await service.snapshot(context, action, target.id, 1 if current else 0)
    assert body["ready"] and body["package_sha256"] == target.package_sha256
    assert body["policy"]["core"] and body["runtime_provisioning"] == "not_supported_in_4c"
    assert body["runtime"]["mode"] == "metadata_only" and body["dependency_pins"] == []
    assert body["permission_diff"]["added"] == ([] if current else ["testnet.objects.read"])
    assert body["authorities"][0]["fingerprint"] == "c" * 64


@pytest.mark.parametrize(
    "mismatch", ["generation", "publisher", "namespace", "type", "package", "same_update", "bad_rollback"]
)
async def test_snapshot_rejects_identity_rebinding_and_stale_generations(context, mismatch):
    target = pkg()
    current = inst(target)
    action, generation = "enable", 1
    if mismatch == "generation":
        generation = 2
    if mismatch == "publisher":
        current.publisher_id = uuid.uuid4()
    if mismatch == "namespace":
        current.namespace = "another"
    if mismatch == "type":
        current.module_type = "autonomous"
    if mismatch == "package":
        current.package_id = uuid.uuid4()
    if mismatch == "same_update":
        action = "update"
    if mismatch == "bad_rollback":
        action = "rollback"
    prepare_context(context, target, current)
    with pytest.raises(HTTPException) as error:
        await service.snapshot(context, action, target.id, generation)
    assert error.value.status_code == 409


async def test_snapshot_missing_dependency_blocks_approval_without_fabricating_installations(context):
    data = manifest_data()
    data["dependencies"] = [
        {"module_id": "missing-module", "publisher_id": "missing-publisher", "version": ">=1.0.0"}
    ]
    target = pkg(data)
    prepare_context(context, target)
    body, _ = await service.snapshot(context, "install", target.id, 0)
    assert body["blockers"] == ["dependencies_unresolved"] and not body["ready"]
    assert body["dependency_graph"]["items"][0]["state"] == "missing"


async def test_snapshot_cannot_change_catalog_owner(context):
    target = pkg()
    prepare_context(context, target)
    get = context.session.get.side_effect

    async def owner(model, identifier, **kw):
        return (
            PermissionNamespace(name="testnet", owner="other-module", state="reserved")
            if model is PermissionNamespace
            else await get(model, identifier, **kw)
        )

    context.session.get.side_effect = owner
    with pytest.raises(HTTPException, match="installation_namespace_owner_conflict"):
        await service.snapshot(context, "install", target.id, 0)


async def test_snapshot_rejects_registry_and_graph_capacity(context):
    target = pkg()
    prepare_context(context, target)
    context.session.execute.return_value = result(*[(inst(target), target)] * 257)
    with pytest.raises(HTTPException, match="installation_resolver_capacity_exceeded"):
        await service.snapshot(context, "install", target.id, 0)


async def test_install_plan_create_approve_cancel_and_immutable_receipt(context, monkeypatch):
    target = pkg()
    prepare_context(context, target)
    body, _ = await service.snapshot(context, "install", target.id, 0)
    context.session.get.side_effect = None
    context.session.get.return_value = None
    value = await service.create_plan(context, uuid.uuid4(), body)
    monkeypatch.setattr(service, "snapshot", AsyncMock(return_value=(body, None)))
    approved = await service.approve(context, value, value.digest)
    assert approved.state == "approved" and approved.approval["digest"] == value.digest
    assert "jwt" not in str(approved.approval).lower()
    assert approved.approved_until <= value.expires_at
    assert service.plan_view(value)["plan"] is body
    assert (await service.approve(context, value, value.digest)).state == "approved"
    assert (await service.cancel(context, value)).state == "cancelled"
    assert (await service.cancel(context, value)).state == "cancelled"
    with pytest.raises(HTTPException):
        await service.approve(context, value, value.digest)
    value.state = "applied"
    with pytest.raises(HTTPException):
        await service.cancel(context, value)


@pytest.mark.parametrize("change", ["digest", "expired", "blocked", "snapshot"])
async def test_approval_fail_closed(context, monkeypatch, change):
    target = pkg()
    prepare_context(context, target)
    body, _ = await service.snapshot(context, "install", target.id, 0)
    context.session.get.side_effect = None
    context.session.get.return_value = None
    value = await service.create_plan(context, uuid.uuid4(), body)
    expected = value.digest
    if change == "digest":
        expected = "d" * 64
    if change == "expired":
        value.expires_at = datetime.fromtimestamp(99, UTC)
    if change == "blocked":
        value.body["ready"] = False
    fresh = copy.deepcopy(body)
    if change == "snapshot":
        fresh["package_sha256"] = "e" * 64
    monkeypatch.setattr(service, "snapshot", AsyncMock(return_value=(fresh, None)))
    with pytest.raises(HTTPException):
        await service.approve(context, value, expected)


async def test_lookup_not_found_and_digest_corruption(context):
    for lookup in (service.package, service.installation, service.plan, service.operation):
        with pytest.raises(HTTPException) as error:
            await lookup(context, uuid.uuid4())
        assert error.value.status_code == 404
    value = ModuleInstallPlan(id=uuid.uuid4(), body={"one": 1}, digest="f" * 64)
    context.session.scalar.return_value = value
    with pytest.raises(HTTPException, match="module_install_plan_corrupt"):
        await service.plan(context, value.id, lock=True)
    value.digest = policy.digest(value.body)
    assert await service.plan(context, value.id) is value


def test_real_blob_verification_rejects_tampering_and_wrong_registry(tmp_path):
    path, trust, report = package(tmp_path / "bundle")
    storage = Storage(tmp_path / "cas")
    storage.publish(path, report["package_sha256"])
    body = {
        "authorities": [
            {
                "sha256": report["package_sha256"],
                "manifest_sha256": report["manifest_sha256"],
                "manifest": manifest_data(),
                "size": path.stat().st_size,
                "fingerprint": report["key_fingerprint"],
            }
        ]
    }
    service.verify_blobs(body, trust, storage, Limits())
    body["authorities"][0]["size"] += 1
    with pytest.raises(HTTPException):
        service.verify_blobs(body, trust, storage, Limits())
    blob = storage.blob(report["package_sha256"])
    blob.chmod(0o600)
    blob.write_bytes(b"not a signed archive")
    with pytest.raises(PackageError):
        service.verify_blobs(body, trust, storage, Limits())


async def test_executor_file_failure_is_journaled_without_changing_catalog(context, monkeypatch, tmp_path):
    identifier, fence = uuid.uuid4(), uuid.uuid4()
    body = {"authorities": []}
    monkeypatch.setattr(executor, "claim", AsyncMock(return_value=(body, None, fence, None)))
    failure = AsyncMock()
    monkeypatch.setattr(executor, "record_failure", failure)

    def fault(phase):
        if phase == "after_verification":
            raise PackageError("artifact_integrity_mismatch")

    with pytest.raises(PackageError):
        await executor.apply(
            MagicMock(), context.config, Storage(tmp_path / "cas"), identifier, "a" * 64, fault=fault
        )
    assert failure.call_args.args[-1] == "artifact_integrity_mismatch"
    receipt = {"id": str(identifier), "state": "succeeded"}
    monkeypatch.setattr(executor, "claim", AsyncMock(return_value=(body, None, fence, receipt)))
    assert (
        await executor.apply(MagicMock(), context.config, Storage(tmp_path / "cas"), identifier, "a" * 64)
        == receipt
    )


async def test_cancelled_verifier_does_not_release_lease_while_thread_runs(monkeypatch, context, tmp_path):
    import threading

    started, release = threading.Event(), threading.Event()

    def verify(*args):
        started.set()
        assert release.wait(2)

    monkeypatch.setattr(executor, "claim", AsyncMock(return_value=({}, None, uuid.uuid4(), None)))
    monkeypatch.setattr(service, "verify_blobs", verify)
    storage = Storage(tmp_path / "cas")
    task = asyncio.create_task(executor.apply(MagicMock(), context.config, storage, uuid.uuid4(), "a" * 64))
    assert await asyncio.to_thread(started.wait, 2)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    # Both original slots can be reclaimed after the bounded worker joined.
    a, b = storage.lease(), storage.lease()
    a.close()
    b.close()


@pytest.mark.parametrize("count", [1, 100])
async def test_installation_list_has_constant_queries_even_without_bindings(context, count):
    target = pkg()
    values = [inst(target) for _ in range(count)]
    key = PublisherSigningKey(id=target.signing_key_id, key_id="test-key", fingerprint="c" * 64)
    namespace = PermissionNamespace(name=values[0].namespace, owner=target.module_id, state="disabled")
    context.session.scalars.side_effect = [
        result(target),
        result(key),
        result(namespace),
        result(),
        result(),
        result(),
    ]
    output = await service.views(context, values)
    assert len(output) == count and all(row["runtime"]["state"] == "not_provisioned" for row in output)
    assert context.session.scalars.await_count == 6
    context.session.get.assert_not_awaited()
    assert await service.views(context, []) == []
