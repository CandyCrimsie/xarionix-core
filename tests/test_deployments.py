import os
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access import Context
from app.core.authentication import verified_deployment_claims
from app.domains.deployments import service
from app.domains.deployments.contracts import CheckIn, PlanCreate, RuntimeReport, digest
from app.domains.deployments.model import (
    DeploymentHost,
    DeploymentJob,
    DeploymentPlan,
    ModuleRetirement,
    RuntimeDeployment,
)
from app.domains.identity.model import Identity
from app.domains.installations.model import ModuleInstallation
from app.domains.modules.authorization import MachineContext
from app.domains.packages.model import ModulePackage
from app.domains.registry import load_models
from app.domains.users.model import User
from app.integrations.keycloak.oidc import OIDCVerifier
from app.main import create_app


@pytest.mark.parametrize("disconnected", [False, True])
async def test_artifact_descriptor_closes_even_before_first_stream_chunk(tmp_path, monkeypatch, disconnected):
    from app.api.v1.deployments import ArtifactResponse, StreamingResponse

    path = tmp_path / "artifact"
    path.write_bytes(b"verified bytes")
    descriptor = os.open(path, os.O_RDONLY)
    response = ArtifactResponse(descriptor, path.stat().st_size, "a" * 64)
    monkeypatch.setattr(
        StreamingResponse, "__call__", AsyncMock(side_effect=ConnectionError if disconnected else None)
    )
    if disconnected:
        with pytest.raises(ConnectionError):
            await response({}, AsyncMock(), AsyncMock())
    else:
        await response({}, AsyncMock(), AsyncMock())
    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.fixture
def context(settings, monkeypatch):
    load_models()
    db = MagicMock(spec=AsyncSession)
    for name in ("get", "execute", "scalar", "scalars", "refresh", "flush"):
        setattr(db, name, AsyncMock())
    db.get.return_value = None
    db.scalar.return_value = None
    user = User(id=uuid.uuid4(), status="active")
    identity = Identity(
        id=uuid.uuid4(), user_id=user.id, issuer=settings.oidc_issuer, subject="human", principal_type="human"
    )
    ctx = Context(db, identity, user, settings, {"acr": "step-up", "auth_time": time.time()})
    monkeypatch.setattr(service, "trusted", AsyncMock(return_value=True))
    monkeypatch.setattr(service, "require_platform", AsyncMock())
    return ctx


@pytest.fixture
def setup(context):
    installation = ModuleInstallation(
        id=uuid.uuid4(),
        module_id="hello-runtime",
        module_type="standard",
        generation=1,
        status="installed_disabled",
        package_id=uuid.uuid4(),
        namespace="hello",
    )
    host = DeploymentHost(
        id=uuid.uuid4(),
        engine_id="test-engine",
        platform="linux/amd64",
        status="active",
        revision=1,
        sequence=0,
    )
    package = ModulePackage(
        id=installation.package_id,
        manifest={"permissions": {"namespace": "hello"}},
        size=100,
        package_sha256="a" * 64,
    )
    runtime_contract = {
        "schema_version": 1,
        "engine": "oci",
        "platform": "linux/amd64",
        "image_digest": "sha256:" + "b" * 64,
        "config_digest": "sha256:" + "c" * 64,
        "health_contract": "http-python-v1",
        "health_port": 8080,
    }
    objects = {
        (ModuleInstallation, installation.id): installation,
        (DeploymentHost, host.id): host,
        (ModulePackage, package.id): package,
    }

    async def get(model, identifier, **kwargs):
        return objects.get((model, identifier))

    context.session.get.side_effect = get
    payload = PlanCreate(
        idempotency_key=uuid.uuid4(),
        installation_id=installation.id,
        host_id=host.id,
        operation="start",
        expected_installation_generation=1,
        expected_deployment_generation=0,
    )
    return installation, host, package, runtime_contract, objects, payload


async def test_plan_binds_exact_package_host_policy_generations_and_new_approval(context, setup):
    installation, host, package, contract, objects, payload = setup
    plan = await service.prepare(context, payload, contract)
    assert plan.state == "pending" and plan.digest == digest(plan.body)
    assert plan.body["package_sha256"] == package.package_sha256
    assert plan.body["engine_id"] == host.engine_id and plan.body["installation_generation"] == 1
    objects[DeploymentPlan, plan.id] = plan
    assert await service.prepare(context, payload, contract) is plan
    context.session.scalar.side_effect = [0, None, 0]
    job = await service.queue(context, plan, plan.digest)
    assert job.state == "queued" and job.generation == 1 and job.plan_id == plan.id
    assert plan.approved_until <= datetime.fromtimestamp(context.claims["auth_time"], UTC) + timedelta(
        seconds=context.config.admin_auth_max_age_seconds
    )
    assert not any("secret" in key for key in plan.approval)


@pytest.mark.parametrize("operation", ["start", "restore"])
async def test_restore_can_select_compatible_target_image_but_still_requires_storage_validation(
    context, setup, monkeypatch, operation
):
    installation, host, package, contract, objects, payload = setup
    objects[RuntimeDeployment, installation.id] = RuntimeDeployment(
        installation_id=installation.id,
        host_id=host.id,
        package_id=uuid.uuid4(),
        generation=1,
        desired="quarantined",
        observed="stopped",
        profile="offline-small-v1",
    )
    validator = AsyncMock(
        side_effect=HTTPException(409, detail={"code": "storage_restore_validation_required"})
    )
    monkeypatch.setattr(service.storage_service, "snapshot", validator)
    with pytest.raises(HTTPException) as error:
        await service.snapshot(
            context,
            payload.model_copy(update={"operation": operation, "expected_deployment_generation": 1}),
            contract,
        )
    assert error.value.detail["code"] == (
        "storage_restore_validation_required" if operation == "restore" else "deployment_upgrade_required"
    )
    assert validator.await_count == (1 if operation == "restore" else 0)


@pytest.mark.parametrize(
    "kind",
    [
        "installation_generation",
        "deployment_generation",
        "platform",
        "host",
        "autonomous",
        "removed",
        "untrusted",
        "retired",
    ],
)
async def test_plan_cannot_bypass_generation_identity_or_trust(context, setup, kind):
    installation, host, package, contract, objects, payload = setup
    if kind == "installation_generation":
        installation.generation = 2
    elif kind == "deployment_generation":
        payload = payload.model_copy(update={"expected_deployment_generation": 4})
    elif kind == "platform":
        host.platform = "linux/arm64"
    elif kind == "host":
        host.status = "disabled"
    elif kind == "autonomous":
        installation.module_type = "autonomous"
    elif kind == "removed":
        installation.status = "removed"
    elif kind == "untrusted":
        service.trusted.return_value = False
    elif kind == "retired":
        objects[ModuleRetirement, installation.id] = ModuleRetirement(
            installation_id=installation.id, state="retired"
        )
    with pytest.raises(HTTPException):
        await service.prepare(context, payload, contract)


@pytest.mark.parametrize("kind", ["digest", "expiry", "cancelled", "queue_full", "busy", "changed_policy"])
async def test_job_creation_needs_fresh_exact_snapshot_and_bounded_queue(context, setup, kind):
    *_, contract, objects, payload = setup
    plan = await service.prepare(context, payload, contract)
    requested = plan.digest
    if kind == "digest":
        requested = "0" * 64
    elif kind == "expiry":
        plan.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    elif kind == "cancelled":
        plan.state = "cancelled"
    elif kind == "queue_full":
        context.session.scalar.side_effect = [0, None, 32]
    elif kind == "busy":
        context.session.scalar.side_effect = [0, DeploymentJob(id=uuid.uuid4())]
    elif kind == "changed_policy":
        plan.body["resource_policy"] = {"memory": 999999999}
    with pytest.raises(HTTPException):
        await service.queue(context, plan, requested)


@pytest.mark.parametrize("operation", ["stop", "inspect", "deprovision", "quarantine", "retire"])
async def test_safety_job_never_rebinds_runtime_to_new_installation_package(context, setup, operation):
    installation, host, package, contract, objects, payload = setup
    old_package = ModulePackage(id=uuid.uuid4(), package_sha256="d" * 64, size=101)
    runtime = RuntimeDeployment(
        installation_id=installation.id,
        host_id=host.id,
        package_id=old_package.id,
        generation=1,
        installation_generation=1,
        desired="stopped",
        observed="stopped",
        image_digest=contract["image_digest"],
        profile="offline-small-v1",
    )
    objects[ModulePackage, old_package.id] = old_package
    objects[RuntimeDeployment, installation.id] = runtime
    payload = payload.model_copy(update={"operation": operation, "expected_deployment_generation": 1})
    plan = await service.prepare(context, payload, contract)
    context.session.scalar.side_effect = [None, 0]
    await service.queue(context, plan, plan.digest)
    assert runtime.package_id == old_package.id and runtime.image_digest == contract["image_digest"]
    assert runtime.generation == 2
    if operation == "inspect":
        assert runtime.desired == "stopped"


async def test_authorization_rechecks_host_fence_expiry_generation_and_current_package(context, setup):
    installation, host, package, contract, objects, payload = setup
    runtime = RuntimeDeployment(
        installation_id=installation.id, host_id=host.id, package_id=package.id, generation=1
    )
    objects[RuntimeDeployment, installation.id] = runtime
    job = DeploymentJob(
        id=uuid.uuid4(),
        installation_id=installation.id,
        host_id=host.id,
        operation="stop",
        state="leased",
        fence=uuid.uuid4(),
        generation=1,
        lease_until=datetime.now(UTC) + timedelta(seconds=20),
        expires_at=datetime.now(UTC) + timedelta(seconds=100),
    )
    objects[DeploymentJob, job.id] = job
    machine = MachineContext(
        context.session, context.config, {"xarionix_principal": "deployment"}, "test-request"
    )
    assert await service.authorize(machine, host, job.id, job.fence) is job
    for changes in (
        {"fence": uuid.uuid4()},
        {"generation": 2},
        {"lease_until": datetime.now(UTC) - timedelta(seconds=1)},
        {"state": "expired"},
    ):
        original = {k: getattr(job, k) for k in changes}
        for key, value in changes.items():
            setattr(job, key, value)
        with pytest.raises(HTTPException):
            await service.authorize(machine, host, job.id, original.get("fence", job.fence))
        for key, value in original.items():
            setattr(job, key, value)


async def test_heartbeat_cannot_forge_an_unacknowledged_runtime_generation(context, setup):
    installation, host, package, contract, objects, payload = setup
    runtime = RuntimeDeployment(
        installation_id=installation.id,
        host_id=host.id,
        generation=1,
        image_digest=contract["image_digest"],
        health="unknown",
    )
    objects[RuntimeDeployment, installation.id] = runtime
    machine = MachineContext(context.session, context.config, {}, "request-test")
    report = RuntimeReport(
        installation_id=installation.id,
        generation=1,
        image_digest=contract["image_digest"],
        state="running",
        health="healthy",
        live=True,
        ready=True,
    )
    from unittest.mock import patch

    with patch.object(service, "safety_reconciliation", AsyncMock()):
        rows = MagicMock()
        rows.all.return_value = []
        context.session.scalars.return_value = rows
        await service.check_in(machine, host, CheckIn(sequence=1, reports=[report]))
        assert runtime.health == "unknown"
        with pytest.raises(HTTPException, match="replay"):
            await service.check_in(machine, host, CheckIn(sequence=1))


async def test_expired_unacknowledged_execution_queues_only_a_fenced_security_stop(
    context, setup, monkeypatch
):
    installation, host, package, contract, objects, payload = setup
    body = await service.snapshot(context, payload, contract)
    runtime = RuntimeDeployment(
        installation_id=installation.id,
        host_id=host.id,
        package_id=package.id,
        generation=1,
        desired="running",
        health="unknown",
    )
    objects[RuntimeDeployment, installation.id] = runtime
    old = DeploymentJob(
        id=uuid.uuid4(),
        installation_id=installation.id,
        host_id=host.id,
        generation=1,
        operation="start",
        body=body,
        state="leased",
        attempts=1,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    rows, empty = MagicMock(), MagicMock()
    rows.all.return_value, empty.all.return_value = [old], []
    context.session.scalars.side_effect = [rows, empty]
    monkeypatch.setattr(service, "safety_reconciliation", AsyncMock())
    machine = MachineContext(context.session, context.config, {}, "expiry-test")
    assert await service.check_in(machine, host, CheckIn(sequence=1)) == {"jobs": [], "poll_seconds": 2}
    assert old.state == "expired" and runtime.generation == 2 and runtime.desired == "quarantined"
    created = [
        call.args[0] for call in context.session.add.call_args_list if isinstance(call.args[0], DeploymentJob)
    ]
    assert len(created) == 1 and created[0].operation == "quarantine" and created[0].plan_id is None


def test_healthy_means_both_live_and_ready_not_just_process_running(setup):
    installation, host, package, contract, objects, payload = setup
    runtime = RuntimeDeployment(installation_id=installation.id)
    report = RuntimeReport(
        installation_id=installation.id,
        generation=1,
        image_digest=contract["image_digest"],
        state="running",
        health="healthy",
        live=True,
        ready=False,
    )
    service.apply_report(runtime, report)
    assert runtime.health != "healthy" and runtime.last_ready is None
    service.apply_report(runtime, report.model_copy(update={"ready": True}))
    assert runtime.health == "healthy" and runtime.last_ready is not None


@pytest.mark.parametrize(
    "job_state,container,ready",
    [
        ("succeeded", "a" * 64, True),
        ("failed", "a" * 64, False),
        ("queued", "a" * 64, False),
        ("succeeded", None, False),
    ],
)
async def test_enable_read_model_requires_successful_ack_not_only_reported_health(
    context, setup, job_state, container, ready
):
    from package_helpers import manifest_data

    from app.domains.installations import service as installation_service
    from app.domains.packages.schema import Manifest

    installation, host, package, contract, objects, payload = setup
    data = manifest_data()
    data["artifacts"][0]["path"] = "payload/resources/runtime-v1.json"
    manifest = Manifest.model_validate(data)
    stamp = datetime.now(UTC)
    host.last_seen = stamp
    runtime = RuntimeDeployment(
        installation_id=installation.id,
        host_id=host.id,
        package_id=package.id,
        desired="running",
        observed="running",
        health="healthy",
        generation=1,
        observed_generation=1,
        image_digest=contract["image_digest"],
        observed_image_digest=contract["image_digest"],
        container_id=container,
        last_ready=stamp,
        last_seen=stamp,
    )
    facts = {installation.id: (runtime, host, job_state)}
    result = await installation_service.runtime(context, installation, manifest, deployment_facts=facts)
    assert result["binding_active"] is ready


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"aud": "xarionix-core"},
        {"aud": "xarionix-core-modules", "xarionix_principal": "machine"},
        {"xarionix_principal": "human"},
        {"azp": None},
        {"client_id": "another"},
        {"aud": ["xarionix-core-deployment", "xarionix-core"]},
    ],
)
async def test_deployment_api_rejects_wrong_principal_audience_or_client(provider, overrides):
    app = create_app(provider.settings)

    @app.get("/deployment-auth-test")
    async def protected(claims: Annotated[dict, Depends(verified_deployment_claims)]):
        return {"subject": claims["sub"]}

    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as oidc_client:
        app.state.oidc = OIDCVerifier(provider.settings, oidc_client)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://core.example.test"
        ) as client:
            base = {
                "aud": provider.settings.deployment_audience,
                "xarionix_principal": "deployment",
                "azp": "deployment-client",
            }
            if overrides:
                base |= overrides
                response = await client.get(
                    "/deployment-auth-test", headers={"Authorization": "Bearer " + provider.token(**base)}
                )
                assert response.status_code == 401
            else:
                response = await client.get(
                    "/deployment-auth-test", headers={"Authorization": "Bearer " + provider.token(**base)}
                )
                assert response.status_code == 200
                assert (await client.get("/deployment-auth-test")).status_code == 401
            # Even adding the human audience never turns a deployment machine into a user.
            response = await client.get(
                "/api/v1/me",
                headers={
                    "Authorization": "Bearer "
                    + provider.token(**(base | {"aud": "xarionix-core", "xarionix_principal": "deployment"}))
                },
            )
            assert response.status_code == 401
