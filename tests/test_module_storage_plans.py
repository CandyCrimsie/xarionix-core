import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from package_helpers import manifest_data

from app.domains.deployments.contracts import PlanCreate, StorageReport
from app.domains.module_sdk import service
from app.domains.module_sdk.contracts import SDKContract
from app.domains.module_sdk.model import ModuleDataBackup, ModuleSDKContract, ModuleStorageAllocation


@pytest.fixture
def scenario(monkeypatch):
    root = Path(__file__).resolve().parents[1] / "examples/modules/hello-business-stateful"
    sdk = SDKContract.model_validate(json.loads((root / "module-sdk-v1.json").read_text()))
    installation = SimpleNamespace(id=uuid4(), module_id="hello-business")
    package = SimpleNamespace(
        id=uuid4(), version="1.1.0", manifest=json.loads((root / "manifest.json").read_text())
    )
    package.manifest["artifacts"] = manifest_data()["artifacts"]
    host = uuid4()
    allocation = ModuleStorageAllocation(
        installation_id=installation.id,
        host_id=host,
        epoch_id=uuid4(),
        maximum_bytes=67108864,
        revision=3,
        data_schema_version=1,
        retained_epochs=[],
    )
    metadata = ModuleSDKContract(
        package_id=package.id, sha256=sdk.digest(), document=sdk.model_dump(mode="json")
    )
    backups = {}
    session = MagicMock()

    async def get(model, identifier, **kwargs):
        return (
            {ModuleStorageAllocation: allocation, ModuleSDKContract: metadata}.get(model)
            if model != ModuleDataBackup
            else backups.get(identifier)
        )

    session.get, session.flush = AsyncMock(side_effect=get), AsyncMock()
    ctx = SimpleNamespace(session=session)
    monkeypatch.setattr(service, "audit", MagicMock())
    payload = PlanCreate(
        idempotency_key=uuid4(),
        installation_id=installation.id,
        host_id=host,
        operation="start",
        expected_installation_generation=1,
        expected_deployment_generation=2,
        profile=service.PROFILE,
    )
    current = SimpleNamespace(observed="stopped", desired="stopped")
    return SimpleNamespace(
        ctx=ctx,
        payload=payload,
        installation=installation,
        package=package,
        allocation=allocation,
        metadata=metadata,
        backups=backups,
        current=current,
    )


async def snapshot(s, **changes):
    return await service.snapshot(
        s.ctx, s.payload.model_copy(update=changes), s.installation, s.package, s.current, service.PROFILE
    )


async def test_storage_plan_is_bound_to_exact_installation_host_schema_and_metadata(scenario):
    s = scenario
    body = (await snapshot(s))["storage"]
    assert body["epoch_id"] == str(s.allocation.epoch_id)
    assert body["allocation_revision"] == 3 and body["maximum_bytes"] == 67108864
    assert body["sdk_sha256"] == s.metadata.sha256
    assert body["expected_schema_version"] == 1
    with pytest.raises(HTTPException, match="storage_host_binding_immutable"):
        await snapshot(s, host_id=uuid4())


@pytest.mark.parametrize("defect", ["missing", "hash", "no_storage"])
async def test_old_or_tampered_package_never_acquires_persistence(scenario, defect):
    s = scenario
    if defect == "hash":
        s.metadata.sha256 = "0" * 64
    if defect == "no_storage":
        s.metadata.document["storage"] = None
    if defect == "missing":
        original = s.ctx.session.get.side_effect
        s.ctx.session.get.side_effect = lambda model, identifier, **kw: None

        async def missing(model, identifier, **kw):
            return None if model == ModuleSDKContract else await original(model, identifier, **kw)

        s.ctx.session.get.side_effect = missing
    with pytest.raises(HTTPException):
        await snapshot(s)


@pytest.mark.parametrize("operation", ["backup", "restore"])
async def test_backup_restore_require_stopped_writer_and_own_backup(scenario, operation):
    s = scenario
    s.current.observed = "running"
    with pytest.raises(HTTPException, match="stop_writer"):
        await snapshot(s, operation=operation)
    s.current.observed = "stopped"
    wrong = uuid4()
    s.backups[wrong] = SimpleNamespace(installation_id=uuid4())
    with pytest.raises(HTTPException, match="backup_not_found"):
        await snapshot(s, operation=operation, backup_id=wrong)


@pytest.mark.parametrize("defect", ["approval", "missing", "revision", "epoch", "schema"])
async def test_migration_requires_exact_fresh_backup_and_explicit_approval(scenario, defect):
    s = scenario
    # The package target stays 1; current database 0 is initialization, never an approved migration.
    doc = s.metadata.document
    doc["storage"]["data_schema_version"] = 2
    doc["storage"]["compatible_minimum"] = doc["storage"]["compatible_maximum"] = 2
    doc["storage"]["migrations"].append({"version": 2, "sha256": "a" * 64})
    s.metadata.sha256 = SDKContract.model_validate(doc).digest()
    identifier = uuid4()
    backup = SimpleNamespace(
        installation_id=s.installation.id,
        epoch_id=s.allocation.epoch_id,
        data_schema_version=1,
        allocation_revision=3,
        sha256="a" * 64,
    )
    s.backups[identifier] = backup
    if defect == "revision":
        backup.allocation_revision -= 1
    if defect == "epoch":
        backup.epoch_id = uuid4()
    if defect == "schema":
        backup.data_schema_version = 2
    with pytest.raises(HTTPException, match="fresh_backup_and_approval"):
        await snapshot(
            s,
            operation="upgrade",
            allow_migration=defect != "approval",
            backup_id=None if defect == "missing" else identifier,
        )


async def test_backup_and_restore_use_distinct_owned_epochs_and_never_delete_old_data(scenario):
    s = scenario
    backup_body = (await snapshot(s, operation="backup"))["storage"]
    identifier = uuid4()
    s.backups[identifier] = SimpleNamespace(
        installation_id=s.installation.id,
        epoch_id=s.allocation.epoch_id,
        data_schema_version=1,
        allocation_revision=3,
        sha256="a" * 64,
    )
    restored = (await snapshot(s, operation="restore", backup_id=identifier))["storage"]
    assert restored["epoch_id"] != restored["next_epoch_id"]
    assert restored["backup_sha256"] == "a" * 64
    job = SimpleNamespace(
        body={"storage": restored},
        installation_id=s.installation.id,
        host_id=s.allocation.host_id,
        operation="restore",
        id=uuid4(),
    )
    await service.acknowledge(
        s.ctx, job, StorageReport(epoch_id=restored["next_epoch_id"], data_schema_version=1), True
    )
    assert s.allocation.revision == 4 and len(s.allocation.retained_epochs) == 1
    assert str(s.allocation.epoch_id) == restored["next_epoch_id"]
    assert backup_body["backup_id"] is not None
    s.ctx.session.delete.assert_not_called()


@pytest.mark.parametrize("defect", ["revision", "epoch", "regression", "missing"])
async def test_storage_acknowledgement_rejects_concurrent_or_invalid_report(scenario, defect):
    s = scenario
    body = await snapshot(s)
    job = SimpleNamespace(
        body=body,
        installation_id=s.installation.id,
        host_id=s.allocation.host_id,
        operation="start",
        id=uuid4(),
    )
    if defect == "revision":
        s.allocation.revision += 1
    report = StorageReport(
        epoch_id=uuid4() if defect == "epoch" else s.allocation.epoch_id,
        data_schema_version=0 if defect == "regression" else 1,
    )
    with pytest.raises(HTTPException):
        await service.acknowledge(s.ctx, job, None if defect == "missing" else report, True)


async def test_security_stop_uses_current_revision_and_epoch_without_replaying_a_restore(scenario):
    s = scenario
    source = await snapshot(s)
    source["storage"]["next_epoch_id"] = str(uuid4())
    source["storage"]["backup_id"] = str(uuid4())
    s.allocation.revision += 2
    s.allocation.epoch_id = uuid4()
    body = await service.safety_binding(s.ctx, source, s.installation.id)
    assert body["storage"]["allocation_revision"] == 5
    assert body["storage"]["epoch_id"] == body["storage"]["next_epoch_id"] == str(s.allocation.epoch_id)
    assert body["storage"]["backup_id"] is None and not body["storage"]["allow_migration"]
    assert source["storage"]["allocation_revision"] == 3


@pytest.mark.parametrize("defect", ["schema", "hash", "installation", "missing"])
async def test_successful_restore_receipt_cannot_relabel_an_empty_or_wrong_database(scenario, defect):
    s = scenario
    identifier = uuid4()
    backup = SimpleNamespace(
        installation_id=s.installation.id,
        epoch_id=s.allocation.epoch_id,
        data_schema_version=1,
        allocation_revision=3,
        sha256="a" * 64,
    )
    s.backups[identifier] = backup
    body = await snapshot(s, operation="restore", backup_id=identifier)
    job = SimpleNamespace(
        body=body,
        installation_id=s.installation.id,
        host_id=s.allocation.host_id,
        operation="restore",
        id=uuid4(),
    )
    if defect == "hash":
        backup.sha256 = "b" * 64
    if defect == "installation":
        backup.installation_id = uuid4()
    if defect == "missing":
        s.backups.clear()
    report = StorageReport(
        epoch_id=body["storage"]["next_epoch_id"], data_schema_version=0 if defect == "schema" else 1
    )
    epoch = s.allocation.epoch_id
    with pytest.raises(HTTPException, match="storage_restore_binding_conflict"):
        await service.acknowledge(s.ctx, job, report, True)
    assert s.allocation.revision == 3 and s.allocation.epoch_id == epoch
