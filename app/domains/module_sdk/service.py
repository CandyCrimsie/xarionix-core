"""Data ownership in approved plans. No Docker/filesystem/SQL business access in Core."""

from typing import Any
from uuid import UUID, uuid5

from app.core.access import Context, audit, fail
from app.domains.deployments.contracts import SAFETY, PlanCreate, StorageBinding, StorageReport
from app.domains.deployments.model import DeploymentJob, RuntimeDeployment
from app.domains.installations.model import ModuleInstallation
from app.domains.module_sdk.contracts import SDKContract
from app.domains.module_sdk.model import ModuleDataBackup, ModuleSDKContract, ModuleStorageAllocation
from app.domains.packages.model import ModulePackage
from app.domains.packages.schema import Manifest

PROFILE = "module-api-stateful-v1"
MAXIMUM_BYTES = 67108864


async def snapshot(
    ctx: Context,
    payload: PlanCreate,
    installation: ModuleInstallation,
    package: ModulePackage,
    current: RuntimeDeployment | None,
    profile: str,
) -> dict[str, Any]:
    allocation = await ctx.session.get(ModuleStorageAllocation, installation.id)
    if profile != PROFILE:
        metadata = await ctx.session.get(ModuleSDKContract, package.id)
        if (
            metadata is not None
            and metadata.document.get("storage") is not None
            and payload.operation not in SAFETY
        ):
            fail(409, "stateful_storage_profile_required")
        if allocation is not None and payload.operation not in SAFETY:
            fail(409, "storage_capability_cannot_be_silently_removed")
        if payload.operation in {"backup", "restore"} or payload.backup_id or payload.allow_migration:
            fail(422, "stateful_storage_profile_required")
        return {}
    metadata = await ctx.session.get(ModuleSDKContract, package.id)
    if metadata is None:
        fail(409, "signed_module_storage_required")
    sdk = SDKContract.model_validate(metadata.document)
    sdk.bound(Manifest.model_validate(package.manifest), sdk.api_contract)
    declaration = sdk.storage
    if declaration is None or metadata.sha256 != sdk.digest():
        fail(409, "signed_module_storage_required")
    if allocation is not None and (
        allocation.host_id != payload.host_id or allocation.maximum_bytes != MAXIMUM_BYTES
    ):
        fail(409, "storage_host_binding_immutable")
    epoch = allocation.epoch_id if allocation else uuid5(installation.id, "xarionix-data-v1")
    revision = allocation.revision if allocation else 0
    schema = allocation.data_schema_version if allocation else 0
    if payload.operation in {"backup", "restore"} and (
        allocation is None
        or current is None
        or current.observed not in {"stopped", "not_provisioned"}
        or current.desired not in {"stopped", "absent", "provisioned", "quarantined"}
    ):
        fail(409, "storage_stop_writer_required")
    backup = await ctx.session.get(ModuleDataBackup, payload.backup_id) if payload.backup_id else None
    if payload.backup_id and (backup is None or backup.installation_id != installation.id):
        fail(404, "storage_backup_not_found")
    migrate = schema > 0 and schema < declaration.data_schema_version
    if payload.operation not in SAFETY and payload.operation not in {"backup", "restore", "provision"}:
        if (
            schema
            and not declaration.compatible_minimum <= schema <= declaration.compatible_maximum
            and not migrate
        ):
            fail(409, "storage_schema_incompatible")
        if migrate and (
            not payload.allow_migration
            or backup is None
            or backup.epoch_id != epoch
            or backup.data_schema_version != schema
            or backup.allocation_revision != revision
        ):
            fail(409, "storage_migration_requires_fresh_backup_and_approval")
    if payload.allow_migration and (
        not migrate or payload.operation in {*SAFETY, "backup", "restore", "provision"}
    ):
        fail(422, "storage_migration_not_applicable")
    if payload.operation == "restore" and (
        backup is None
        or not declaration.compatible_minimum <= backup.data_schema_version <= declaration.compatible_maximum
    ):
        fail(409, "storage_restore_schema_incompatible")
    if payload.operation == "backup" and schema == 0:
        fail(409, "storage_database_not_initialized")
    binding = StorageBinding(
        module_id=installation.module_id,
        epoch_id=epoch,
        next_epoch_id=uuid5(payload.idempotency_key, "restore-data-epoch")
        if payload.operation == "restore"
        else epoch,
        allocation_revision=revision,
        expected_schema_version=schema,
        target_schema_version=declaration.data_schema_version,
        compatible_minimum=declaration.compatible_minimum,
        compatible_maximum=declaration.compatible_maximum,
        sdk_sha256=metadata.sha256,
        package_version=package.version,
        allow_migration=payload.allow_migration,
        backup_id=uuid5(payload.idempotency_key, "data-backup")
        if payload.operation == "backup"
        else payload.backup_id,
        backup_sha256=backup.sha256 if backup else None,
    )
    return {"storage": binding.model_dump(mode="json")}


async def reserve(ctx: Context, body: dict[str, Any]) -> None:
    if "storage" not in body:
        return
    binding = StorageBinding.model_validate(body["storage"])
    installation = UUID(body["installation_id"])
    allocation = await ctx.session.get(ModuleStorageAllocation, installation, with_for_update=True)
    if allocation is None:
        if binding.allocation_revision != 0 or binding.expected_schema_version != 0:
            fail(409, "storage_allocation_missing")
        ctx.session.add(
            ModuleStorageAllocation(
                installation_id=installation,
                host_id=UUID(body["host_id"]),
                epoch_id=binding.epoch_id,
                maximum_bytes=binding.maximum_bytes,
                revision=0,
                data_schema_version=0,
                retained_epochs=[],
            )
        )
        audit(ctx, "module.storage_reserved", "module_installation", installation)
        await ctx.session.flush()


async def safety_binding(ctx: Any, body: dict[str, Any], installation_id: UUID) -> dict[str, Any]:
    """A security stop is new work, not a replay of an old data revision/restore."""
    if "storage" not in body:
        return body
    allocation = await ctx.session.get(ModuleStorageAllocation, installation_id, with_for_update=True)
    if allocation is None:
        return body
    binding = StorageBinding.model_validate(body["storage"]).model_copy(
        update={
            "epoch_id": allocation.epoch_id,
            "next_epoch_id": allocation.epoch_id,
            "allocation_revision": allocation.revision,
            "expected_schema_version": allocation.data_schema_version,
            "backup_id": None,
            "backup_sha256": None,
            "allow_migration": False,
        }
    )
    return body | {"storage": binding.model_dump(mode="json")}


async def acknowledge(ctx: Any, job: DeploymentJob, report: StorageReport | None, success: bool) -> None:
    raw = job.body.get("storage")
    if raw is None:
        if report is not None:
            fail(409, "unexpected_storage_report")
        return
    binding = StorageBinding.model_validate(raw)
    if report is None:
        if success and job.operation not in {"stop", "quarantine", "retire", "deprovision", "inspect"}:
            fail(409, "storage_report_required")
        return
    allocation = await ctx.session.get(ModuleStorageAllocation, job.installation_id, with_for_update=True)
    if (
        allocation is None
        or allocation.host_id != job.host_id
        or allocation.revision != binding.allocation_revision
    ):
        fail(409, "storage_allocation_revision_conflict")
    expected_epoch = binding.next_epoch_id if success and job.operation == "restore" else binding.epoch_id
    if report.epoch_id != expected_epoch:
        fail(409, "storage_epoch_conflict")
    if success and job.operation == "restore":
        backup = await ctx.session.get(ModuleDataBackup, binding.backup_id) if binding.backup_id else None
        if (
            backup is None
            or backup.installation_id != job.installation_id
            or backup.sha256 != binding.backup_sha256
            or report.data_schema_version != backup.data_schema_version
            or not binding.compatible_minimum <= report.data_schema_version <= binding.compatible_maximum
        ):
            fail(409, "storage_restore_binding_conflict")
    if (
        success
        and job.operation in {"start", "restart", "upgrade", "rollback", "reconcile"}
        and not binding.compatible_minimum <= report.data_schema_version <= binding.compatible_maximum
    ):
        fail(409, "storage_schema_incompatible")
    if job.operation != "restore" and report.data_schema_version < binding.expected_schema_version:
        fail(409, "storage_schema_regression")
    allocation.revision += 1
    allocation.data_schema_version = report.data_schema_version
    if allocation.epoch_id != expected_epoch:
        allocation.retained_epochs = [*allocation.retained_epochs, str(allocation.epoch_id)]
        allocation.epoch_id = expected_epoch
    if success and job.operation == "backup":
        backup = report.backup
        if (
            backup is None
            or backup.id != binding.backup_id
            or backup.epoch_id != binding.epoch_id
            or backup.data_schema_version != report.data_schema_version
            or backup.package_version != binding.package_version
        ):
            fail(409, "storage_backup_binding_conflict")
        ctx.session.add(
            ModuleDataBackup(
                id=backup.id,
                installation_id=job.installation_id,
                epoch_id=backup.epoch_id,
                data_schema_version=backup.data_schema_version,
                sha256=backup.sha256,
                size=backup.size,
                package_version=backup.package_version,
                allocation_revision=allocation.revision,
                job_id=job.id,
            )
        )
    elif report.backup is not None:
        fail(409, "unexpected_storage_backup")
