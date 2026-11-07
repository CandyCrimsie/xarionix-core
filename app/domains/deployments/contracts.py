"""Versioned, closed deployment protocol; no caller-supplied Docker flags or shell."""

import hashlib
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domains.deployments.artifacts import RuntimeContract
from app.domains.module_gateway.contracts import APIContract
from app.domains.packages.codec import canonical

Operation = Literal[
    "provision",
    "start",
    "stop",
    "restart",
    "upgrade",
    "rollback",
    "deprovision",
    "inspect",
    "reconcile",
    "quarantine",
    "retire",
    "backup",
    "restore",
]
Profile = Literal["offline-small-v1", "offline-medium-v1", "module-api-private-v1", "module-api-stateful-v1"]
PROFILES: dict[str, dict[str, int]] = {
    "offline-small-v1": {"memory": 268435456, "cpu_quota": 50000, "pids": 64, "tmpfs": 67108864},
    "offline-medium-v1": {"memory": 536870912, "cpu_quota": 100000, "pids": 128, "tmpfs": 67108864},
    "module-api-private-v1": {"memory": 268435456, "cpu_quota": 50000, "pids": 64, "tmpfs": 67108864},
    "module-api-stateful-v1": {
        "memory": 268435456,
        "cpu_quota": 50000,
        "pids": 64,
        "tmpfs": 67108864,
        "storage": 67108864,
    },
}
SAFETY = frozenset({"stop", "quarantine", "retire", "deprovision", "inspect"})


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class HostCreate(Input):
    id: UUID
    name: str = Field(min_length=1, max_length=120)
    issuer: str = Field(max_length=512)
    subject: str = Field(min_length=1, max_length=255)
    client_id: str = Field(min_length=1, max_length=120)
    engine_id: str = Field(pattern=r"^[A-Za-z0-9:-]{8,120}$")
    platform: Literal["linux/amd64", "linux/arm64"]


class PlanCreate(Input):
    idempotency_key: UUID
    installation_id: UUID
    host_id: UUID
    operation: Operation
    expected_installation_generation: int = Field(ge=1, strict=True)
    expected_deployment_generation: int = Field(ge=0, strict=True)
    profile: Profile = "offline-small-v1"
    backup_id: UUID | None = None
    allow_migration: bool = False


class StorageBinding(Input):
    schema_version: Literal[1] = 1
    module_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    epoch_id: UUID
    next_epoch_id: UUID
    allocation_revision: int = Field(ge=0, strict=True)
    expected_schema_version: int = Field(ge=0, le=128, strict=True)
    target_schema_version: int = Field(ge=1, le=128, strict=True)
    compatible_minimum: int = Field(ge=1, le=128, strict=True)
    compatible_maximum: int = Field(ge=1, le=128, strict=True)
    maximum_bytes: Literal[67108864] = 67108864
    sdk_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    package_version: str = Field(max_length=120)
    backup_id: UUID | None = None
    backup_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    allow_migration: bool = False

    @model_validator(mode="after")
    def schema_bounds(self) -> "StorageBinding":
        if not self.compatible_minimum <= self.target_schema_version <= self.compatible_maximum:
            raise ValueError("storage_schema_bounds_invalid")
        return self


class BackupMetadata(Input):
    id: UUID
    epoch_id: UUID
    data_schema_version: int = Field(ge=1, le=128, strict=True)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=1, le=67108864, strict=True)
    package_version: str = Field(max_length=120)


class StorageReport(Input):
    epoch_id: UUID
    data_schema_version: int = Field(ge=0, le=128, strict=True)
    backup: BackupMetadata | None = Field(default=None, exclude_if=lambda value: value is None)


class Approval(Input):
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class RuntimeReport(Input):
    installation_id: UUID
    generation: int = Field(ge=1, strict=True)
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    container_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    state: Literal["not_provisioned", "stopped", "starting", "running", "unhealthy", "failed", "unknown"]
    health: Literal["healthy", "unhealthy", "unknown"]
    live: bool = False
    ready: bool = False
    restart_count: int = Field(default=0, ge=0, le=100000, strict=True)
    storage: StorageReport | None = Field(default=None, exclude_if=lambda value: value is None)
    safe_error_code: (
        Literal[
            "engine_unavailable",
            "isolation_unavailable",
            "artifact_invalid",
            "health_failed",
            "runtime_missing",
            "policy_denied",
            "deployment_failed",
        ]
        | None
    ) = None


class CheckIn(Input):
    sequence: int = Field(ge=1, le=2**63 - 1, strict=True)
    reports: list[RuntimeReport] = Field(default_factory=list, max_length=32)


class Receipt(Input):
    fence: UUID
    report: RuntimeReport
    success: bool


class Delivery(Input):
    id: UUID
    fence: UUID
    host_id: UUID
    installation_id: UUID
    operation: Operation
    generation: int = Field(ge=1)
    lease_until: datetime
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    package_size: int = Field(ge=1, le=134217728)
    runtime: RuntimeContract
    profile: Profile
    engine_id: str
    trust: dict[str, Any]
    api_contract: APIContract | None = None
    storage: StorageBinding | None = Field(default=None, exclude_if=lambda value: value is None)
    installation_generation: int | None = Field(
        default=None, ge=1, strict=True, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def storage_capability(self) -> "Delivery":
        if self.profile == "module-api-stateful-v1":
            if self.storage is None or self.installation_generation is None:
                raise ValueError("stateful_storage_binding_required")
        elif self.storage is not None:
            raise ValueError("unexpected_storage_capability")
        return self


def digest(body: dict[str, Any]) -> str:
    return hashlib.sha256(b"XARIONIX-DEPLOYMENT-PLAN-V1\x00" + canonical(body)).hexdigest()
