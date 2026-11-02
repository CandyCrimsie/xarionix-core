from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.api.v1.schemas import DTO, Name
from app.domains.modules.model import OPERATIONS

Health = Literal["healthy", "degraded", "error"]
Operation = Literal["ping", "get_status"]


class ServiceCreate(DTO):
    module_key: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    name: Name
    description: str | None = Field(default=None, max_length=1000)
    issuer: str = Field(min_length=8, max_length=512)
    subject: str = Field(min_length=1, max_length=255)
    client_id: str = Field(min_length=1, max_length=120)
    operations: list[str] = Field(max_length=5)

    @field_validator("module_key")
    @classmethod
    def reserved(cls, value: str) -> str:
        if value in {"core", "xarionix-core"}:
            raise ValueError("Reserved module key")
        return value

    @field_validator("operations")
    @classmethod
    def capabilities(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value) or not set(value) <= OPERATIONS:
            raise ValueError("Unknown or duplicate machine capability")
        return value


class InstanceCreate(DTO):
    installation_key: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")


class ScopePut(DTO):
    status: Literal["active", "revoked"]
    operations: list[Literal["core.modules.metadata.read"]] = Field(max_length=1)


class ServiceView(ServiceCreate):
    id: UUID
    status: str
    registered_by_user_id: UUID
    created_at: datetime
    updated_at: datetime


class InstanceView(DTO):
    id: UUID
    service_id: UUID
    installation_key: str
    status: str
    connection_state: Literal["connected", "stale", "disabled", "revoked", "error"]
    last_seen: datetime | None
    health: str | None
    protocol_version: int | None
    agent_version: str | None
    created_at: datetime
    updated_at: datetime


class CheckIn(DTO):
    instance_id: UUID
    protocol_version: Literal[1]
    health: Health
    agent_version: str = Field(min_length=1, max_length=32, pattern=r"^[a-zA-Z0-9._+-]+$")

    @field_validator("protocol_version", mode="before")
    @classmethod
    def protocol(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Integer protocol required")
        return value


class CommandDelivery(DTO):
    id: UUID
    operation: Operation
    expires_at: datetime
    attempt: int
    request_id: str


class CheckInView(DTO):
    instance_id: UUID
    connection_state: Literal["connected", "error"]
    check_in_seconds: int
    server_time: datetime
    commands: list[CommandDelivery]


class Pong(DTO):
    kind: Literal["pong"]


class AgentStatus(DTO):
    kind: Literal["status"]
    health: Health
    agent_version: str = Field(min_length=1, max_length=32, pattern=r"^[a-zA-Z0-9._+-]+$")


class CommandError(DTO):
    kind: Literal["error"]
    code: Literal["unsupported_operation", "agent_error"]


SafeResult = Annotated[Pong | AgentStatus | CommandError, Field(discriminator="kind")]


class Acknowledgement(DTO):
    instance_id: UUID
    result: SafeResult


class CommandCreate(DTO):
    expires_in_seconds: int = Field(default=300, ge=10, le=3600, strict=True)


class CommandView(DTO):
    id: UUID
    instance_id: UUID
    operation: Operation
    state: str
    attempts: int
    created_at: datetime
    expires_at: datetime
    completed_at: datetime | None
    result: dict[str, str] | None
    request_id: str


class CompanyMetadata(DTO):
    company_id: UUID
    name: str
