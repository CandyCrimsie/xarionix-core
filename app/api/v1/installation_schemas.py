from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictInt


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class PlanCreate(Input):
    action: Literal["install", "enable", "disable", "update", "uninstall", "rollback"]
    package_id: UUID
    expected_generation: StrictInt = Field(default=0, ge=0)
    idempotency_key: UUID = Field(default_factory=uuid4)


class PlanDigest(Input):
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class BindInstance(Input):
    instance_id: UUID | None
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_generation: StrictInt = Field(ge=1)
    expected_revision: StrictInt = Field(ge=0)
