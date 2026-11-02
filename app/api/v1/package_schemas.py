from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.api.v1.schemas import DTO
from app.domains.packages.codec import fingerprint
from app.domains.packages.schema import Identifier, Namespace


class PublisherCreate(DTO):
    publisher_id: Identifier
    display_name: str = Field(min_length=1, max_length=160)


class PublisherView(PublisherCreate):
    id: UUID
    status: Literal["active", "revoked"]
    created_at: datetime
    updated_at: datetime


class KeyCreate(DTO):
    key_id: Identifier
    public_key: str = Field(min_length=44, max_length=44)

    @field_validator("public_key")
    @classmethod
    def real_key(cls, value: str) -> str:
        fingerprint(value)
        return value


class KeyView(KeyCreate):
    id: UUID
    fingerprint: str
    status: Literal["active", "revoked"]
    algorithm: Literal["Ed25519"]
    revoked_at: datetime | None


class NamespacePut(DTO):
    namespaces: list[Namespace] = Field(max_length=64)

    @field_validator("namespaces")
    @classmethod
    def unique_non_core(cls, value: list[str]) -> list[str]:
        if "core" in value or len(set(value)) != len(value):
            raise ValueError("Core namespace is protected; grants must be unique")
        return value
