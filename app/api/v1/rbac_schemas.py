import re
from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import Field, field_validator

from app.api.v1.schemas import DTO, Name, Patch

PermissionKeys = Annotated[list[str], Field(max_length=100)]


class PermissionSet(DTO):
    permissions: PermissionKeys

    @field_validator("permissions")
    @classmethod
    def keys(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value) or any(
            len(key) > 120 or not re.fullmatch(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_.]*\.[a-z][a-z0-9_]*", key)
            for key in value
        ):
            raise ValueError("Invalid or duplicate permission key")
        return value


class RoleCreate(PermissionSet):
    permissions: PermissionKeys = Field(default_factory=list)
    code: str = Field(min_length=2, max_length=63)
    name: Name
    description: str | None = Field(default=None, max_length=1000)
    template_key: str | None = Field(default=None, min_length=3, max_length=120)
    template_version: int = Field(default=1, ge=1, strict=True)

    @field_validator("code")
    @classmethod
    def code_value(cls, value: str) -> str:
        if (
            not re.fullmatch(r"[a-z][a-z0-9_-]{1,62}", value)
            or value in {"owner", "admin", "member", "platform_admin", "core", "system"}
            or value.startswith(("core_", "system_"))
        ):
            raise ValueError("Invalid or reserved role code")
        return value


class RolePatch(Patch):
    nullable = {"description"}
    expected_version: int = Field(ge=1, strict=True)
    name: Name | None = None
    description: str | None = Field(default=None, max_length=1000)
    active: bool | None = Field(default=None, strict=True)


class RolePermissionsPatch(PermissionSet):
    expected_version: int = Field(ge=1, strict=True)


class RoleAssignment(DTO):
    role_id: UUID


class RoleView(DTO):
    id: UUID
    company_id: UUID
    code: str
    name: str
    description: str | None
    is_system: bool
    active: bool
    version: int
    definition_version: int
    created_by_user_id: UUID | None
    created_at: datetime
    updated_at: datetime


class PermissionView(DTO):
    key: str
    namespace: str
    description: str
    scope: str
    protected: bool
    owner_grantable: bool


class TemplateView(DTO):
    key: str
    version: int
    name: str
    permissions: list[str]
