import re
from datetime import datetime
from typing import Annotated, Any, ClassVar, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StringConstraints,
    field_validator,
    model_validator,
)

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=160)]
Role = Literal["owner", "admin", "member"]
CompanyStatus = Literal["active", "suspended", "archived"]
MemberStatus = Literal["active", "suspended", "removed"]


class DTO(BaseModel):
    model_config = ConfigDict(
        extra="forbid", from_attributes=True, str_strip_whitespace=True, hide_input_in_errors=True
    )


class Patch(DTO):
    nullable: ClassVar[set[str]] = set()

    @model_validator(mode="before")
    @classmethod
    def explicit_nulls(cls, value: Any) -> Any:
        if isinstance(value, dict):
            if not value:
                raise ValueError("At least one field is required")
            if any(item is None and key not in cls.nullable for key, item in value.items()):
                raise ValueError("Explicit null is not allowed for this field")
        return value


class ProfilePatch(Patch):
    nullable = {"display_name"}
    display_name: Name | None = None


class UserStatusPatch(Patch):
    status: Literal["active", "suspended"]


class UserView(DTO):
    id: UUID
    display_name: str | None
    status: Literal["active", "suspended"]
    created_at: datetime
    updated_at: datetime


class Profile(DTO):
    id: UUID  # backward-compatible Identity ID
    issuer: str
    subject: str
    user_id: UUID
    principal_type: Literal["unclassified", "human", "service"]
    display_name: str | None
    status: Literal["active", "suspended"]
    created_at: datetime
    updated_at: datetime


def normalize_slug(value: str) -> str:
    slug = value.strip().lower()
    if (
        not re.fullmatch(r"[a-z][a-z0-9-]{1,61}[a-z0-9]", slug)
        or "--" in slug
        or slug
        in {
            "admin",
            "api",
            "www",
            "core",
            "system",
            "platform",
            "auth",
            "keycloak",
            "health",
            "support",
            "xarionix",
            "root",
            "billing",
        }
    ):
        raise ValueError("Invalid or reserved company slug")
    return slug


class CompanyCreate(DTO):
    name: Name
    slug: str = Field(min_length=3, max_length=63)
    _slug = field_validator("slug")(normalize_slug)


class CompanyPatch(Patch):
    name: Name | None = None
    slug: str | None = Field(default=None, min_length=3, max_length=63)
    status: CompanyStatus | None = None

    @field_validator("slug")
    @classmethod
    def slug_value(cls, value: str | None) -> str | None:
        return normalize_slug(value) if value else value


class CompanyView(DTO):
    id: UUID
    name: str
    slug: str
    status: CompanyStatus
    created_by_user_id: UUID
    created_at: datetime
    updated_at: datetime


class SettingsPatch(Patch):
    company_creation_policy: Literal["closed", "approval", "open"] | None = None
    max_owned_companies_per_user: int | None = Field(default=None, ge=1, le=100, strict=True)
    invitations_enabled: bool | None = Field(default=None, strict=True)


class SettingsView(DTO):
    company_creation_policy: Literal["closed", "approval", "open"]
    max_owned_companies_per_user: int
    invitations_enabled: bool


class RequestView(DTO):
    id: UUID
    requested_by_user_id: UUID
    name: str
    requested_slug: str
    status: Literal["pending", "approved", "rejected", "cancelled"]
    reviewed_at: datetime | None
    reviewed_by_user_id: UUID | None
    review_comment: str | None
    company_id: UUID | None
    created_at: datetime


class Review(DTO):
    comment: str | None = Field(default=None, max_length=1000)


class MemberPatch(Patch):
    role: Role | None = None
    status: MemberStatus | None = None


class MemberView(DTO):
    id: UUID
    company_id: UUID
    user_id: UUID
    role: Role
    status: MemberStatus
    joined_at: datetime
    created_at: datetime
    updated_at: datetime


class OwnershipTransfer(DTO):
    target_membership_id: UUID


class EmployeeCreate(DTO):
    display_name: Name
    position: Name | None = None
    department: Name | None = None
    user_id: UUID | None = None
    status: Literal["active", "inactive"] = "active"


class EmployeePatch(Patch):
    nullable = {"position", "department", "user_id"}
    display_name: Name | None = None
    position: Name | None = None
    department: Name | None = None
    user_id: UUID | None = None
    status: Literal["active", "inactive"] | None = None


class EmployeeView(EmployeeCreate):
    id: UUID
    company_id: UUID
    created_at: datetime
    updated_at: datetime


class InvitationCreate(DTO):
    role: Literal["admin", "member"] = "member"
    expires_in_hours: int = Field(default=72, ge=1, le=168, strict=True)
    recipient_user_id: UUID | None = None
    recipient_email: str | None = Field(default=None, max_length=254)
    role_ids: list[UUID] = Field(default_factory=list, max_length=20)

    @field_validator("role_ids")
    @classmethod
    def unique_roles(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("Duplicate roles")
        return value

    @field_validator("recipient_email")
    @classmethod
    def email(cls, value: str | None) -> str | None:
        if value is not None:
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
                raise ValueError("Invalid recipient email")
            return value.casefold()
        return None


class InvitationView(DTO):
    id: UUID
    company_id: UUID
    created_by_user_id: UUID
    role: Literal["admin", "member"]
    status: Literal["pending", "accepted", "revoked"]
    expires_at: datetime
    used_at: datetime | None
    created_at: datetime
    recipient_user_id: UUID | None
    recipient_email: str | None


class InvitationIssued(DTO):
    invitation: InvitationView
    secret: str = Field(repr=False)  # only creation response, never audit/list/get


class InvitationAccept(DTO):
    company_id: UUID
    secret: SecretStr = Field(min_length=40, max_length=128, repr=False)


class AdminAssignment(DTO):
    user_id: UUID


class PrincipalPatch(DTO):
    principal_type: Literal["human", "service", "unclassified"]


class AdminView(DTO):
    user_id: UUID
    active: bool
    granted_by_user_id: UUID | None
    created_at: datetime


class AuditView(DTO):
    id: UUID
    actor_user_id: UUID | None
    actor_identity_id: UUID | None
    action: str
    resource_type: str
    resource_id: UUID | None
    company_id: UUID | None
    request_id: str | None
    details: dict[str, Any]
    created_at: datetime


class Page[T](DTO):
    items: list[T]
    total: int
    limit: int
    offset: int
