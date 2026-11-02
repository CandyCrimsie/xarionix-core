import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.domains.users.model import Timestamps


class PermissionNamespace(Base):
    __tablename__ = "permission_namespaces"
    __table_args__ = (
        CheckConstraint("state IN ('active','reserved','disabled')", name="ck_namespace_state"),
    )
    name: Mapped[str] = mapped_column(String(40), primary_key=True)
    owner: Mapped[str] = mapped_column(String(80))
    state: Mapped[str] = mapped_column(String(16))


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (
        CheckConstraint("scope='company'", name="ck_permission_scope"),
        CheckConstraint(
            "key ~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_.]*[.][a-z][a-z0-9_]*$' AND split_part(key,'.',1)=namespace",
            name="ck_permission_key",
        ),
        CheckConstraint("NOT protected OR NOT owner_grantable", name="ck_permission_protected"),
    )
    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    namespace: Mapped[str] = mapped_column(
        ForeignKey("permission_namespaces.name", ondelete="RESTRICT"), index=True
    )
    description: Mapped[str] = mapped_column(String(320))
    scope: Mapped[str] = mapped_column(String(16), default="company")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    protected: Mapped[bool] = mapped_column(Boolean, default=False)
    owner_grantable: Mapped[bool] = mapped_column(Boolean, default=False)


class Role(Timestamps, Base):
    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("company_id", "id", name="uq_role_company_id"),
        UniqueConstraint("company_id", "code", name="uq_role_company_code"),
        CheckConstraint("code ~ '^[a-z][a-z0-9_-]{1,62}$'", name="ck_role_code"),
        CheckConstraint(
            "(is_system AND code IN ('owner','admin','member')) OR (NOT is_system AND code NOT IN ('owner','admin','member','platform_admin','core','system'))",
            name="ck_role_reserved",
        ),
        CheckConstraint("version > 0 AND definition_version > 0", name="ck_role_version"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("companies.id", ondelete="RESTRICT"), index=True)
    code: Mapped[str] = mapped_column(String(63))
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str | None] = mapped_column(String(1000))
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    definition_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))


class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["company_id", "role_id"], ["roles.company_id", "roles.id"], ondelete="RESTRICT"
        ),
    )
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    role_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    permission_key: Mapped[str] = mapped_column(
        ForeignKey("permissions.key", ondelete="RESTRICT"), primary_key=True
    )


class MembershipRole(Base):
    __tablename__ = "membership_roles"
    __table_args__ = (
        ForeignKeyConstraint(
            ["company_id", "membership_id"], ["memberships.company_id", "memberships.id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(
            ["company_id", "role_id"], ["roles.company_id", "roles.id"], ondelete="RESTRICT"
        ),
        CheckConstraint("origin IN ('system','custom')", name="ck_assignment_origin"),
    )
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    membership_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    role_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, index=True)
    origin: Mapped[str] = mapped_column(String(16), default="custom")


class RoleTemplate(Base):
    __tablename__ = "role_templates"
    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    permissions: Mapped[list[str]] = mapped_column(JSONB)


class PermissionDelegation(Base):
    __tablename__ = "permission_delegations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["company_id", "membership_id"], ["memberships.company_id", "memberships.id"], ondelete="RESTRICT"
        ),
        CheckConstraint(
            "role_scope='custom_roles' AND member_scope='non_owners'", name="ck_delegation_scope"
        ),
    )
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    membership_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    permission_key: Mapped[str] = mapped_column(
        ForeignKey("permissions.key", ondelete="RESTRICT"), primary_key=True
    )
    role_scope: Mapped[str] = mapped_column(String(24), default="custom_roles", server_default="custom_roles")
    member_scope: Mapped[str] = mapped_column(String(24), default="non_owners", server_default="non_owners")


class InvitationRole(Base):
    __tablename__ = "invitation_roles"
    __table_args__ = (
        ForeignKeyConstraint(
            ["company_id", "invitation_id"], ["invitations.company_id", "invitations.id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(
            ["company_id", "role_id"], ["roles.company_id", "roles.id"], ondelete="RESTRICT"
        ),
    )
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    invitation_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    role_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
