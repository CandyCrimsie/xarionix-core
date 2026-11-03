import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.domains.users.model import Timestamps


class ModuleInstallation(Timestamps, Base):
    __tablename__ = "module_installations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('installed_disabled','installed_enabled','removed')", name="ck_installation_status"
        ),
        CheckConstraint("generation > 0", name="ck_installation_generation"),
        CheckConstraint(
            "module_type IN ('standard','autonomous') AND namespace <> 'core'", name="ck_installation_type"
        ),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    module_id: Mapped[str] = mapped_column(String(63), unique=True)
    publisher_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("package_publishers.id", ondelete="RESTRICT"))
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("module_packages.id", ondelete="RESTRICT"))
    previous_package_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("module_packages.id", ondelete="RESTRICT")
    )
    namespace: Mapped[str] = mapped_column(String(40), unique=True)
    module_type: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24))
    generation: Mapped[int] = mapped_column(Integer)
    installed_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))


class ModuleDependencyPin(Base):
    """Bounded transitive closure, not a second dependency resolver."""

    __tablename__ = "module_dependency_pins"
    __table_args__ = (
        CheckConstraint("installation_id <> dependency_id AND generation > 0", name="ck_dependency_pin"),
    )
    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_installations.id", ondelete="RESTRICT"), primary_key=True
    )
    dependency_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_installations.id", ondelete="RESTRICT"), primary_key=True, index=True
    )
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("module_packages.id", ondelete="RESTRICT"))
    generation: Mapped[int] = mapped_column(Integer)


class ModuleInstallPlan(Base):
    __tablename__ = "module_install_plans"
    __table_args__ = (
        CheckConstraint(
            "action IN ('install','update','enable','disable','uninstall','rollback')",
            name="ck_install_plan_action",
        ),
        CheckConstraint(
            "state IN ('pending','approved','cancelled','applied')", name="ck_install_plan_state"
        ),
        CheckConstraint(
            "digest ~ '^[0-9a-f]{64}$' AND expected_generation >= 0", name="ck_install_plan_digest"
        ),
        CheckConstraint(
            "(approved_by IS NULL) = (approved_at IS NULL) AND (approved_by IS NULL) = (approved_until IS NULL)",
            name="ck_install_plan_approval",
        ),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    action: Mapped[str] = mapped_column(String(16))
    module_id: Mapped[str] = mapped_column(String(63), index=True)
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("module_packages.id", ondelete="RESTRICT"))
    expected_generation: Mapped[int] = mapped_column(Integer)
    digest: Mapped[str] = mapped_column(String(64))
    body: Mapped[dict[str, Any]] = mapped_column(JSONB)
    state: Mapped[str] = mapped_column(String(16), default="pending")
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    approved_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("identities.id", ondelete="RESTRICT")
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approval: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class ModuleInstallOperation(Base):
    __tablename__ = "module_install_operations"
    __table_args__ = (
        CheckConstraint(
            "state IN ('prepared','applying','succeeded','failed')", name="ck_install_operation_state"
        ),
        CheckConstraint("attempts BETWEEN 0 AND 32", name="ck_install_operation_attempts"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    plan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_install_plans.id", ondelete="RESTRICT"), unique=True
    )
    module_id: Mapped[str] = mapped_column(String(63), index=True)
    state: Mapped[str] = mapped_column(String(16), default="prepared")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    fence: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    safe_error_code: Mapped[str | None] = mapped_column(String(80))
    failures: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    correlation_id: Mapped[uuid.UUID] = mapped_column(Uuid, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ModuleInstallationHistory(Base):
    __tablename__ = "module_installation_history"
    __table_args__ = (
        UniqueConstraint("installation_id", "generation", name="uq_installation_history_generation"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_installations.id", ondelete="RESTRICT"), index=True
    )
    operation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_install_operations.id", ondelete="RESTRICT"), unique=True
    )
    previous_package_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("module_packages.id", ondelete="RESTRICT")
    )
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("module_packages.id", ondelete="RESTRICT"))
    previous_state: Mapped[str | None] = mapped_column(String(24))
    state: Mapped[str] = mapped_column(String(24))
    generation: Mapped[int] = mapped_column(Integer)
    performed_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ModuleInstanceBinding(Timestamps, Base):
    __tablename__ = "module_instance_bindings"
    __table_args__ = (CheckConstraint("revision > 0", name="ck_instance_binding_revision"),)
    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_installations.id", ondelete="RESTRICT"), primary_key=True
    )
    instance_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("module_instances.id", ondelete="RESTRICT"), unique=True
    )
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("module_packages.id", ondelete="RESTRICT"))
    active: Mapped[bool] = mapped_column(Boolean)
    revision: Mapped[int] = mapped_column(Integer)
    bound_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
