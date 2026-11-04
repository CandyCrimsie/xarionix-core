import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
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


class DeploymentHost(Base):
    __tablename__ = "deployment_hosts"
    __table_args__ = (
        UniqueConstraint("issuer", "subject", "client_id", name="uq_deployment_identity"),
        CheckConstraint("status IN ('active','disabled','revoked')", name="ck_deployment_host_status"),
        CheckConstraint("revision > 0 AND sequence >= 0", name="ck_deployment_host_revision"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    issuer: Mapped[str] = mapped_column(String(512))
    subject: Mapped[str] = mapped_column(String(255))
    client_id: Mapped[str] = mapped_column(String(120))
    engine_id: Mapped[str] = mapped_column(String(120), unique=True)
    platform: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(16), default="active")
    revision: Mapped[int] = mapped_column(Integer, default=1)
    sequence: Mapped[int] = mapped_column(BigInteger, default=0)
    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DeploymentPlan(Base):
    __tablename__ = "deployment_plans"
    __table_args__ = (
        CheckConstraint("state IN ('pending','approved','cancelled','applied')", name="ck_deploy_plan_state"),
        CheckConstraint("digest ~ '^[0-9a-f]{64}$'", name="ck_deploy_plan_digest"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_installations.id", ondelete="RESTRICT"), index=True
    )
    host_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("deployment_hosts.id", ondelete="RESTRICT"))
    body: Mapped[dict[str, Any]] = mapped_column(JSONB)
    digest: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16), default="pending")
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    approved_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("identities.id", ondelete="RESTRICT")
    )
    approved_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approval: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RuntimeDeployment(Base):
    __tablename__ = "runtime_deployments"
    __table_args__ = (
        CheckConstraint("generation > 0 AND observed_generation >= 0", name="ck_runtime_generation"),
        CheckConstraint(
            "desired IN ('provisioned','running','stopped','absent','quarantined','retired')",
            name="ck_runtime_desired",
        ),
    )
    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_installations.id", ondelete="RESTRICT"), primary_key=True
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("deployment_hosts.id", ondelete="RESTRICT"), index=True
    )
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("module_packages.id", ondelete="RESTRICT"))
    installation_generation: Mapped[int] = mapped_column(Integer)
    generation: Mapped[int] = mapped_column(Integer)
    desired: Mapped[str] = mapped_column(String(24))
    observed_generation: Mapped[int] = mapped_column(Integer, default=0)
    observed: Mapped[str] = mapped_column(String(24), default="unknown")
    health: Mapped[str] = mapped_column(String(16), default="unknown")
    container_id: Mapped[str | None] = mapped_column(String(64))
    image_digest: Mapped[str] = mapped_column(String(71))
    observed_image_digest: Mapped[str | None] = mapped_column(String(71))
    profile: Mapped[str] = mapped_column(String(40))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_live: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_ready: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    restart_count: Mapped[int] = mapped_column(Integer, default=0)
    safe_error_code: Mapped[str | None] = mapped_column(String(80))


class DeploymentJob(Base):
    __tablename__ = "deployment_jobs"
    __table_args__ = (
        UniqueConstraint("installation_id", "generation", name="uq_deploy_job_generation"),
        CheckConstraint(
            "state IN ('queued','leased','succeeded','failed','expired','cancelled')",
            name="ck_deploy_job_state",
        ),
        CheckConstraint("attempts BETWEEN 0 AND 8", name="ck_deploy_job_attempts"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    plan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("deployment_plans.id", ondelete="RESTRICT"), unique=True
    )
    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_installations.id", ondelete="RESTRICT"), index=True
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("deployment_hosts.id", ondelete="RESTRICT"), index=True
    )
    generation: Mapped[int] = mapped_column(Integer)
    operation: Mapped[str] = mapped_column(String(24))
    body: Mapped[dict[str, Any]] = mapped_column(JSONB)
    state: Mapped[str] = mapped_column(String(16), default="queued")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    fence: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ModuleRetirement(Base):
    __tablename__ = "module_retirements"
    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_installations.id", ondelete="RESTRICT"), primary_key=True
    )
    state: Mapped[str] = mapped_column(String(16))
    revision: Mapped[int] = mapped_column(Integer)
    performed_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
