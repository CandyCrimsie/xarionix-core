import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.domains.users.model import Timestamps

OPERATIONS = frozenset(
    "core.modules." + value
    for value in ("connect", "heartbeat", "commands.read", "commands.ack", "metadata.read")
)


class ModuleService(Timestamps, Base):
    __tablename__ = "module_services"
    __table_args__ = (
        UniqueConstraint("issuer", "subject", name="uq_module_service_subject"),
        UniqueConstraint("issuer", "client_id", name="uq_module_service_client"),
        CheckConstraint("status IN ('active','disabled','revoked')", name="ck_module_service_status"),
        CheckConstraint(
            "module_key ~ '^[a-z][a-z0-9-]{1,62}$' AND module_key NOT IN ('core','xarionix-core')",
            name="ck_module_key",
        ),
        CheckConstraint(
            'jsonb_typeof(operations)=\'array\' AND \'["core.modules.connect","core.modules.heartbeat","core.modules.commands.read","core.modules.commands.ack","core.modules.metadata.read"]\'::jsonb @> operations',
            name="ck_module_operations",
        ),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    module_key: Mapped[str] = mapped_column(String(63), index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str | None] = mapped_column(String(1000))
    issuer: Mapped[str] = mapped_column(String(512))
    subject: Mapped[str] = mapped_column(String(255))
    client_id: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    operations: Mapped[list[str]] = mapped_column(JSONB)
    registered_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))


class ModuleInstance(Timestamps, Base):
    __tablename__ = "module_instances"
    __table_args__ = (
        UniqueConstraint("service_id", name="uq_module_instance_service"),
        UniqueConstraint("service_id", "installation_key", name="uq_module_installation"),
        CheckConstraint("status IN ('active','disabled','revoked')", name="ck_module_instance_status"),
        CheckConstraint(
            "health IS NULL OR health IN ('healthy','degraded','error')", name="ck_module_health"
        ),
        CheckConstraint("protocol_version IS NULL OR protocol_version=1", name="ck_module_protocol"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    service_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("module_services.id", ondelete="RESTRICT"))
    installation_key: Mapped[str] = mapped_column(String(63))
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_check_in_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    health: Mapped[str | None] = mapped_column(String(16))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    protocol_version: Mapped[int | None]
    installation_managed: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")


class ModuleCompanyScope(Timestamps, Base):
    __tablename__ = "module_company_scopes"
    __table_args__ = (
        CheckConstraint("status IN ('active','revoked')", name="ck_module_scope_status"),
        CheckConstraint(
            "jsonb_typeof(operations)='array' AND '[\"core.modules.metadata.read\"]'::jsonb @> operations",
            name="ck_module_scope_operations",
        ),
        Index("ix_module_scopes_company", "company_id"),
    )
    instance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_instances.id", ondelete="RESTRICT"), primary_key=True
    )
    company_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("companies.id", ondelete="RESTRICT"), primary_key=True
    )
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    operations: Mapped[list[str]] = mapped_column(JSONB)


class ModuleCommand(Base):
    __tablename__ = "module_commands"
    __table_args__ = (
        Index("ix_module_commands_poll", "instance_id", "state", "lease_until", "created_at"),
        CheckConstraint("operation IN ('ping','get_status')", name="ck_module_command_operation"),
        CheckConstraint(
            "state IN ('pending','delivered','completed','expired')", name="ck_module_command_state"
        ),
        CheckConstraint("attempts BETWEEN 0 AND 5", name="ck_module_command_attempts"),
        CheckConstraint("expires_at>created_at", name="ck_module_command_expiry"),
        CheckConstraint(
            "(state='completed')=(completed_at IS NOT NULL AND result IS NOT NULL)",
            name="ck_module_command_completion",
        ),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    instance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_instances.id", ondelete="RESTRICT"), index=True
    )
    operation: Mapped[str] = mapped_column(String(16))
    state: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    request_id: Mapped[str] = mapped_column(String(64))
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
