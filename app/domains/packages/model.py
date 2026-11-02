import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.domains.users.model import Timestamps


class PackagePublisher(Timestamps, Base):
    __tablename__ = "package_publishers"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    publisher_id: Mapped[str] = mapped_column(String(63), unique=True)
    display_name: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    __table_args__ = (CheckConstraint("status IN ('active','revoked')", name="ck_publisher_status"),)


class PublisherSigningKey(Timestamps, Base):
    __tablename__ = "publisher_signing_keys"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    publisher_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("package_publishers.id", ondelete="RESTRICT"), index=True
    )
    key_id: Mapped[str] = mapped_column(String(63))
    public_key: Mapped[str] = mapped_column(String(44))
    fingerprint: Mapped[str] = mapped_column(String(64))
    algorithm: Mapped[str] = mapped_column(String(16), default="Ed25519", server_default="Ed25519")
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        UniqueConstraint("publisher_id", "key_id", name="uq_publisher_key_id"),
        UniqueConstraint("publisher_id", "fingerprint", name="uq_publisher_key_material"),
        CheckConstraint(
            "status IN ('active','revoked') AND algorithm='Ed25519'", name="ck_signing_key_state"
        ),
        CheckConstraint("(status='revoked')=(revoked_at IS NOT NULL)", name="ck_key_revoked_at"),
    )


class PublisherNamespaceGrant(Timestamps, Base):
    __tablename__ = "publisher_namespace_grants"
    namespace: Mapped[str] = mapped_column(String(40), primary_key=True)
    publisher_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("package_publishers.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    __table_args__ = (
        CheckConstraint(
            "status IN ('active','revoked') AND namespace<>'core'", name="ck_publisher_namespace"
        ),
    )


class ModulePackage(Base):
    __tablename__ = "module_packages"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    module_id: Mapped[str] = mapped_column(String(63), index=True)
    version: Mapped[str] = mapped_column(String(120))
    publisher_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("package_publishers.id", ondelete="RESTRICT"))
    signing_key_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("publisher_signing_keys.id", ondelete="RESTRICT")
    )
    package_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    state: Mapped[str] = mapped_column(String(16), default="available", server_default="available")
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB)
    imported_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (
        UniqueConstraint("module_id", "version", "publisher_id", name="uq_package_identity"),
        CheckConstraint(
            "state IN ('available','quarantined') AND size BETWEEN 1 AND 134217728",
            name="ck_package_state_size",
        ),
        CheckConstraint(
            "package_sha256 ~ '^[0-9a-f]{64}$' AND manifest_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_package_digests",
        ),
    )
