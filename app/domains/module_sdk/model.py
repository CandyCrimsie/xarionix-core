from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ModuleSDKContract(Base):
    __tablename__ = "module_sdk_contracts"
    package_id: Mapped[UUID] = mapped_column(
        ForeignKey("module_packages.id", ondelete="RESTRICT"), primary_key=True
    )
    sha256: Mapped[str] = mapped_column(String(64))
    document: Mapped[dict[str, Any]] = mapped_column(JSONB)


class ModuleStorageAllocation(Base):
    __tablename__ = "module_storage_allocations"
    installation_id: Mapped[UUID] = mapped_column(
        ForeignKey("module_installations.id", ondelete="RESTRICT"), primary_key=True
    )
    host_id: Mapped[UUID] = mapped_column(ForeignKey("deployment_hosts.id", ondelete="RESTRICT"))
    epoch_id: Mapped[UUID] = mapped_column(Uuid)
    maximum_bytes: Mapped[int] = mapped_column(BigInteger)
    revision: Mapped[int] = mapped_column(Integer, default=0)
    data_schema_version: Mapped[int] = mapped_column(Integer, default=0)
    retained_epochs: Mapped[list[str]] = mapped_column(JSONB, default=list)


class ModuleDataBackup(Base):
    __tablename__ = "module_data_backups"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    installation_id: Mapped[UUID] = mapped_column(
        ForeignKey("module_storage_allocations.installation_id", ondelete="RESTRICT"), index=True
    )
    epoch_id: Mapped[UUID] = mapped_column(Uuid)
    data_schema_version: Mapped[int] = mapped_column(Integer)
    allocation_revision: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    package_version: Mapped[str] = mapped_column(String(120))
    job_id: Mapped[UUID] = mapped_column(ForeignKey("deployment_jobs.id", ondelete="RESTRICT"), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
