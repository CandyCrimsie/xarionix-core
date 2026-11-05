from typing import Any
from uuid import UUID

from sqlalchemy import ForeignKey, Integer, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ModuleAPIContract(Base):
    __tablename__ = "module_api_contracts"
    package_id: Mapped[UUID] = mapped_column(
        ForeignKey("module_packages.id", ondelete="RESTRICT"), primary_key=True
    )
    sha256: Mapped[str] = mapped_column(String(64))
    document: Mapped[dict[str, Any]] = mapped_column(JSONB)


class GatewayIdentity(Base):
    __tablename__ = "module_gateway_identities"
    host_id: Mapped[UUID] = mapped_column(
        ForeignKey("deployment_hosts.id", ondelete="RESTRICT"), primary_key=True
    )
    issuer: Mapped[str] = mapped_column(String(512))
    subject: Mapped[str] = mapped_column(String(255))
    client_id: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16), default="active")
    revision: Mapped[int] = mapped_column(Integer, default=1)
    approved_by: Mapped[UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
