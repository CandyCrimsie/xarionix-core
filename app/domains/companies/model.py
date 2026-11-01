import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.domains.users.model import Timestamps


class Company(Timestamps, Base):
    __tablename__ = "companies"
    __table_args__ = (
        CheckConstraint("status IN ('active','suspended','archived')", name="ck_company_status"),
        CheckConstraint("slug ~ '^[a-z][a-z0-9-]{1,61}[a-z0-9]$'", name="ck_company_slug"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(160))
    slug: Mapped[str] = mapped_column(String(63), unique=True)
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))


class CompanyRequest(Timestamps, Base):
    __tablename__ = "company_requests"
    __table_args__ = (
        CheckConstraint("status IN ('pending','approved','rejected','cancelled')", name="ck_request_status"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    name: Mapped[str] = mapped_column(String(160))
    requested_slug: Mapped[str] = mapped_column(String(63))
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending", index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    review_comment: Mapped[str | None] = mapped_column(String(1000))
    company_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("companies.id", ondelete="RESTRICT"))
