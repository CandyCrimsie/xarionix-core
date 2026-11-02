import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.domains.users.model import Timestamps


class Invitation(Timestamps, Base):
    __tablename__ = "invitations"
    __table_args__ = (
        UniqueConstraint("company_id", "id", name="uq_invitation_company_id"),
        CheckConstraint("role IN ('admin','member')", name="ck_invitation_role"),
        CheckConstraint("status IN ('pending','accepted','revoked')", name="ck_invitation_status"),
        CheckConstraint("expires_at > created_at", name="ck_invitation_expiry"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("companies.id", ondelete="RESTRICT"), index=True)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    role: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    recipient_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    recipient_email: Mapped[str | None] = mapped_column(String(254))
    permission_snapshot: Mapped[list[str] | None] = mapped_column(JSONB)
