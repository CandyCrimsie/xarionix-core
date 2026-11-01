import uuid

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.domains.users.model import Timestamps


class PlatformSettings(Timestamps, Base):
    __tablename__ = "platform_settings"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_settings_singleton"),
        CheckConstraint("company_creation_policy IN ('closed','approval','open')", name="ck_creation_policy"),
        CheckConstraint("max_owned_companies_per_user BETWEEN 1 AND 100", name="ck_company_limit"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    company_creation_policy: Mapped[str] = mapped_column(String(16), default="approval")
    max_owned_companies_per_user: Mapped[int] = mapped_column(Integer, default=3)
    invitations_enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class PlatformAdmin(Timestamps, Base):
    __tablename__ = "platform_admins"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    granted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
