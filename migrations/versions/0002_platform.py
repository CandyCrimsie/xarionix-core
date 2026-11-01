"""Users, company lifecycle, explicit principals and transactional administration."""

from typing import Any
from uuid import UUID

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_platform"
down_revision = "0001_identity"
branch_labels = None
depends_on = None


def identifier() -> sa.Column[UUID]:
    return sa.Column("id", sa.Uuid(), primary_key=True)


def timestamps() -> list[sa.Column[Any]]:
    return [
        sa.Column(name, sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now())
        for name in ("created_at", "updated_at")
    ]


def ref(name: str, target: str, *, nullable: bool = False) -> sa.Column[UUID]:
    return sa.Column(name, sa.Uuid(), sa.ForeignKey(target, ondelete="RESTRICT"), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "users",
        identifier(),
        sa.Column("display_name", sa.String(160)),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        *timestamps(),
        sa.CheckConstraint("status IN ('active','suspended')", name="ck_user_status"),
    )
    op.add_column("identities", sa.Column("user_id", sa.Uuid(), nullable=True))
    op.add_column(
        "identities",
        sa.Column("principal_type", sa.String(16), nullable=False, server_default="unclassified"),
    )
    # Preserve every existing Identity UUID; no matching or linking by email.
    op.execute("INSERT INTO users (id) SELECT id FROM identities")
    op.execute("UPDATE identities SET user_id = id")
    op.alter_column("identities", "user_id", nullable=False)
    op.create_foreign_key("fk_identity_user", "identities", "users", ["user_id"], ["id"], ondelete="RESTRICT")
    op.create_check_constraint(
        "ck_principal_type", "identities", "principal_type IN ('unclassified','human','service')"
    )
    op.create_index("ix_identities_user_id", "identities", ["user_id"])
    op.create_table(
        "companies",
        identifier(),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("slug", sa.String(63), nullable=False, unique=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        ref("created_by_user_id", "users.id"),
        *timestamps(),
        sa.CheckConstraint("status IN ('active','suspended','archived')", name="ck_company_status"),
        sa.CheckConstraint("slug ~ '^[a-z][a-z0-9-]{1,61}[a-z0-9]$'", name="ck_company_slug"),
    )
    op.create_table(
        "memberships",
        identifier(),
        ref("company_id", "companies.id"),
        ref("user_id", "users.id"),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        *timestamps(),
        sa.UniqueConstraint("company_id", "user_id", name="uq_membership_company_user"),
        sa.CheckConstraint("role IN ('owner','admin','member')", name="ck_membership_role"),
        sa.CheckConstraint("status IN ('active','suspended','removed')", name="ck_membership_status"),
    )
    op.create_table(
        "platform_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("company_creation_policy", sa.String(16), nullable=False),
        sa.Column("max_owned_companies_per_user", sa.Integer(), nullable=False),
        sa.Column("invitations_enabled", sa.Boolean(), nullable=False),
        *timestamps(),
        sa.CheckConstraint("id = 1", name="ck_settings_singleton"),
        sa.CheckConstraint(
            "company_creation_policy IN ('closed','approval','open')", name="ck_creation_policy"
        ),
        sa.CheckConstraint("max_owned_companies_per_user BETWEEN 1 AND 100", name="ck_company_limit"),
    )
    op.execute(
        "INSERT INTO platform_settings (id, company_creation_policy, max_owned_companies_per_user, invitations_enabled) VALUES (1, 'approval', 3, true) ON CONFLICT DO NOTHING"
    )
    op.create_table(
        "platform_admins",
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        ref("granted_by_user_id", "users.id", nullable=True),
        *timestamps(),
    )
    op.create_table(
        "company_requests",
        identifier(),
        ref("requested_by_user_id", "users.id"),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("requested_slug", sa.String(63), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        ref("reviewed_by_user_id", "users.id", nullable=True),
        sa.Column("review_comment", sa.String(1000)),
        ref("company_id", "companies.id", nullable=True),
        *timestamps(),
        sa.CheckConstraint(
            "status IN ('pending','approved','rejected','cancelled')", name="ck_request_status"
        ),
    )
    op.create_table(
        "employees",
        identifier(),
        ref("company_id", "companies.id"),
        ref("user_id", "users.id", nullable=True),
        sa.Column("display_name", sa.String(160), nullable=False),
        sa.Column("position", sa.String(160)),
        sa.Column("department", sa.String(160)),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        *timestamps(),
        sa.UniqueConstraint("company_id", "user_id", name="uq_employee_company_user"),
        sa.CheckConstraint("status IN ('active','inactive')", name="ck_employee_status"),
    )
    op.create_table(
        "invitations",
        identifier(),
        ref("company_id", "companies.id"),
        ref("created_by_user_id", "users.id"),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        ref("used_by_user_id", "users.id", nullable=True),
        ref("recipient_user_id", "users.id", nullable=True),
        sa.Column("recipient_email", sa.String(254)),
        *timestamps(),
        sa.CheckConstraint("role IN ('admin','member')", name="ck_invitation_role"),
        sa.CheckConstraint("status IN ('pending','accepted','revoked')", name="ck_invitation_status"),
        sa.CheckConstraint("expires_at > created_at", name="ck_invitation_expiry"),
    )
    op.create_table(
        "audit_events",
        identifier(),
        ref("actor_user_id", "users.id", nullable=True),
        ref("actor_identity_id", "identities.id", nullable=True),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource_type", sa.String(40), nullable=False),
        sa.Column("resource_id", sa.Uuid()),
        ref("company_id", "companies.id", nullable=True),
        sa.Column("request_id", sa.String(64)),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    for table, columns in {
        "memberships": ["company_id", "user_id"],
        "employees": ["company_id"],
        "invitations": ["company_id"],
        "company_requests": ["requested_by_user_id", "status"],
        "audit_events": ["action", "company_id", "created_at"],
    }.items():
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])
    # DB backstops also protect direct DML. Service operations acquire this gate BEFORE
    # reading mutable authorization/policies; deferred checks see the final transaction.
    op.execute("""CREATE FUNCTION core_mutation_gate() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN PERFORM id FROM platform_settings WHERE id=1 FOR UPDATE; RETURN NULL; END $$""")
    for table in ("memberships", "companies", "platform_admins", "users"):
        op.execute(
            f"CREATE TRIGGER core_gate BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION core_mutation_gate()"
        )
    op.execute("""CREATE FUNCTION core_check_owners() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF EXISTS (SELECT 1 FROM companies c WHERE c.status='active' AND NOT EXISTS (
        SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id
        WHERE m.company_id=c.id AND m.role='owner' AND m.status='active' AND u.status='active'))
      THEN RAISE EXCEPTION 'active company requires an owner' USING ERRCODE='23514'; END IF;
      RETURN NULL;
    END $$""")
    for table in ("memberships", "companies", "users"):
        op.execute(
            f"CREATE CONSTRAINT TRIGGER core_owner_guard AFTER INSERT OR UPDATE OR DELETE ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION core_check_owners()"
        )
    op.execute("""CREATE FUNCTION core_check_admins() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_TABLE_NAME='users' AND NOT EXISTS (SELECT 1 FROM platform_admins) THEN RETURN NULL; END IF;
      IF NOT EXISTS (SELECT 1 FROM platform_admins a JOIN users u ON u.id=a.user_id WHERE a.active AND u.status='active')
      THEN RAISE EXCEPTION 'last platform admin cannot be removed' USING ERRCODE='23514'; END IF;
      RETURN NULL;
    END $$""")
    op.execute(
        "CREATE CONSTRAINT TRIGGER core_admin_guard AFTER INSERT OR UPDATE OR DELETE ON platform_admins DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION core_check_admins()"
    )
    op.execute(
        "CREATE CONSTRAINT TRIGGER core_user_admin_guard AFTER UPDATE OR DELETE ON users DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION core_check_admins()"
    )
    op.execute("""CREATE FUNCTION core_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'audit is append only' USING ERRCODE='42501'; END $$""")
    op.execute(
        "CREATE TRIGGER core_audit_guard BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION core_audit_immutable()"
    )


def downgrade() -> None:
    # Explicitly refuse destructive downgrade: users, invitations and audit are business data.
    raise RuntimeError("Sprint 2 downgrade is destructive; use a reviewed backup/restore procedure")
