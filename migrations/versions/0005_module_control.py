"""Separate machine bindings, company scopes and durable bounded command delivery."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0005_module_control"
down_revision = "0004_rbac"
branch_labels = None
depends_on = None


def timestamps() -> list[sa.Column]:  # type: ignore[type-arg]
    return [
        sa.Column(name, sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now())
        for name in ("created_at", "updated_at")
    ]


def ref(name: str, target: str, *, primary: bool = False) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(
        name, sa.Uuid(), sa.ForeignKey(target, ondelete="RESTRICT"), nullable=False, primary_key=primary
    )


def upgrade() -> None:
    op.create_table(
        "module_services",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("module_key", sa.String(63), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.String(1000)),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("client_id", sa.String(120), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("operations", JSONB(), nullable=False),
        ref("registered_by_user_id", "users.id"),
        *timestamps(),
        sa.UniqueConstraint("issuer", "subject", name="uq_module_service_subject"),
        sa.UniqueConstraint("issuer", "client_id", name="uq_module_service_client"),
        sa.CheckConstraint("status IN ('active','disabled','revoked')", name="ck_module_service_status"),
        sa.CheckConstraint(
            "module_key ~ '^[a-z][a-z0-9-]{1,62}$' AND module_key NOT IN ('core','xarionix-core')",
            name="ck_module_key",
        ),
        sa.CheckConstraint(
            'jsonb_typeof(operations)=\'array\' AND \'["core.modules.connect","core.modules.heartbeat","core.modules.commands.read","core.modules.commands.ack","core.modules.metadata.read"]\'::jsonb @> operations',
            name="ck_module_operations",
        ),
    )
    op.create_index("ix_module_services_module_key", "module_services", ["module_key"])
    op.create_table(
        "module_instances",
        sa.Column("id", sa.Uuid(), primary_key=True),
        ref("service_id", "module_services.id"),
        sa.Column("installation_key", sa.String(63), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("next_check_in_at", sa.DateTime(timezone=True)),
        sa.Column("health", sa.String(16)),
        sa.Column("agent_version", sa.String(32)),
        sa.Column("protocol_version", sa.Integer()),
        *timestamps(),
        sa.UniqueConstraint("service_id", name="uq_module_instance_service"),
        sa.UniqueConstraint("service_id", "installation_key", name="uq_module_installation"),
        sa.CheckConstraint("status IN ('active','disabled','revoked')", name="ck_module_instance_status"),
        sa.CheckConstraint(
            "health IS NULL OR health IN ('healthy','degraded','error')", name="ck_module_health"
        ),
        sa.CheckConstraint("protocol_version IS NULL OR protocol_version=1", name="ck_module_protocol"),
    )
    op.create_table(
        "module_company_scopes",
        ref("instance_id", "module_instances.id", primary=True),
        ref("company_id", "companies.id", primary=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("operations", JSONB(), nullable=False),
        *timestamps(),
        sa.CheckConstraint("status IN ('active','revoked')", name="ck_module_scope_status"),
        sa.CheckConstraint(
            "jsonb_typeof(operations)='array' AND '[\"core.modules.metadata.read\"]'::jsonb @> operations",
            name="ck_module_scope_operations",
        ),
    )
    op.create_index("ix_module_scopes_company", "module_company_scopes", ["company_id"])
    op.create_table(
        "module_commands",
        sa.Column("id", sa.Uuid(), primary_key=True),
        ref("instance_id", "module_instances.id"),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("result", JSONB()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("request_id", sa.String(64), nullable=False),
        ref("created_by_user_id", "users.id"),
        sa.CheckConstraint("operation IN ('ping','get_status')", name="ck_module_command_operation"),
        sa.CheckConstraint(
            "state IN ('pending','delivered','completed','expired')", name="ck_module_command_state"
        ),
        sa.CheckConstraint("attempts BETWEEN 0 AND 5", name="ck_module_command_attempts"),
        sa.CheckConstraint("expires_at>created_at", name="ck_module_command_expiry"),
        sa.CheckConstraint(
            "(state='completed')=(completed_at IS NOT NULL AND result IS NOT NULL)",
            name="ck_module_command_completion",
        ),
    )
    op.create_index("ix_module_commands_instance_id", "module_commands", ["instance_id"])
    op.create_index(
        "ix_module_commands_poll", "module_commands", ["instance_id", "state", "lease_until", "created_at"]
    )
    op.execute("""CREATE FUNCTION core_module_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      PERFORM pg_advisory_xact_lock(hashtextextended('module-binding/'||NEW.issuer||'/'||NEW.subject,0));
      IF TG_OP='UPDATE' AND (NEW.issuer,NEW.subject,NEW.client_id,NEW.module_key)
          IS DISTINCT FROM (OLD.issuer,OLD.subject,OLD.client_id,OLD.module_key) THEN
        RAISE EXCEPTION 'explicit new machine binding required' USING ERRCODE='23514';
      END IF;
      IF TG_OP='UPDATE' AND OLD.status='revoked' AND NEW.status<>'revoked' THEN
        RAISE EXCEPTION 'revocation is terminal' USING ERRCODE='23514';
      END IF;
      IF EXISTS (SELECT 1 FROM identities WHERE issuer=NEW.issuer AND subject=NEW.subject) THEN
        RAISE EXCEPTION 'identity already admitted through legacy path' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END $$""")
    op.execute(
        "CREATE TRIGGER core_module_binding_guard BEFORE INSERT OR UPDATE ON module_services FOR EACH ROW EXECUTE FUNCTION core_module_binding_guard()"
    )
    op.execute("""CREATE FUNCTION core_no_machine_jit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      PERFORM pg_advisory_xact_lock(hashtextextended('module-binding/'||NEW.issuer||'/'||NEW.subject,0));
      IF EXISTS (SELECT 1 FROM module_services WHERE issuer=NEW.issuer AND subject=NEW.subject) THEN
        RAISE EXCEPTION 'machine cannot become legacy identity' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END $$""")
    op.execute(
        "CREATE TRIGGER core_no_machine_jit BEFORE INSERT OR UPDATE OF issuer,subject ON identities FOR EACH ROW EXECUTE FUNCTION core_no_machine_jit()"
    )


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup under maintenance; destructive downgrade is disabled")
