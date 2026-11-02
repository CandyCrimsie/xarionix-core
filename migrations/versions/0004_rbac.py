"""Expand/backfill/switch RBAC without changing existing business identifiers."""

import json

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.domains.rbac.catalog_v1 import CORE_PERMISSIONS, SYSTEM_ROLES, TEMPLATES

revision = "0004_rbac"
down_revision = "0003_locking"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint("uq_membership_company_id", "memberships", ["company_id", "id"])
    op.create_unique_constraint("uq_invitation_company_id", "invitations", ["company_id", "id"])
    op.add_column("invitations", sa.Column("permission_snapshot", JSONB(), nullable=True))
    op.create_table(
        "permission_namespaces",
        sa.Column("name", sa.String(40), primary_key=True),
        sa.Column("owner", sa.String(80), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.CheckConstraint("state IN ('active','reserved','disabled')", name="ck_namespace_state"),
    )
    op.create_table(
        "permissions",
        sa.Column("key", sa.String(120), primary_key=True),
        sa.Column(
            "namespace",
            sa.String(40),
            sa.ForeignKey("permission_namespaces.name", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("description", sa.String(320), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("protected", sa.Boolean(), nullable=False),
        sa.Column("owner_grantable", sa.Boolean(), nullable=False),
        sa.CheckConstraint("scope='company'", name="ck_permission_scope"),
        sa.CheckConstraint(
            "key ~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_.]*[.][a-z][a-z0-9_]*$' AND split_part(key,'.',1)=namespace",
            name="ck_permission_key",
        ),
        sa.CheckConstraint("NOT protected OR NOT owner_grantable", name="ck_permission_protected"),
    )
    op.create_index("ix_permissions_namespace", "permissions", ["namespace"])
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "company_id", sa.Uuid(), sa.ForeignKey("companies.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("code", sa.String(63), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.String(1000)),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("definition_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_by_user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("company_id", "id", name="uq_role_company_id"),
        sa.UniqueConstraint("company_id", "code", name="uq_role_company_code"),
        sa.CheckConstraint("code ~ '^[a-z][a-z0-9_-]{1,62}$'", name="ck_role_code"),
        sa.CheckConstraint(
            "(is_system AND code IN ('owner','admin','member')) OR (NOT is_system AND code NOT IN ('owner','admin','member','platform_admin','core','system'))",
            name="ck_role_reserved",
        ),
        sa.CheckConstraint("version > 0 AND definition_version > 0", name="ck_role_version"),
    )
    op.create_index("ix_roles_company_id", "roles", ["company_id"])
    op.create_table(
        "role_permissions",
        sa.Column("company_id", sa.Uuid(), primary_key=True),
        sa.Column("role_id", sa.Uuid(), primary_key=True),
        sa.Column(
            "permission_key",
            sa.String(120),
            sa.ForeignKey("permissions.key", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.ForeignKeyConstraint(
            ["company_id", "role_id"], ["roles.company_id", "roles.id"], ondelete="RESTRICT"
        ),
    )
    op.create_table(
        "membership_roles",
        sa.Column("company_id", sa.Uuid(), primary_key=True),
        sa.Column("membership_id", sa.Uuid(), primary_key=True),
        sa.Column("role_id", sa.Uuid(), primary_key=True),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.ForeignKeyConstraint(
            ["company_id", "role_id"], ["roles.company_id", "roles.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["company_id", "membership_id"], ["memberships.company_id", "memberships.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint("origin IN ('system','custom')", name="ck_assignment_origin"),
    )
    op.create_index("ix_membership_roles_role_id", "membership_roles", ["role_id"])
    op.create_table(
        "role_templates",
        sa.Column("key", sa.String(120), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("permissions", JSONB(), nullable=False),
    )
    op.create_table(
        "permission_delegations",
        sa.Column("company_id", sa.Uuid(), primary_key=True),
        sa.Column("membership_id", sa.Uuid(), primary_key=True),
        sa.Column(
            "permission_key",
            sa.String(120),
            sa.ForeignKey("permissions.key", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("role_scope", sa.String(24), nullable=False, server_default="custom_roles"),
        sa.Column("member_scope", sa.String(24), nullable=False, server_default="non_owners"),
        sa.ForeignKeyConstraint(
            ["company_id", "membership_id"], ["memberships.company_id", "memberships.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "role_scope='custom_roles' AND member_scope='non_owners'", name="ck_delegation_scope"
        ),
    )
    op.create_table(
        "invitation_roles",
        sa.Column("company_id", sa.Uuid(), primary_key=True),
        sa.Column("invitation_id", sa.Uuid(), primary_key=True),
        sa.Column("role_id", sa.Uuid(), primary_key=True),
        sa.ForeignKeyConstraint(
            ["company_id", "role_id"], ["roles.company_id", "roles.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["company_id", "invitation_id"], ["invitations.company_id", "invitations.id"], ondelete="RESTRICT"
        ),
    )
    op.create_table(
        "system_role_definitions",
        sa.Column("code", sa.String(16), primary_key=True),
        sa.Column(
            "permission_key",
            sa.String(120),
            sa.ForeignKey("permissions.key", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
    )
    bind = op.get_bind()
    for name, state in (
        ("core", "active"),
        ("erp", "reserved"),
        ("oss", "reserved"),
        ("billing", "reserved"),
    ):
        bind.execute(
            sa.text("INSERT INTO permission_namespaces VALUES (:name,:owner,:state)"),
            {"name": name, "owner": "xarionix-" + name, "state": state},
        )
    for key, description, protected in CORE_PERMISSIONS:
        bind.execute(
            sa.text(
                "INSERT INTO permissions VALUES (:key,'core',:description,'company',true,:protected,:grantable)"
            ),
            {"key": key, "description": description, "protected": protected, "grantable": not protected},
        )
    for code, (_, permissions) in SYSTEM_ROLES.items():
        for key in sorted(permissions):
            bind.execute(
                sa.text("INSERT INTO system_role_definitions VALUES (:code,:key,1)"),
                {"code": code, "key": key},
            )
    for key, name, template_permissions in TEMPLATES:
        bind.execute(
            sa.text("INSERT INTO role_templates VALUES (:key,1,:name,CAST(:permissions AS jsonb))"),
            {"key": key, "name": name, "permissions": json.dumps(template_permissions)},
        )
    op.execute("""CREATE FUNCTION core_seed_roles(cid uuid) RETURNS void LANGUAGE plpgsql AS $$
    BEGIN
      INSERT INTO roles(id,company_id,code,name,is_system) VALUES
        (gen_random_uuid(),cid,'owner','Владелец',true),
        (gen_random_uuid(),cid,'admin','Администратор',true),
        (gen_random_uuid(),cid,'member','Участник',true);
      INSERT INTO role_permissions(company_id,role_id,permission_key)
        SELECT cid,r.id,d.permission_key FROM roles r JOIN system_role_definitions d ON d.code=r.code
        WHERE r.company_id=cid AND r.is_system;
    END $$""")
    op.execute("SELECT core_seed_roles(id) FROM companies")
    op.execute("""INSERT INTO membership_roles(company_id,membership_id,role_id,origin)
        SELECT m.company_id,m.id,r.id,'system' FROM memberships m JOIN roles r
        ON r.company_id=m.company_id AND r.code=m.role AND r.is_system""")
    op.execute("""CREATE FUNCTION core_company_roles() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN PERFORM core_seed_roles(NEW.id); RETURN NEW; END $$""")
    op.execute(
        "CREATE TRIGGER core_seed_company_roles AFTER INSERT ON companies FOR EACH ROW EXECUTE FUNCTION core_company_roles()"
    )
    op.execute("""CREATE FUNCTION core_membership_roles() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      DELETE FROM membership_roles WHERE membership_id=NEW.id AND company_id=NEW.company_id AND origin='system';
      IF NEW.status='removed' THEN
        DELETE FROM membership_roles WHERE membership_id=NEW.id AND company_id=NEW.company_id;
      ELSE
        INSERT INTO membership_roles(company_id,membership_id,role_id,origin)
          SELECT NEW.company_id,NEW.id,id,'system' FROM roles
          WHERE company_id=NEW.company_id AND code=NEW.role AND is_system;
      END IF;
      RETURN NEW;
    END $$""")
    op.execute(
        "CREATE TRIGGER core_sync_membership_roles AFTER INSERT OR UPDATE OF role,status ON memberships FOR EACH ROW EXECUTE FUNCTION core_membership_roles()"
    )
    op.execute("""CREATE FUNCTION core_rbac_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE cid uuid; rid uuid; system boolean; protected_permission boolean;
    BEGIN
      cid := CASE WHEN TG_OP='DELETE' THEN OLD.company_id ELSE NEW.company_id END;
      PERFORM core_lock('company',cid::text);
      IF TG_OP='UPDATE' THEN
        IF NEW.company_id IS DISTINCT FROM OLD.company_id THEN RAISE EXCEPTION 'immutable tenant' USING ERRCODE='23514'; END IF;
      END IF;
      IF TG_TABLE_NAME='roles' THEN
        IF TG_OP='INSERT' THEN
          IF NEW.is_system AND pg_trigger_depth()<=1 THEN RAISE EXCEPTION 'system role protected' USING ERRCODE='42501'; END IF;
        ELSIF OLD.is_system OR NEW.is_system THEN
          RAISE EXCEPTION 'system role protected' USING ERRCODE='42501';
        END IF;
      ELSIF TG_TABLE_NAME IN ('role_permissions','membership_roles','invitation_roles') THEN
        rid := CASE WHEN TG_OP='DELETE' THEN OLD.role_id ELSE NEW.role_id END;
        SELECT is_system INTO system FROM roles WHERE company_id=cid AND id=rid;
        IF TG_TABLE_NAME='role_permissions' THEN
          IF TG_OP='UPDATE' THEN
            IF EXISTS (SELECT 1 FROM roles WHERE company_id=OLD.company_id AND id=OLD.role_id AND is_system) AND pg_trigger_depth()<=1 THEN
              RAISE EXCEPTION 'system definition protected' USING ERRCODE='42501';
            END IF;
          END IF;
          IF system AND pg_trigger_depth()<=1 THEN RAISE EXCEPTION 'system definition protected' USING ERRCODE='42501'; END IF;
          IF NOT system AND TG_OP<>'DELETE' THEN
            SELECT protected INTO protected_permission FROM permissions WHERE key=NEW.permission_key;
            IF protected_permission THEN RAISE EXCEPTION 'protected authority' USING ERRCODE='23514'; END IF;
          END IF;
        ELSIF TG_TABLE_NAME='membership_roles' THEN
          IF TG_OP='UPDATE' THEN
            IF OLD.origin='system' AND pg_trigger_depth()<=1 THEN RAISE EXCEPTION 'protected compatibility assignment' USING ERRCODE='42501'; END IF;
          END IF;
          IF TG_OP='DELETE' THEN
            IF OLD.origin='system' AND pg_trigger_depth()<=1 THEN RAISE EXCEPTION 'protected compatibility assignment' USING ERRCODE='42501'; END IF;
          ELSE
            IF (NEW.origin='system' AND pg_trigger_depth()<=1) OR (NEW.origin='custom' AND system) THEN
              RAISE EXCEPTION 'protected compatibility assignment' USING ERRCODE='42501';
            END IF;
          END IF;
        ELSIF system THEN RAISE EXCEPTION 'custom invitation role required' USING ERRCODE='23514';
        END IF;
      ELSIF TG_TABLE_NAME='permission_delegations' AND TG_OP<>'DELETE' THEN
        SELECT protected INTO protected_permission FROM permissions WHERE key=NEW.permission_key;
        IF protected_permission THEN RAISE EXCEPTION 'protected delegation' USING ERRCODE='23514'; END IF;
      END IF;
      IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END $$""")
    for table in (
        "roles",
        "role_permissions",
        "membership_roles",
        "permission_delegations",
        "invitation_roles",
    ):
        op.execute(
            f"CREATE TRIGGER core_rbac_guard BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION core_rbac_guard()"
        )
    op.execute("""CREATE FUNCTION core_catalog_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'trusted deployment catalog only' USING ERRCODE='42501'; END $$""")
    for table in ("permissions", "permission_namespaces", "role_templates", "system_role_definitions"):
        op.execute(
            f"CREATE TRIGGER core_catalog_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION core_catalog_immutable()"
        )


def downgrade() -> None:
    raise RuntimeError("RBAC downgrade loses grants; restore a reviewed maintenance backup instead")
