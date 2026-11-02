"""Inert signed packages, external publisher trust and terminal instance revocation."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0006_package_registry"
down_revision = "0005_module_control"
branch_labels = None
depends_on = None


def ref(name: str, target: str) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(name, sa.Uuid(), sa.ForeignKey(target, ondelete="RESTRICT"), nullable=False)


def times() -> list[sa.Column]:  # type: ignore[type-arg]
    return [
        sa.Column(name, sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now())
        for name in ("created_at", "updated_at")
    ]


def upgrade() -> None:
    op.create_table(
        "package_publishers",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("publisher_id", sa.String(63), nullable=False, unique=True),
        sa.Column("display_name", sa.String(160), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        *times(),
        sa.CheckConstraint("status IN ('active','revoked')", name="ck_publisher_status"),
        sa.CheckConstraint("publisher_id ~ '^[a-z][a-z0-9-]{1,62}$'", name="ck_publisher_identifier"),
    )
    op.create_table(
        "publisher_signing_keys",
        sa.Column("id", sa.Uuid(), primary_key=True),
        ref("publisher_id", "package_publishers.id"),
        sa.Column("key_id", sa.String(63), nullable=False),
        sa.Column("public_key", sa.String(44), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("algorithm", sa.String(16), nullable=False, server_default="Ed25519"),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        *times(),
        sa.UniqueConstraint("publisher_id", "key_id", name="uq_publisher_key_id"),
        sa.UniqueConstraint("publisher_id", "fingerprint", name="uq_publisher_key_material"),
        sa.CheckConstraint(
            "status IN ('active','revoked') AND algorithm='Ed25519'", name="ck_signing_key_state"
        ),
        sa.CheckConstraint("(status='revoked')=(revoked_at IS NOT NULL)", name="ck_key_revoked_at"),
        sa.CheckConstraint(
            "key_id ~ '^[a-z][a-z0-9-]{1,62}$' AND fingerprint ~ '^[0-9a-f]{64}$'", name="ck_key_identifiers"
        ),
    )
    op.create_index("ix_publisher_signing_keys_publisher_id", "publisher_signing_keys", ["publisher_id"])
    op.create_table(
        "publisher_namespace_grants",
        sa.Column("namespace", sa.String(40), primary_key=True),
        ref("publisher_id", "package_publishers.id"),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        *times(),
        sa.CheckConstraint(
            "status IN ('active','revoked') AND namespace<>'core'", name="ck_publisher_namespace"
        ),
        sa.CheckConstraint("namespace ~ '^[a-z][a-z0-9_]{1,39}$'", name="ck_namespace_identifier"),
    )
    op.create_index(
        "ix_publisher_namespace_grants_publisher_id", "publisher_namespace_grants", ["publisher_id"]
    )
    op.create_table(
        "module_packages",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("module_id", sa.String(63), nullable=False),
        sa.Column("version", sa.String(120), nullable=False),
        ref("publisher_id", "package_publishers.id"),
        ref("signing_key_id", "publisher_signing_keys.id"),
        sa.Column("package_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="available"),
        sa.Column("manifest", JSONB(), nullable=False),
        ref("imported_by_user_id", "users.id"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("module_id", "version", "publisher_id", name="uq_package_identity"),
        sa.CheckConstraint(
            "state IN ('available','quarantined') AND size BETWEEN 1 AND 134217728",
            name="ck_package_state_size",
        ),
        sa.CheckConstraint(
            "package_sha256 ~ '^[0-9a-f]{64}$' AND manifest_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_package_digests",
        ),
    )
    op.create_index("ix_module_packages_module_id", "module_packages", ["module_id"])
    op.execute("""CREATE FUNCTION core_package_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path=pg_catalog,public,pg_temp AS $$
    BEGIN
      IF TG_OP='DELETE' THEN RAISE EXCEPTION 'package history is retained' USING ERRCODE='23514'; END IF;
      IF TG_TABLE_NAME='module_packages' THEN
        IF TG_OP='UPDATE' AND (to_jsonb(NEW)-'state'-'verified_at') IS DISTINCT FROM (to_jsonb(OLD)-'state'-'verified_at') THEN
          RAISE EXCEPTION 'package identity is immutable' USING ERRCODE='23514';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM publisher_signing_keys k WHERE k.id=NEW.signing_key_id AND k.publisher_id=NEW.publisher_id) THEN
          RAISE EXCEPTION 'publisher key mismatch' USING ERRCODE='23514'; END IF;
      ELSIF TG_OP='UPDATE' THEN
        IF OLD.status='revoked' AND NEW.status<>'revoked' THEN
          RAISE EXCEPTION 'revocation is terminal' USING ERRCODE='23514'; END IF;
        IF TG_TABLE_NAME='package_publishers' THEN
          IF (NEW.id,NEW.publisher_id) IS DISTINCT FROM (OLD.id,OLD.publisher_id) THEN
            RAISE EXCEPTION 'publisher immutable' USING ERRCODE='23514'; END IF;
        ELSIF TG_TABLE_NAME='publisher_signing_keys' THEN
          IF (NEW.id,NEW.publisher_id,NEW.key_id,NEW.public_key,NEW.fingerprint,NEW.algorithm)
           IS DISTINCT FROM (OLD.id,OLD.publisher_id,OLD.key_id,OLD.public_key,OLD.fingerprint,OLD.algorithm) THEN
            RAISE EXCEPTION 'key immutable' USING ERRCODE='23514'; END IF;
        ELSIF TG_TABLE_NAME='publisher_namespace_grants' THEN
          IF (NEW.namespace,NEW.publisher_id) IS DISTINCT FROM (OLD.namespace,OLD.publisher_id) THEN
            RAISE EXCEPTION 'namespace ownership immutable' USING ERRCODE='23514'; END IF;
        END IF;
      END IF;
      RETURN NEW;
    END $$""")
    for table in (
        "module_packages",
        "package_publishers",
        "publisher_signing_keys",
        "publisher_namespace_grants",
    ):
        op.execute(
            f"CREATE TRIGGER core_package_guard BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION core_package_guard()"
        )
        op.execute(
            f"CREATE TRIGGER core_package_no_truncate BEFORE TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION core_catalog_immutable()"
        )
    op.execute("""CREATE FUNCTION core_instance_revoke_guard() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF OLD.status='revoked' AND NEW.status<>'revoked' THEN
          RAISE EXCEPTION 'revocation is terminal' USING ERRCODE='23514'; END IF;
        IF (NEW.id,NEW.service_id,NEW.installation_key) IS DISTINCT FROM (OLD.id,OLD.service_id,OLD.installation_key) THEN
          RAISE EXCEPTION 'instance binding is immutable' USING ERRCODE='23514'; END IF;
        RETURN NEW;
      END $$""")
    op.execute(
        "CREATE TRIGGER core_instance_revoke_guard BEFORE UPDATE ON module_instances FOR EACH ROW EXECUTE FUNCTION core_instance_revoke_guard()"
    )


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup under maintenance; destructive downgrade is disabled")
