"""An explicitly enrolled agent must never fall back to unbound legacy authority."""

from alembic import op

revision = "0010_instance_enrollment"
down_revision = "0009_catalog_read_checks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    ALTER TABLE module_instances ADD COLUMN installation_managed boolean NOT NULL DEFAULT false;
    UPDATE module_instances SET installation_managed=true WHERE id IN
      (SELECT instance_id FROM module_instance_bindings WHERE instance_id IS NOT NULL);
    CREATE FUNCTION core_instance_enrollment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF (OLD.installation_managed AND NOT NEW.installation_managed)
        OR (NOT OLD.installation_managed AND NEW.installation_managed AND NOT EXISTS
          (SELECT 1 FROM module_instance_bindings WHERE instance_id=NEW.id))
      THEN RAISE EXCEPTION 'installation enrollment is retained' USING ERRCODE='23514'; END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER core_instance_enrollment_guard BEFORE UPDATE ON module_instances
      FOR EACH ROW EXECUTE FUNCTION core_instance_enrollment_guard();
    """)


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup under maintenance; destructive downgrade is disabled")
