"""Close delete/reinsert and TRUNCATE bypasses of terminal instance revocation."""

from alembic import op

revision = "0007_instance_history"
down_revision = "0006_package_registry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE FUNCTION core_instance_history_guard() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'instance history is retained' USING ERRCODE='23514'; END $$""")
    op.execute(
        "CREATE TRIGGER core_instance_history_guard BEFORE DELETE OR TRUNCATE ON module_instances FOR EACH STATEMENT EXECUTE FUNCTION core_instance_history_guard()"
    )


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup under maintenance; destructive downgrade is disabled")
