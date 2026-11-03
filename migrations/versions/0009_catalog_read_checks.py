"""Epoch checks need SELECT, never permission-catalog UPDATE authority for HTTP runtime."""

from alembic import op

revision = "0009_catalog_read_checks"
down_revision = "0008_module_installations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # No row lock: a concurrent definition change invalidates the saved epoch in
    # effective authorization. It must not force runtime catalog UPDATE privileges.
    op.execute("""CREATE OR REPLACE FUNCTION core_module_grant_generation() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE p public.permissions;
    BEGIN
      SELECT * INTO STRICT p FROM public.permissions WHERE key=NEW.permission_key;
      IF NEW.permission_generation<>p.definition_generation THEN
        RAISE EXCEPTION 'permission generation mismatch' USING ERRCODE='23514'; END IF;
      RETURN NEW;
    END $$""")


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup under maintenance; destructive downgrade is disabled")
