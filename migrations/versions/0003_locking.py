"""Targeted, transaction-scoped locks and deferred invariant checks."""

from alembic import op

revision = "0003_locking"
down_revision = "0002_platform"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("memberships", "companies", "platform_admins", "users"):
        op.execute(f"DROP TRIGGER core_gate ON {table}")
    op.execute("DROP FUNCTION core_mutation_gate()")
    op.execute("""CREATE FUNCTION core_lock(scope text, identifier text, shared boolean DEFAULT false)
    RETURNS void LANGUAGE plpgsql VOLATILE AS $$
    DECLARE key bigint;
    BEGIN
      IF scope NOT IN ('company','quota','administration') OR identifier IS NULL THEN
        RAISE EXCEPTION 'invalid lock resource' USING ERRCODE='22023';
      END IF;
      key := hashtextextended('xarionix-core/v3/' || scope || '/' || identifier, 0);
      IF shared THEN PERFORM pg_advisory_xact_lock_shared(key);
      ELSE PERFORM pg_advisory_xact_lock(key); END IF;
    END $$""")
    op.execute("""CREATE FUNCTION core_scoped_gate() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE cid uuid; uid uuid;
    BEGIN
      IF TG_TABLE_NAME='platform_admins' THEN
        PERFORM core_lock('administration','singleton');
      ELSIF TG_TABLE_NAME='users' THEN
        IF TG_OP='UPDATE' AND NEW.status IS NOT DISTINCT FROM OLD.status THEN RETURN NEW; END IF;
        IF EXISTS (SELECT 1 FROM platform_admins WHERE user_id=OLD.id) THEN
          PERFORM core_lock('administration','singleton');
        END IF;
        FOR cid IN SELECT company_id FROM memberships WHERE user_id=OLD.id ORDER BY company_id LOOP
          PERFORM core_lock('company',cid::text);
        END LOOP;
      ELSIF TG_TABLE_NAME='memberships' THEN
        IF TG_OP='UPDATE' THEN
          IF NEW.company_id IS DISTINCT FROM OLD.company_id OR NEW.user_id IS DISTINCT FROM OLD.user_id THEN
            RAISE EXCEPTION 'immutable membership identity' USING ERRCODE='23514';
          END IF;
        END IF;
        PERFORM id FROM platform_settings WHERE id=1 FOR SHARE;
        FOR uid IN SELECT DISTINCT v FROM unnest(ARRAY[
          CASE WHEN TG_OP<>'INSERT' THEN OLD.user_id END,
          CASE WHEN TG_OP<>'DELETE' THEN NEW.user_id END]) v WHERE v IS NOT NULL ORDER BY v LOOP
          PERFORM core_lock('quota',uid::text);
        END LOOP;
        FOR cid IN SELECT DISTINCT v FROM unnest(ARRAY[
          CASE WHEN TG_OP<>'INSERT' THEN OLD.company_id END,
          CASE WHEN TG_OP<>'DELETE' THEN NEW.company_id END]) v WHERE v IS NOT NULL ORDER BY v LOOP
          PERFORM core_lock('company',cid::text);
        END LOOP;
      ELSIF TG_TABLE_NAME='companies' THEN
        IF TG_OP='UPDATE' AND NEW.status IS DISTINCT FROM OLD.status THEN
          PERFORM id FROM platform_settings WHERE id=1 FOR SHARE;
          FOR uid IN SELECT user_id FROM memberships WHERE company_id=OLD.id AND role='owner' ORDER BY user_id LOOP
            PERFORM core_lock('quota',uid::text);
          END LOOP;
        END IF;
        PERFORM core_lock('company', (CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END)::text);
      END IF;
      IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END $$""")
    for table in ("memberships", "companies", "platform_admins"):
        op.execute(
            f"CREATE TRIGGER core_gate BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION core_scoped_gate()"
        )
    op.execute(
        "CREATE TRIGGER core_gate BEFORE UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION core_scoped_gate()"
    )
    op.execute("""CREATE OR REPLACE FUNCTION core_check_owners() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE affected uuid[]; cid uuid;
    BEGIN
      IF TG_TABLE_NAME='users' THEN
        SELECT array_agg(company_id ORDER BY company_id) INTO affected FROM memberships WHERE user_id=OLD.id;
      ELSIF TG_TABLE_NAME='companies' THEN
        affected := ARRAY[CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END];
      ELSE
        affected := ARRAY[CASE WHEN TG_OP<>'INSERT' THEN OLD.company_id END,
                          CASE WHEN TG_OP<>'DELETE' THEN NEW.company_id END];
      END IF;
      FOREACH cid IN ARRAY coalesce(affected,ARRAY[]::uuid[]) LOOP
        IF EXISTS (SELECT 1 FROM companies WHERE id=cid AND status='active') AND NOT EXISTS (
          SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id
          WHERE m.company_id=cid AND m.role='owner' AND m.status='active' AND u.status='active') THEN
          RAISE EXCEPTION 'active company requires an owner' USING ERRCODE='23514';
        END IF;
      END LOOP;
      RETURN NULL;
    END $$""")
    op.execute("""CREATE OR REPLACE FUNCTION core_check_admins() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_TABLE_NAME='users' THEN
        IF NOT EXISTS (SELECT 1 FROM platform_admins WHERE user_id=OLD.id) THEN RETURN NULL; END IF;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM platform_admins a JOIN users u ON u.id=a.user_id WHERE a.active AND u.status='active') THEN
        RAISE EXCEPTION 'last platform admin cannot be removed' USING ERRCODE='23514';
      END IF;
      RETURN NULL;
    END $$""")


def downgrade() -> None:
    raise RuntimeError("Locking rollback requires reviewed maintenance restore, not a live downgrade")
