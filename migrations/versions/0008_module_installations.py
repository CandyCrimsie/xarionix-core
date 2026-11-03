"""Global installation plans and a separately provisioned, fixed catalog capability.

No LOGIN roles, credentials, grants to the HTTP runtime, or changes to old migrations.
The catalog function is inert until a DBA transfers it to the dedicated NOLOGIN role.
"""

from alembic import op

revision = "0008_module_installations"
down_revision = "0007_instance_history"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE OR REPLACE FUNCTION core_lock(scope text, identifier text, shared boolean DEFAULT false)
    RETURNS void LANGUAGE plpgsql VOLATILE AS $$
    DECLARE key bigint;
    BEGIN
      IF scope NOT IN ('company','quota','administration','module_installation','module_namespace','module_instance_binding') OR identifier IS NULL THEN
        RAISE EXCEPTION 'invalid lock resource' USING ERRCODE='22023'; END IF;
      key := hashtextextended('xarionix-core/v3/' || scope || '/' || identifier, 0);
      IF shared THEN PERFORM pg_advisory_xact_lock_shared(key);
      ELSE PERFORM pg_advisory_xact_lock(key); END IF;
    END $$""")
    op.execute("""
    ALTER TABLE permissions ADD COLUMN definition_generation integer NOT NULL DEFAULT 1 CHECK (definition_generation > 0);
    ALTER TABLE role_permissions ADD COLUMN permission_generation integer NOT NULL DEFAULT 1 CHECK (permission_generation > 0);
    ALTER TABLE permission_delegations ADD COLUMN permission_generation integer NOT NULL DEFAULT 1 CHECK (permission_generation > 0);
    CREATE TABLE module_installations (
      id uuid PRIMARY KEY, module_id varchar(63) NOT NULL UNIQUE,
      publisher_id uuid NOT NULL REFERENCES package_publishers ON DELETE RESTRICT,
      package_id uuid NOT NULL REFERENCES module_packages ON DELETE RESTRICT,
      previous_package_id uuid REFERENCES module_packages ON DELETE RESTRICT,
      namespace varchar(40) NOT NULL UNIQUE CHECK (namespace <> 'core'),
      module_type varchar(16) NOT NULL CHECK (module_type IN ('standard','autonomous')),
      status varchar(24) NOT NULL CHECK (status IN ('installed_disabled','installed_enabled','removed')),
      generation integer NOT NULL CHECK (generation > 0),
      installed_by_user_id uuid NOT NULL REFERENCES users ON DELETE RESTRICT,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE module_dependency_pins (
      installation_id uuid NOT NULL REFERENCES module_installations ON DELETE RESTRICT,
      dependency_id uuid NOT NULL REFERENCES module_installations ON DELETE RESTRICT,
      package_id uuid NOT NULL REFERENCES module_packages ON DELETE RESTRICT,
      generation integer NOT NULL CHECK (generation > 0),
      PRIMARY KEY (installation_id, dependency_id), CHECK (installation_id <> dependency_id)
    );
    CREATE INDEX ix_module_dependency_pins_dependency_id ON module_dependency_pins(dependency_id);
    CREATE TABLE module_install_plans (
      id uuid PRIMARY KEY, action varchar(16) NOT NULL CHECK (action IN ('install','update','enable','disable','uninstall','rollback')),
      module_id varchar(63) NOT NULL, package_id uuid NOT NULL REFERENCES module_packages ON DELETE RESTRICT,
      expected_generation integer NOT NULL CHECK (expected_generation >= 0),
      digest varchar(64) NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'), body jsonb NOT NULL,
      state varchar(16) NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','cancelled','applied')),
      created_by uuid NOT NULL REFERENCES users ON DELETE RESTRICT,
      created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
      approved_by uuid REFERENCES users ON DELETE RESTRICT,
      approved_identity_id uuid REFERENCES identities ON DELETE RESTRICT,
      approved_at timestamptz, approved_until timestamptz, approval jsonb,
      CHECK ((approved_by IS NULL) = (approved_at IS NULL) AND (approved_by IS NULL) = (approved_until IS NULL))
    );
    CREATE INDEX ix_module_install_plans_module_id ON module_install_plans(module_id);
    CREATE TABLE module_install_operations (
      id uuid PRIMARY KEY, plan_id uuid NOT NULL UNIQUE REFERENCES module_install_plans ON DELETE RESTRICT,
      module_id varchar(63) NOT NULL,
      state varchar(16) NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','applying','succeeded','failed')),
      attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 32),
      fence uuid, lease_until timestamptz, started_at timestamptz, completed_at timestamptz,
      safe_error_code varchar(80), failures jsonb NOT NULL DEFAULT '[]', correlation_id uuid NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX ix_module_install_operations_module_id ON module_install_operations(module_id);
    CREATE UNIQUE INDEX uq_module_active_operation ON module_install_operations(module_id) WHERE state='applying';
    CREATE TABLE module_installation_history (
      id uuid PRIMARY KEY, installation_id uuid NOT NULL REFERENCES module_installations ON DELETE RESTRICT,
      operation_id uuid NOT NULL UNIQUE REFERENCES module_install_operations ON DELETE RESTRICT,
      previous_package_id uuid REFERENCES module_packages ON DELETE RESTRICT,
      package_id uuid NOT NULL REFERENCES module_packages ON DELETE RESTRICT,
      previous_state varchar(24), state varchar(24) NOT NULL,
      generation integer NOT NULL, performed_by uuid NOT NULL REFERENCES users ON DELETE RESTRICT,
      created_at timestamptz NOT NULL DEFAULT now(), UNIQUE (installation_id, generation)
    );
    CREATE INDEX ix_module_installation_history_installation_id ON module_installation_history(installation_id);
    CREATE TABLE module_instance_bindings (
      installation_id uuid PRIMARY KEY REFERENCES module_installations ON DELETE RESTRICT,
      instance_id uuid UNIQUE REFERENCES module_instances ON DELETE RESTRICT,
      package_id uuid NOT NULL REFERENCES module_packages ON DELETE RESTRICT,
      active boolean NOT NULL, revision integer NOT NULL CHECK (revision > 0),
      bound_by uuid NOT NULL REFERENCES users ON DELETE RESTRICT,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
    );
    """)
    # No session variable can enable this capability. NOLOGIN owner has no members.
    op.execute("""
    CREATE OR REPLACE FUNCTION core_catalog_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF current_user = 'xarionix_module_catalog'
        AND TG_TABLE_NAME IN ('permissions','permission_namespaces') AND TG_OP IN ('INSERT','UPDATE')
      THEN RETURN NULL; END IF;
      RAISE EXCEPTION 'catalog is deployment managed' USING ERRCODE='42501';
    END $$;
    CREATE FUNCTION core_module_catalog_rows() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_TABLE_NAME='permission_namespaces' THEN
        IF NEW.name='core' OR (TG_OP='UPDATE' AND (NEW.name<>OLD.name OR NEW.owner<>OLD.owner))
          OR (NEW.name IN ('erp','oss','billing') AND NEW.owner<>'xarionix-'||NEW.name)
        THEN RAISE EXCEPTION 'namespace ownership is immutable' USING ERRCODE='23514'; END IF;
      ELSE
        IF NEW.namespace='core' OR NEW.protected OR NOT NEW.owner_grantable
          OR (TG_OP='UPDATE' AND (NEW.key<>OLD.key OR NEW.namespace<>OLD.namespace
            OR NEW.definition_generation<OLD.definition_generation))
        THEN RAISE EXCEPTION 'permission ownership is immutable' USING ERRCODE='23514'; END IF;
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER core_module_catalog_rows BEFORE INSERT OR UPDATE ON permissions
      FOR EACH ROW EXECUTE FUNCTION core_module_catalog_rows();
    CREATE TRIGGER core_module_catalog_rows BEFORE INSERT OR UPDATE ON permission_namespaces
      FOR EACH ROW EXECUTE FUNCTION core_module_catalog_rows();
    CREATE FUNCTION core_installation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP='TRUNCATE' OR (TG_OP='DELETE' AND TG_TABLE_NAME<>'module_dependency_pins')
        OR (TG_TABLE_NAME='module_installation_history' AND TG_OP='UPDATE')
      THEN RAISE EXCEPTION 'installation history is retained' USING ERRCODE='42501'; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='xarionix_module_executor')
        OR NOT pg_has_role(current_user, 'xarionix_module_executor', 'MEMBER')
      THEN RAISE EXCEPTION 'trusted installation executor required' USING ERRCODE='42501'; END IF;
      IF TG_TABLE_NAME='module_installations' AND TG_OP='UPDATE' THEN
        IF NEW.id<>OLD.id OR NEW.module_id<>OLD.module_id OR NEW.publisher_id<>OLD.publisher_id
          OR NEW.namespace<>OLD.namespace OR NEW.generation<>OLD.generation+1
        THEN RAISE EXCEPTION 'installation identity or generation invalid' USING ERRCODE='23514'; END IF;
      END IF;
      IF TG_OP='DELETE' THEN RETURN OLD; END IF;
      RETURN NEW;
    END $$;
    CREATE FUNCTION core_install_plan_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'installation history is retained' USING ERRCODE='42501';
      END IF;
      IF TG_OP='UPDATE' THEN
        IF (to_jsonb(NEW)-ARRAY['state','approved_by','approved_identity_id','approved_at','approved_until','approval'])
          IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','approved_by','approved_identity_id','approved_at','approved_until','approval'])
          OR OLD.state IN ('applied','cancelled')
          OR (OLD.approved_by IS NOT NULL AND (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state'))
          OR (NEW.state='applied' AND (NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='xarionix_module_executor')
            OR NOT pg_has_role(current_user,'xarionix_module_executor','MEMBER')))
        THEN RAISE EXCEPTION 'install plan is immutable' USING ERRCODE='23514'; END IF;
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER core_install_plan_guard BEFORE UPDATE OR DELETE ON module_install_plans
      FOR EACH ROW EXECUTE FUNCTION core_install_plan_guard();
    CREATE TRIGGER core_install_plan_truncate BEFORE TRUNCATE ON module_install_plans
      FOR EACH STATEMENT EXECUTE FUNCTION core_install_plan_guard();
    CREATE FUNCTION core_installation_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'binding history is retained' USING ERRCODE='23514'; END IF;
      IF TG_OP='UPDATE' AND (NEW.installation_id<>OLD.installation_id OR NEW.revision<>OLD.revision+1) THEN
        RAISE EXCEPTION 'binding revision invalid' USING ERRCODE='23514'; END IF;
      IF NEW.active AND NOT EXISTS(SELECT 1 FROM module_installations i
        JOIN module_instances a ON a.id=NEW.instance_id JOIN module_services s ON s.id=a.service_id
        WHERE i.id=NEW.installation_id AND i.package_id=NEW.package_id AND i.module_type='autonomous'
          AND i.status<>'removed' AND a.status='active' AND s.status='active' AND s.module_key=i.module_id)
      THEN RAISE EXCEPTION 'binding identity invalid' USING ERRCODE='23514'; END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER core_installation_binding_guard BEFORE INSERT OR UPDATE OR DELETE ON module_instance_bindings
      FOR EACH ROW EXECUTE FUNCTION core_installation_binding_guard();
    CREATE TRIGGER core_installation_binding_truncate BEFORE TRUNCATE ON module_instance_bindings
      FOR EACH STATEMENT EXECUTE FUNCTION core_installation_binding_guard();
    """)
    for table in (
        "module_installations",
        "module_dependency_pins",
        "module_install_operations",
        "module_installation_history",
    ):
        op.execute(
            f"CREATE TRIGGER core_installation_guard BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION core_installation_guard()"
        )
        op.execute(
            f"CREATE TRIGGER core_installation_truncate BEFORE TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION core_installation_guard()"
        )
    # Only this fixed function runs under catalog ownership. It accepts no SQL/JSON payload.
    op.execute("""
    CREATE FUNCTION core_apply_module_catalog(plan_uuid uuid, plan_digest text, operation_fence uuid)
    RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
    DECLARE p public.module_install_plans; pkg public.module_packages; inst public.module_installations;
      ns text; definition jsonb; key_text text; present_keys text[];
    BEGIN
      IF current_user<>'xarionix_module_catalog' THEN
        RAISE EXCEPTION 'catalog executor not provisioned' USING ERRCODE='42501'; END IF;
      SELECT * INTO STRICT p FROM public.module_install_plans WHERE id=plan_uuid;
      IF p.digest<>plan_digest OR p.state<>'approved' OR p.expires_at<=clock_timestamp()
        OR p.approved_until<=clock_timestamp() OR p.approved_by IS NULL
        OR NOT EXISTS (SELECT 1 FROM public.module_install_operations
          WHERE plan_id=p.id AND state='applying' AND fence=operation_fence AND lease_until>clock_timestamp())
      THEN RAISE EXCEPTION 'approved live operation required' USING ERRCODE='23514'; END IF;
      SELECT * INTO STRICT pkg FROM public.module_packages WHERE id=p.package_id;
      SELECT * INTO STRICT inst FROM public.module_installations WHERE module_id=p.module_id;
      ns:=pkg.manifest->'permissions'->>'namespace';
      IF pkg.module_id<>inst.module_id OR pkg.publisher_id<>inst.publisher_id OR ns<>inst.namespace
        OR pkg.id<>inst.package_id OR ns='core'
        OR (ns IN ('erp','oss','billing') AND pkg.module_id<>'xarionix-'||ns)
        OR NOT EXISTS (SELECT 1 FROM public.package_publishers pub
          JOIN public.publisher_signing_keys k ON k.publisher_id=pub.id
          JOIN public.publisher_namespace_grants g ON g.publisher_id=pub.id
          WHERE pub.id=pkg.publisher_id AND k.id=pkg.signing_key_id AND pub.status='active'
            AND k.status='active' AND g.namespace=ns AND g.status='active') OR pkg.state<>'available'
      THEN RAISE EXCEPTION 'package authority mismatch' USING ERRCODE='23514'; END IF;
      IF EXISTS (SELECT 1 FROM public.permission_namespaces WHERE name=ns AND owner<>pkg.module_id)
      THEN RAISE EXCEPTION 'namespace owner mismatch' USING ERRCODE='23514'; END IF;
      INSERT INTO public.permission_namespaces(name,owner,state) VALUES(ns,pkg.module_id,'disabled')
        ON CONFLICT(name) DO NOTHING;
      IF p.action IN ('install','update','rollback') THEN
        present_keys:=ARRAY(SELECT d->>'key' FROM jsonb_array_elements(pkg.manifest->'permissions'->'definitions') d);
        UPDATE public.permissions SET active=false, definition_generation=definition_generation+1
          WHERE namespace=ns AND active AND NOT (key=ANY(present_keys));
        FOR definition IN SELECT * FROM jsonb_array_elements(pkg.manifest->'permissions'->'definitions') LOOP
          key_text:=definition->>'key';
          INSERT INTO public.permissions(key,namespace,description,scope,active,protected,owner_grantable,definition_generation)
            VALUES(key_text,ns,definition->>'description','company',true,false,true,1)
          ON CONFLICT(key) DO UPDATE SET description=EXCLUDED.description,active=true,
            definition_generation=public.permissions.definition_generation +
              CASE WHEN NOT public.permissions.active OR public.permissions.description<>EXCLUDED.description THEN 1 ELSE 0 END;
        END LOOP;
      END IF;
      IF p.action='uninstall' THEN
        UPDATE public.permissions SET active=false,definition_generation=definition_generation+1 WHERE namespace=ns AND active;
      END IF;
      UPDATE public.permission_namespaces SET state=CASE WHEN inst.status='installed_enabled' THEN 'active' ELSE 'disabled' END WHERE name=ns;
    END $$;
    REVOKE ALL ON FUNCTION core_apply_module_catalog(uuid,text,uuid) FROM PUBLIC;
    """)
    op.execute("""
    CREATE FUNCTION core_module_authorized(iid uuid, stale_seconds integer) RETURNS boolean
    LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
      SELECT EXISTS(SELECT 1 FROM public.module_installations i
        JOIN public.module_packages p ON p.id=i.package_id
        JOIN public.package_publishers pub ON pub.id=p.publisher_id
        JOIN public.publisher_signing_keys k ON k.id=p.signing_key_id
        JOIN public.publisher_namespace_grants g ON g.publisher_id=pub.id AND g.namespace=i.namespace
        WHERE i.id=iid AND i.status='installed_enabled' AND p.state='available'
          AND pub.status='active' AND k.status='active' AND g.status='active'
          AND ((i.module_type='standard' AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(p.manifest->'artifacts') a WHERE a->>'path' NOT LIKE 'payload/resources/%'))
          OR (i.module_type='autonomous' AND EXISTS (
            SELECT 1 FROM public.module_instance_bindings b
              JOIN public.module_instances a ON a.id=b.instance_id JOIN public.module_services s ON s.id=a.service_id
            WHERE b.installation_id=i.id AND b.package_id=i.package_id AND b.active
              AND a.status='active' AND s.status='active' AND a.protocol_version=1 AND a.health='healthy'
              AND a.last_seen > statement_timestamp() - make_interval(secs=>greatest(10,least(900,stale_seconds)))))))
    $$;
    CREATE FUNCTION core_module_available(ns text, stale_seconds integer) RETURNS boolean
    LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
      SELECT ns='core' OR EXISTS(SELECT 1 FROM public.module_installations i
        JOIN public.permission_namespaces n ON n.name=i.namespace AND n.owner=i.module_id
        WHERE i.namespace=ns AND n.state='active' AND public.core_module_authorized(i.id,stale_seconds)
        AND NOT EXISTS (SELECT 1 FROM public.module_dependency_pins pin
          JOIN public.module_installations d ON d.id=pin.dependency_id
          WHERE pin.installation_id=i.id AND (d.package_id<>pin.package_id
            OR NOT public.core_module_authorized(d.id,stale_seconds))))
    $$;
    CREATE FUNCTION core_module_grant_generation() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE p public.permissions;
    BEGIN
      SELECT * INTO STRICT p FROM public.permissions WHERE key=NEW.permission_key FOR SHARE;
      IF NEW.permission_generation<>p.definition_generation THEN
        RAISE EXCEPTION 'permission generation mismatch' USING ERRCODE='23514'; END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER core_module_grant_generation BEFORE INSERT OR UPDATE ON role_permissions
      FOR EACH ROW EXECUTE FUNCTION core_module_grant_generation();
    CREATE TRIGGER core_module_grant_generation BEFORE INSERT OR UPDATE ON permission_delegations
      FOR EACH ROW EXECUTE FUNCTION core_module_grant_generation();
    """)


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup under maintenance; destructive downgrade is disabled")
