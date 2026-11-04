"""Outbound deployment control plane; no engine access or deployment DB identities."""

from alembic import op

revision = "0011_deployment_runtime"
down_revision = "0010_instance_enrollment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE deployment_hosts (
      id uuid PRIMARY KEY, name varchar(120) NOT NULL,
      issuer varchar(512) NOT NULL, subject varchar(255) NOT NULL, client_id varchar(120) NOT NULL,
      engine_id varchar(120) NOT NULL UNIQUE, platform varchar(24) NOT NULL CHECK(platform IN ('linux/amd64','linux/arm64')),
      status varchar(16) NOT NULL CHECK(status IN ('active','disabled','revoked')),
      revision integer NOT NULL DEFAULT 1 CHECK(revision>0), sequence bigint NOT NULL DEFAULT 0 CHECK(sequence>=0),
      owner_user_id uuid NOT NULL REFERENCES users ON DELETE RESTRICT,
      last_seen timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(issuer,subject,client_id)
    );
    CREATE TABLE deployment_plans (
      id uuid PRIMARY KEY, installation_id uuid NOT NULL REFERENCES module_installations ON DELETE RESTRICT,
      host_id uuid NOT NULL REFERENCES deployment_hosts ON DELETE RESTRICT,
      body jsonb NOT NULL CHECK(octet_length(body::text)<=524288),
      digest varchar(64) NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
      state varchar(16) NOT NULL CHECK(state IN ('pending','approved','cancelled','applied')),
      created_by uuid NOT NULL REFERENCES users ON DELETE RESTRICT,
      expires_at timestamptz NOT NULL, approved_by uuid REFERENCES users ON DELETE RESTRICT,
      approved_identity_id uuid REFERENCES identities ON DELETE RESTRICT,
      approved_until timestamptz, approval jsonb,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX ix_deployment_plans_installation_id ON deployment_plans(installation_id);
    CREATE TABLE runtime_deployments (
      installation_id uuid PRIMARY KEY REFERENCES module_installations ON DELETE RESTRICT,
      host_id uuid NOT NULL REFERENCES deployment_hosts ON DELETE RESTRICT,
      package_id uuid NOT NULL REFERENCES module_packages ON DELETE RESTRICT,
      installation_generation integer NOT NULL CHECK(installation_generation>0),
      generation integer NOT NULL CHECK(generation>0),
      desired varchar(24) NOT NULL CHECK(desired IN ('provisioned','running','stopped','absent','quarantined','retired')),
      observed_generation integer NOT NULL DEFAULT 0 CHECK(observed_generation>=0 AND observed_generation<=generation),
      observed varchar(24) NOT NULL DEFAULT 'unknown' CHECK(observed IN ('not_provisioned','stopped','starting','running','unhealthy','failed','unknown')),
      health varchar(16) NOT NULL DEFAULT 'unknown' CHECK(health IN ('healthy','unhealthy','unknown')),
      container_id varchar(64), image_digest varchar(71) NOT NULL CHECK(image_digest ~ '^sha256:[0-9a-f]{64}$'),
      observed_image_digest varchar(71), profile varchar(40) NOT NULL,
      last_seen timestamptz, last_live timestamptz, last_ready timestamptz,
      restart_count integer NOT NULL DEFAULT 0 CHECK(restart_count>=0), safe_error_code varchar(80)
    );
    CREATE INDEX ix_runtime_deployments_host_id ON runtime_deployments(host_id);
    CREATE TABLE deployment_jobs (
      id uuid PRIMARY KEY, plan_id uuid UNIQUE REFERENCES deployment_plans ON DELETE RESTRICT,
      installation_id uuid NOT NULL REFERENCES module_installations ON DELETE RESTRICT,
      host_id uuid NOT NULL REFERENCES deployment_hosts ON DELETE RESTRICT,
      generation integer NOT NULL CHECK(generation>0),
      operation varchar(24) NOT NULL CHECK(operation IN ('provision','start','stop','restart','upgrade','rollback','deprovision','inspect','reconcile','quarantine','retire')),
      body jsonb NOT NULL CHECK(octet_length(body::text)<=524288),
      state varchar(16) NOT NULL CHECK(state IN ('queued','leased','succeeded','failed','expired','cancelled')),
      attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 8),
      fence uuid, lease_until timestamptz, expires_at timestamptz NOT NULL,
      result jsonb CHECK(octet_length(result::text)<=8192),
      created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(installation_id,generation)
    );
    CREATE INDEX ix_deployment_jobs_host_id ON deployment_jobs(host_id,state,created_at);
    CREATE INDEX ix_deployment_jobs_installation_id ON deployment_jobs(installation_id);
    CREATE UNIQUE INDEX uq_deployment_active_job ON deployment_jobs(installation_id) WHERE state IN ('queued','leased');
    CREATE TABLE module_retirements (
      installation_id uuid PRIMARY KEY REFERENCES module_installations ON DELETE RESTRICT,
      state varchar(16) NOT NULL CHECK(state IN ('quarantined','retired')),
      revision integer NOT NULL CHECK(revision>0),
      performed_by uuid NOT NULL REFERENCES users ON DELETE RESTRICT,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE FUNCTION core_deployment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'deployment identity and history retained' USING ERRCODE='23514'; END IF;
      IF TG_OP='UPDATE' THEN
        IF TG_TABLE_NAME='deployment_hosts' THEN
          IF ((to_jsonb(NEW)-ARRAY['name','status','revision','sequence','last_seen']) IS DISTINCT FROM
           (to_jsonb(OLD)-ARRAY['name','status','revision','sequence','last_seen']) OR NEW.sequence<OLD.sequence
           OR (OLD.status='revoked' AND NEW.status<>'revoked')
           OR (NEW.status<>OLD.status AND NEW.revision<>OLD.revision+1)) THEN
          RAISE EXCEPTION 'deployment host identity immutable' USING ERRCODE='23514'; END IF;
        ELSIF TG_TABLE_NAME='deployment_plans' THEN
          IF ((to_jsonb(NEW)-ARRAY['state','approved_by','approved_identity_id','approved_until','approval']) IS DISTINCT FROM
           (to_jsonb(OLD)-ARRAY['state','approved_by','approved_identity_id','approved_until','approval'])
           OR OLD.state IN ('applied','cancelled')
           OR (OLD.approved_by IS NOT NULL AND (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state'))) THEN
          RAISE EXCEPTION 'deployment plan immutable' USING ERRCODE='23514'; END IF;
        ELSIF TG_TABLE_NAME='runtime_deployments' THEN
          IF (NEW.installation_id<>OLD.installation_id
          OR NEW.host_id<>OLD.host_id OR NEW.generation<OLD.generation OR NEW.generation>OLD.generation+1) THEN
          RAISE EXCEPTION 'runtime identity or generation invalid' USING ERRCODE='23514'; END IF;
        ELSIF TG_TABLE_NAME='deployment_jobs' THEN
          IF ((to_jsonb(NEW)-ARRAY['state','attempts','fence','lease_until','result']) IS DISTINCT FROM
           (to_jsonb(OLD)-ARRAY['state','attempts','fence','lease_until','result'])
           OR OLD.state IN ('succeeded','failed','expired','cancelled')) THEN
          RAISE EXCEPTION 'deployment job immutable' USING ERRCODE='23514'; END IF;
        ELSIF TG_TABLE_NAME='module_retirements' THEN
          IF (NEW.installation_id<>OLD.installation_id
          OR OLD.state='retired' OR NEW.revision<>OLD.revision+1) THEN
          RAISE EXCEPTION 'retirement terminal' USING ERRCODE='23514'; END IF;
        END IF;
      END IF;
      RETURN NEW;
    END $$;
    """)
    for table in (
        "deployment_hosts",
        "deployment_plans",
        "runtime_deployments",
        "deployment_jobs",
        "module_retirements",
    ):
        op.execute(
            f"CREATE TRIGGER core_deployment_guard BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION core_deployment_guard()"
        )
        op.execute(
            f"CREATE TRIGGER core_deployment_truncate BEFORE TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION core_deployment_guard()"
        )
    op.execute("""
    ALTER FUNCTION core_module_authorized(uuid,integer) RENAME TO core_module_authorized_4c;
    CREATE FUNCTION core_module_authorized(iid uuid, stale_seconds integer) RETURNS boolean
    LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
      SELECT NOT EXISTS(SELECT 1 FROM public.module_retirements WHERE installation_id=iid)
      AND ((public.core_module_authorized_4c(iid,stale_seconds) AND NOT EXISTS (
        SELECT 1 FROM public.module_installations mi JOIN public.module_packages mp ON mp.id=mi.package_id,
          jsonb_array_elements(mp.manifest->'artifacts') a
        WHERE mi.id=iid AND mi.module_type='standard' AND a->>'path'='payload/resources/runtime-v1.json')) OR EXISTS (
        SELECT 1 FROM public.module_installations i
        JOIN public.module_packages p ON p.id=i.package_id
        JOIN public.package_publishers pub ON pub.id=p.publisher_id
        JOIN public.publisher_signing_keys k ON k.id=p.signing_key_id
        JOIN public.publisher_namespace_grants g ON g.publisher_id=pub.id AND g.namespace=i.namespace
        JOIN public.runtime_deployments d ON d.installation_id=i.id AND d.package_id=p.id
        JOIN public.deployment_hosts h ON h.id=d.host_id
        JOIN public.deployment_jobs j ON j.installation_id=i.id AND j.generation=d.generation
        WHERE i.id=iid AND i.module_type='standard' AND i.status='installed_enabled'
          AND p.state='available' AND pub.status='active' AND k.status='active' AND g.status='active'
          AND d.desired='running' AND d.observed='running' AND d.health='healthy'
          AND d.container_id IS NOT NULL
          AND d.observed_generation=d.generation AND d.observed_image_digest=d.image_digest
          AND j.state='succeeded' AND j.body->'runtime'->>'image_digest'=d.image_digest
          AND h.status='active' AND h.last_seen>statement_timestamp()-make_interval(secs=>greatest(10,least(900,stale_seconds)))
          AND d.last_ready>statement_timestamp()-make_interval(secs=>greatest(10,least(900,stale_seconds)))
          AND d.last_seen>statement_timestamp()-make_interval(secs=>greatest(10,least(900,stale_seconds)))
      ))
    $$;
    CREATE OR REPLACE FUNCTION core_module_available(ns text, stale_seconds integer) RETURNS boolean
    LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
      SELECT ns='core' OR EXISTS(SELECT 1 FROM public.module_installations i
        JOIN public.permission_namespaces n ON n.name=i.namespace AND n.owner=i.module_id
        WHERE i.namespace=ns AND n.state='active' AND public.core_module_authorized(i.id,stale_seconds)
        AND NOT EXISTS(SELECT 1 FROM public.module_dependency_pins pin
          JOIN public.module_installations d ON d.id=pin.dependency_id
          WHERE pin.installation_id=i.id AND (d.package_id<>pin.package_id OR NOT public.core_module_authorized(d.id,stale_seconds))))
    $$;
    """)


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup under maintenance; destructive downgrade is disabled")
