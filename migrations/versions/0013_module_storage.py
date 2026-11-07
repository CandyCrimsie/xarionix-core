"""Additive signed SDK metadata and retained module data ownership. No business rows in Core."""

from alembic import op

revision = "0013_module_storage"
down_revision = "0012_module_gateway"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    ALTER TABLE deployment_jobs DROP CONSTRAINT deployment_jobs_operation_check;
    ALTER TABLE deployment_jobs ADD CONSTRAINT deployment_jobs_operation_check
      CHECK(operation IN ('provision','start','stop','restart','upgrade','rollback','deprovision',
        'inspect','reconcile','quarantine','retire','backup','restore'));
    CREATE TABLE module_sdk_contracts (
      package_id uuid PRIMARY KEY REFERENCES module_packages ON DELETE RESTRICT,
      sha256 varchar(64) NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
      document jsonb NOT NULL CHECK(octet_length(document::text)<=65536)
    );
    CREATE TRIGGER core_sdk_contract_immutable BEFORE UPDATE OR DELETE ON module_sdk_contracts
      FOR EACH ROW EXECUTE FUNCTION core_api_contract_guard();
    CREATE TRIGGER core_sdk_contract_truncate BEFORE TRUNCATE ON module_sdk_contracts
      FOR EACH STATEMENT EXECUTE FUNCTION core_api_contract_guard();
    CREATE TABLE module_storage_allocations (
      installation_id uuid PRIMARY KEY REFERENCES module_installations ON DELETE RESTRICT,
      host_id uuid NOT NULL REFERENCES deployment_hosts ON DELETE RESTRICT,
      epoch_id uuid NOT NULL, maximum_bytes bigint NOT NULL CHECK(maximum_bytes=67108864),
      revision integer NOT NULL DEFAULT 0 CHECK(revision>=0),
      data_schema_version integer NOT NULL DEFAULT 0 CHECK(data_schema_version BETWEEN 0 AND 128),
      retained_epochs jsonb NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(retained_epochs)='array'
        AND jsonb_array_length(retained_epochs)<=128)
    );
    CREATE TABLE module_data_backups (
      id uuid PRIMARY KEY, installation_id uuid NOT NULL REFERENCES module_storage_allocations ON DELETE RESTRICT,
      epoch_id uuid NOT NULL, data_schema_version integer NOT NULL CHECK(data_schema_version BETWEEN 1 AND 128),
      allocation_revision integer NOT NULL CHECK(allocation_revision>0),
      sha256 varchar(64) NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
      size bigint NOT NULL CHECK(size>0 AND size<=67108864), package_version varchar(120) NOT NULL,
      job_id uuid NOT NULL UNIQUE REFERENCES deployment_jobs ON DELETE RESTRICT,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX ix_module_data_backups_installation_id ON module_data_backups(installation_id);
    CREATE TRIGGER core_data_backup_immutable BEFORE UPDATE OR DELETE ON module_data_backups
      FOR EACH ROW EXECUTE FUNCTION core_api_contract_guard();
    CREATE TRIGGER core_data_backup_truncate BEFORE TRUNCATE ON module_data_backups
      FOR EACH STATEMENT EXECUTE FUNCTION core_api_contract_guard();
    CREATE FUNCTION core_storage_allocation_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path=pg_catalog,public AS $$
    BEGIN
      IF TG_OP<>'UPDATE' THEN
        RAISE EXCEPTION 'module business data ownership retained' USING ERRCODE='23514';
      END IF;
      IF NEW.installation_id<>OLD.installation_id OR NEW.host_id<>OLD.host_id
        OR NEW.maximum_bytes<>OLD.maximum_bytes OR NEW.revision<>OLD.revision+1
        OR NOT NEW.retained_epochs @> OLD.retained_epochs
        OR (NEW.epoch_id<>OLD.epoch_id AND NOT NEW.retained_epochs @> jsonb_build_array(OLD.epoch_id::text)) THEN
        RAISE EXCEPTION 'module storage binding invalid' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER core_storage_allocation_guard BEFORE UPDATE OR DELETE ON module_storage_allocations
      FOR EACH ROW EXECUTE FUNCTION core_storage_allocation_guard();
    CREATE TRIGGER core_storage_allocation_truncate BEFORE TRUNCATE ON module_storage_allocations
      FOR EACH STATEMENT EXECUTE FUNCTION core_storage_allocation_guard();
    ALTER FUNCTION core_module_authorized(uuid,integer) RENAME TO core_module_authorized_6a;
    CREATE FUNCTION core_module_authorized(iid uuid, stale_seconds integer) RETURNS boolean
    LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
      SELECT CASE WHEN EXISTS (SELECT 1 FROM public.runtime_deployments
        WHERE installation_id=iid AND profile='module-api-stateful-v1') THEN
        public.core_module_authorized_4d(iid,stale_seconds) AND EXISTS (
          SELECT 1 FROM public.module_installations i
          JOIN public.module_sdk_contracts s ON s.package_id=i.package_id
          JOIN public.module_api_contracts a ON a.package_id=i.package_id
          JOIN public.runtime_deployments d ON d.installation_id=i.id AND d.package_id=i.package_id
          JOIN public.module_storage_allocations v ON v.installation_id=i.id AND v.host_id=d.host_id
          JOIN public.module_gateway_identities g ON g.host_id=d.host_id AND g.status='active'
          JOIN public.deployment_jobs j ON j.installation_id=i.id AND j.generation=d.generation
          WHERE i.id=iid AND d.installation_generation=i.generation AND j.state='succeeded'
            AND j.body->>'api_contract_sha256'=a.sha256
            AND j.body->>'gateway_protocol'='module-gateway-poll-v1'
            AND j.body->'storage'->>'sdk_sha256'=s.sha256
            AND j.body->'storage'->>'epoch_id'=v.epoch_id::text
            AND j.result->'report'->'storage'->>'epoch_id'=v.epoch_id::text
            AND (j.result->'report'->'storage'->>'data_schema_version')::integer=v.data_schema_version
            AND v.data_schema_version BETWEEN (s.document->'storage'->>'compatible_minimum')::integer
              AND (s.document->'storage'->>'compatible_maximum')::integer
        ) ELSE public.core_module_authorized_6a(iid,stale_seconds) END
    $$;
    """)


def downgrade() -> None:
    raise RuntimeError(
        "Module business data retained; use a verified maintenance backup, never destructive downgrade"
    )
