"""Immutable signed operation metadata and independently approved gateway principals."""

from alembic import op

revision = "0012_module_gateway"
down_revision = "0011_deployment_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE module_api_contracts (
      package_id uuid PRIMARY KEY REFERENCES module_packages ON DELETE RESTRICT,
      sha256 varchar(64) NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
      document jsonb NOT NULL CHECK(octet_length(document::text)<=65536)
    );
    CREATE FUNCTION core_api_contract_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
    BEGIN RAISE EXCEPTION 'signed API metadata immutable' USING ERRCODE='23514'; END $$;
    CREATE TRIGGER core_api_contract_guard BEFORE UPDATE OR DELETE ON module_api_contracts
      FOR EACH ROW EXECUTE FUNCTION core_api_contract_guard();
    CREATE TRIGGER core_api_contract_truncate BEFORE TRUNCATE ON module_api_contracts
      FOR EACH STATEMENT EXECUTE FUNCTION core_api_contract_guard();
    CREATE TABLE module_gateway_identities (
      host_id uuid PRIMARY KEY REFERENCES deployment_hosts ON DELETE RESTRICT,
      issuer varchar(512) NOT NULL, subject varchar(255) NOT NULL, client_id varchar(120) NOT NULL,
      status varchar(16) NOT NULL CHECK(status IN ('active','disabled','revoked')),
      revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
      approved_by uuid NOT NULL REFERENCES users ON DELETE RESTRICT,
      UNIQUE(issuer,subject,client_id)
    );
    CREATE FUNCTION core_gateway_identity_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
    BEGIN
      IF TG_OP<>'UPDATE' THEN
        RAISE EXCEPTION 'gateway identity retained' USING ERRCODE='23514'; END IF;
      IF (to_jsonb(NEW)-ARRAY['status','revision']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','revision'])
        OR NEW.revision<>OLD.revision+1 OR OLD.status='revoked' THEN
        RAISE EXCEPTION 'gateway identity immutable' USING ERRCODE='23514'; END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER core_gateway_identity_guard BEFORE UPDATE OR DELETE ON module_gateway_identities
      FOR EACH ROW EXECUTE FUNCTION core_gateway_identity_guard();
    CREATE TRIGGER core_gateway_identity_truncate BEFORE TRUNCATE ON module_gateway_identities
      FOR EACH STATEMENT EXECUTE FUNCTION core_gateway_identity_guard();
    ALTER FUNCTION core_module_authorized(uuid,integer) RENAME TO core_module_authorized_4d;
    CREATE FUNCTION core_module_authorized(iid uuid, stale_seconds integer) RETURNS boolean
    LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
      SELECT public.core_module_authorized_4d(iid,stale_seconds)
      AND (NOT EXISTS (
        SELECT 1 FROM public.module_installations i JOIN public.module_packages p ON p.id=i.package_id,
          jsonb_array_elements(p.manifest->'artifacts') a
        WHERE i.id=iid AND a->>'path'='payload/resources/module-api-v1.json'
      ) OR EXISTS (
        SELECT 1 FROM public.module_installations i
        JOIN public.module_api_contracts a ON a.package_id=i.package_id
        JOIN public.runtime_deployments d ON d.installation_id=i.id AND d.package_id=i.package_id
        JOIN public.module_gateway_identities g ON g.host_id=d.host_id AND g.status='active'
        JOIN public.deployment_jobs j ON j.installation_id=i.id AND j.generation=d.generation
        WHERE i.id=iid AND d.profile='module-api-private-v1' AND j.state='succeeded'
          AND j.body->>'api_contract_sha256'=a.sha256
          AND j.body->>'gateway_protocol'='module-gateway-poll-v1'
      ))
    $$;
    """)


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup under maintenance; destructive downgrade is disabled")
