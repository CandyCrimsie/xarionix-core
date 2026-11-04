-- Explicit DBA maintenance, NEVER run by Core, install.sh or ordinary Alembic upgrades.
-- psql ... -v runtime_role=core_runtime -v installer_role=core_installer -f this-file
-- Both LOGIN roles must already exist, with separately supplied credentials.
\set ON_ERROR_STOP on
BEGIN;
SELECT set_config('xarionix.bootstrap_runtime', :'runtime_role', true);
SELECT set_config('xarionix.bootstrap_installer', :'installer_role', true);
DO $$
DECLARE runtime_name text:=current_setting('xarionix.bootstrap_runtime');
  installer_name text:=current_setting('xarionix.bootstrap_installer');
BEGIN
  IF runtime_name=installer_name OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=runtime_name AND rolcanlogin
      AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
    OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=installer_name AND rolcanlogin
      AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
  THEN RAISE EXCEPTION 'distinct existing restricted runtime and installer roles required'; END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='xarionix_module_catalog') THEN
    CREATE ROLE xarionix_module_catalog NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='xarionix_module_executor') THEN
    CREATE ROLE xarionix_module_executor NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('xarionix_module_catalog','xarionix_module_executor')
      AND (rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
    OR EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid='xarionix_module_catalog'::regrole
      OR member IN ('xarionix_module_catalog'::regrole,'xarionix_module_executor'::regrole))
    OR pg_has_role(runtime_name,'xarionix_module_executor','MEMBER')
    OR pg_has_role(installer_name,'xarionix_module_catalog','MEMBER')
    OR pg_has_role(runtime_name,installer_name,'MEMBER')
    OR pg_has_role(installer_name,runtime_name,'MEMBER')
    OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=installer_name)
      AND roleid<>'xarionix_module_executor'::regrole)
  THEN RAISE EXCEPTION 'unsafe pre-existing role capability or membership'; END IF;
END $$;
-- These GUCs carry only DBA role identifiers; no runtime guard consults them.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO xarionix_module_catalog, xarionix_module_executor;
GRANT SELECT ON permissions,permission_namespaces,module_installations,module_install_plans,
  module_install_operations,module_packages,package_publishers,publisher_signing_keys,publisher_namespace_grants
  TO xarionix_module_catalog;
GRANT INSERT,UPDATE ON permissions,permission_namespaces TO xarionix_module_catalog;
ALTER FUNCTION core_apply_module_catalog(uuid,text,uuid) OWNER TO xarionix_module_catalog;
REVOKE ALL ON FUNCTION core_apply_module_catalog(uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION core_apply_module_catalog(uuid,text,uuid) FROM :"runtime_role";
GRANT EXECUTE ON FUNCTION core_apply_module_catalog(uuid,text,uuid) TO xarionix_module_executor;
GRANT SELECT ON users,identities,platform_admins,permission_namespaces,permissions,
  package_publishers,publisher_signing_keys,publisher_namespace_grants,module_packages,
  module_installations,module_dependency_pins,module_install_plans,module_install_operations,
  module_installation_history,module_instance_bindings,module_services,module_instances TO xarionix_module_executor;
GRANT SELECT ON deployment_hosts,runtime_deployments,deployment_jobs,module_retirements TO xarionix_module_executor;
GRANT INSERT,UPDATE ON module_installations,module_install_operations,module_installation_history,module_dependency_pins TO xarionix_module_executor;
GRANT DELETE ON module_dependency_pins TO xarionix_module_executor;
GRANT UPDATE ON module_install_plans,module_instance_bindings TO xarionix_module_executor;
GRANT INSERT ON audit_events TO xarionix_module_executor;
-- SQLAlchemy retrieves the server-generated timestamp, not audit payloads.
GRANT SELECT(created_at) ON audit_events TO xarionix_module_executor;
GRANT EXECUTE ON FUNCTION core_lock(text,text,boolean),core_module_available(text,integer),core_module_authorized(uuid,integer),core_module_authorized_4c(uuid,integer) TO xarionix_module_executor;
GRANT xarionix_module_executor TO :"installer_role" WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
COMMIT;
