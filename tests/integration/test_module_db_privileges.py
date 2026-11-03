"""Maintenance rehearsal on a NEW disposable DB, not existing dev/prod volumes."""

import json
import secrets
import uuid

import httpx
import jwt
import psycopg
import pytest
import test_managed_stack as managed
from package_helpers import manifest_data, package
from psycopg import sql

from app.core.config import Settings
from app.core.database import create_database, database_ready
from app.domains.modules.model import OPERATIONS
from app.main import create_app
from scripts.db_privileges import inspect

stack = managed.stack
pytestmark = pytest.mark.integration


async def test_split_owner_migrator_runtime_real_upgrade_and_api_mutations(stack, tmp_path):
    suffix = uuid.uuid4().hex[:12]
    database, owner, migrator, runtime = (
        name + suffix for name in ("xarionix_privilege_", "owner_", "migrator_", "runtime_")
    )
    migration_secret, runtime_secret = secrets.token_hex(32), secrets.token_hex(32)
    bootstrap = dict(
        host="localhost",
        port=stack["postgres_port"],
        dbname="postgres",
        user="core_bootstrap",
        password=stack["config"]["DB_BOOTSTRAP_PASSWORD"],
    )
    with psycopg.connect(**bootstrap, autocommit=True) as operator:
        operator.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(owner)))
        # Secrets travel through libpq parameters, not shell argv / logs.
        operator.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(migrator), sql.Literal(migration_secret)
            )
        )
        operator.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(runtime), sql.Literal(runtime_secret)
            )
        )
        operator.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(owner), sql.Identifier(migrator)))
        operator.execute(sql.SQL("CREATE DATABASE {} OWNER core_app").format(sql.Identifier(database)))

    def migrate(user, secret, target):
        stack["execute"](
            [
                "run",
                "--rm",
                "-e",
                "XARIONIX_DB_NAME",
                "-e",
                "XARIONIX_DB_USER",
                "-e",
                "XARIONIX_DB_PASSWORD",
                "migrate",
                "alembic",
                "upgrade",
                target,
            ],
            extra_environment={
                "XARIONIX_DB_NAME": database,
                "XARIONIX_DB_USER": user,
                "XARIONIX_DB_PASSWORD": secret,
            },
        )

    migrate("core_app", stack["config"]["DB_PASSWORD"], "0004_rbac")
    uid, cid, membership = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(**(bootstrap | {"dbname": database})) as operator:
        operator.execute("UPDATE platform_settings SET company_creation_policy='open' WHERE id=1")
        operator.execute("INSERT INTO users(id) VALUES (%s)", (uid,))
        operator.execute(
            "INSERT INTO companies(id,name,slug,created_by_user_id) VALUES (%s,'Preserved company','privilege-rehearsal',%s)",
            (cid, uid),
        )
        operator.execute(
            "INSERT INTO memberships(id,company_id,user_id,role) VALUES (%s,%s,%s,'owner')",
            (membership, cid, uid),
        )
        operator.commit()  # Validate deferred Sprint 3 invariants before ownership DDL.
        tables = [
            row[0] for row in operator.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
        ]
        for table in tables:
            operator.execute(
                sql.SQL("ALTER TABLE public.{} OWNER TO {}").format(
                    sql.Identifier(table), sql.Identifier(owner)
                )
            )
        functions = operator.execute(
            "SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'core_%'"
        ).fetchall()
        for (signature,) in functions:
            # Server-generated regprocedure, not payload / CLI input.
            operator.execute(
                sql.SQL("ALTER FUNCTION {} OWNER TO {}").format(sql.SQL(signature), sql.Identifier(owner))
            )
            operator.execute(
                sql.SQL("ALTER FUNCTION {} SET search_path=pg_catalog,public,pg_temp").format(
                    sql.SQL(signature)
                )
            )
        operator.execute(sql.SQL("ALTER SCHEMA public OWNER TO {}").format(sql.Identifier(owner)))
        operator.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        operator.execute(
            sql.SQL("REVOKE CREATE,TEMP ON DATABASE {} FROM PUBLIC").format(sql.Identifier(database))
        )
        operator.execute(
            sql.SQL("ALTER DATABASE {} OWNER TO {}").format(sql.Identifier(database), sql.Identifier(owner))
        )
        operator.execute(
            sql.SQL("ALTER ROLE {} IN DATABASE {} SET role TO {}").format(
                sql.Identifier(migrator), sql.Identifier(database), sql.Literal(owner)
            )
        )
    # A genuine 0007 -> 4C rehearsal includes existing 4A/4B records, not only empty tables.
    migrate(migrator, migration_secret, "0007_instance_history")
    preserved = {
        table: uuid.uuid4()
        for table in (
            "identities",
            "employees",
            "invitations",
            "audit_events",
            "module_services",
            "module_instances",
            "package_publishers",
            "publisher_signing_keys",
            "module_packages",
        )
    }
    data = manifest_data(module="legacy-module", publisher="upgrade-pub", namespace="upgradepkg")
    _, trust, report = package(tmp_path / "pre-4c-package", data=data)
    with psycopg.connect(**(bootstrap | {"dbname": database})) as db:
        db.execute(
            "INSERT INTO identities(id,issuer,subject,user_id,principal_type) VALUES (%s,%s,'pre-4c',%s,'human')",
            (preserved["identities"], stack["issuer"], uid),
        )
        db.execute(
            "INSERT INTO employees(id,company_id,user_id,display_name) VALUES (%s,%s,%s,'Preserved 4C employee')",
            (preserved["employees"], cid, uid),
        )
        db.execute(
            "INSERT INTO invitations(id,company_id,created_by_user_id,role,token_hash,expires_at) VALUES (%s,%s,%s,'member',%s,now()+interval '1 day')",
            (preserved["invitations"], cid, uid, secrets.token_hex(32)),
        )
        db.execute(
            "INSERT INTO audit_events(id,action,resource_type,details) VALUES (%s,'pre4c.seed','migration','{}')",
            (preserved["audit_events"],),
        )
        db.execute(
            "INSERT INTO module_services(id,module_key,name,issuer,subject,client_id,operations,registered_by_user_id) VALUES (%s,'legacy-module','Preserved 4A',%s,'pre-4c-service','pre4c-agent','[]',%s)",
            (preserved["module_services"], stack["issuer"], uid),
        )
        db.execute(
            "INSERT INTO module_instances(id,service_id,installation_key) VALUES (%s,%s,'pre4c-instance')",
            (preserved["module_instances"], preserved["module_services"]),
        )
        db.execute(
            "INSERT INTO package_publishers(id,publisher_id,display_name) VALUES (%s,'upgrade-pub','Preserved publisher')",
            (preserved["package_publishers"],),
        )
        db.execute(
            "INSERT INTO publisher_signing_keys(id,publisher_id,key_id,public_key,fingerprint) VALUES (%s,%s,'test-key',%s,%s)",
            (
                preserved["publisher_signing_keys"],
                preserved["package_publishers"],
                trust.keys[0].public_key,
                report["key_fingerprint"],
            ),
        )
        db.execute(
            "INSERT INTO publisher_namespace_grants(namespace,publisher_id) VALUES ('upgradepkg',%s)",
            (preserved["package_publishers"],),
        )
        db.execute(
            "INSERT INTO module_packages(id,module_id,version,publisher_id,signing_key_id,package_sha256,manifest_sha256,size,manifest,imported_by_user_id) VALUES (%s,'legacy-module','1.0.0',%s,%s,%s,%s,%s,%s,%s)",
            (
                preserved["module_packages"],
                preserved["package_publishers"],
                preserved["publisher_signing_keys"],
                report["package_sha256"],
                report["manifest_sha256"],
                report["size"],
                json.dumps(data),
                uid,
            ),
        )
    migrate(migrator, migration_secret, "head")
    with psycopg.connect(**(bootstrap | {"dbname": database})) as db:
        for table, identifier in preserved.items():
            assert db.execute(
                sql.SQL("SELECT id FROM {} WHERE id=%s").format(sql.Identifier(table)), (identifier,)
            ).fetchone() == (identifier,)
        assert db.execute("SELECT count(*) FROM module_installations").fetchone() == (0,)
        assert db.execute("SELECT bool_and(permission_generation=1) FROM role_permissions").fetchone() == (
            True,
        )
    catalogs = {
        "permissions",
        "permission_namespaces",
        "role_templates",
        "system_role_definitions",
        "alembic_version",
    }
    with psycopg.connect(**(bootstrap | {"dbname": database})) as operator:
        operator.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(database), sql.Identifier(runtime)
            )
        )
        operator.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(runtime)))
        operator.execute(
            sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(runtime))
        )
        for (table,) in operator.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public'"
        ).fetchall():
            if table in catalogs:
                continue
            rights = "INSERT" if table == "audit_events" else "INSERT,UPDATE,DELETE"
            operator.execute(
                sql.SQL("GRANT {} ON TABLE public.{} TO {}").format(
                    sql.SQL(rights), sql.Identifier(table), sql.Identifier(runtime)
                )
            )
        operator.execute("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC")
        operator.execute(
            sql.SQL("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {}").format(sql.Identifier(runtime))
        )
        operator.execute(
            sql.SQL("REVOKE EXECUTE ON FUNCTION core_apply_module_catalog(uuid,text,uuid) FROM {}").format(
                sql.Identifier(runtime)
            )
        )
        assert operator.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0010_instance_enrollment",
        )
        assert operator.execute("SELECT id FROM memberships WHERE company_id=%s", (cid,)).fetchone() == (
            membership,
        )
    connection = dict(
        host="localhost", port=stack["postgres_port"], dbname=database, user=runtime, password=runtime_secret
    )
    for statement in (
        "ALTER TABLE users ADD COLUMN forbidden text",
        "ALTER TABLE users DISABLE TRIGGER ALL",
        "UPDATE permissions SET active=false",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
        "CREATE TEMP TABLE memberships(id uuid)",
        f'SET ROLE "{owner}"',
    ):
        with psycopg.connect(**connection) as db:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                db.execute(statement)
            db.rollback()
    config = Settings(
        environment="development",
        keycloak_mode="external",
        public_url=stack["config"]["PUBLIC_URL"],
        oidc_issuer=stack["issuer"],
        db_host="localhost",
        db_port=stack["postgres_port"],
        db_name=database,
        db_user=runtime,
        db_password=runtime_secret,
        admin_acr_values=["test-step-up"],
        packages_storage_root=tmp_path / "registry",
    )
    engine, _ = create_database(config)
    try:
        assert await database_ready(engine)
        async with engine.connect() as db:
            assert await inspect(db) == {
                "superuser": False,
                "schema_create": False,
                "owns_tables": False,
                "audit_delete": False,
                "catalog_update": False,
                "instance_update": True,
            }
    finally:
        await engine.dispose()
    app = create_app(config)
    token = managed.token(stack, "integration-admin")
    async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
        response = await client.post(
            stack["issuer"] + "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "module-a",
                "client_secret": stack["module_secrets"]["module-a"],
            },
        )
        machine_token = response.json()["access_token"]
    claims = jwt.decode(machine_token, options={"verify_signature": False})
    sid, iid = uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(**(bootstrap | {"dbname": database})) as operator:
        operator.execute(
            "INSERT INTO module_services(id,module_key,name,issuer,subject,client_id,operations,registered_by_user_id) VALUES (%s,'test-autonomous-module','Runtime machine',%s,%s,'module-a',%s,%s)",
            (sid, claims["iss"], claims["sub"], json.dumps(sorted(OPERATIONS)), uid),
        )
        operator.execute(
            "INSERT INTO module_instances(id,service_id,installation_key) VALUES (%s,%s,'runtime-instance')",
            (iid, sid),
        )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=config.public_url,
            headers={"Authorization": "Bearer " + token},
        ) as client,
    ):
        response = await client.get("/api/v1/me")
        assert response.status_code == 200
        with psycopg.connect(**(bootstrap | {"dbname": database})) as operator:
            operator.execute(
                "UPDATE identities SET principal_type='human' WHERE id=%s", (response.json()["id"],)
            )
            operator.execute(
                "INSERT INTO platform_admins(user_id,active) VALUES (%s,true)", (response.json()["user_id"],)
            )
        response = await client.post(
            "/api/v1/companies", json={"name": "Runtime company", "slug": "runtime-company"}
        )
        assert response.status_code == 201, response.json().get("detail")
        company = response.json()["id"]
        response = await client.post(
            f"/api/v1/companies/{company}/roles",
            json={"code": "runtime-engineer", "name": "Инженер", "permissions": ["core.employees.read"]},
        )
        assert response.status_code == 201, response.json().get("detail")
        assert (
            await client.post(
                f"/api/v1/companies/{company}/employees", json={"display_name": "Runtime employee"}
            )
        ).status_code == 201
        assert (await client.get("/health/ready")).status_code == 200
        response = await client.post(
            "/api/v1/module-agent/check-in",
            headers={"Authorization": "Bearer " + machine_token},
            json={
                "instance_id": str(iid),
                "protocol_version": 1,
                "health": "healthy",
                "agent_version": "0.1.0",
            },
        )
        assert response.status_code == 200, response.json().get("detail")
        archive, trust, _ = package(tmp_path / "package")
        response = await client.post(
            "/api/v1/platform/package-publishers",
            json={"publisher_id": "test-publisher", "display_name": "Restricted runtime publisher"},
        )
        assert response.status_code == 201, response.text
        publisher = response.json()["id"]
        response = await client.post(
            f"/api/v1/platform/package-publishers/{publisher}/keys",
            json={"key_id": "test-key", "public_key": trust.keys[0].public_key},
        )
        assert response.status_code == 201, response.text
        assert (
            await client.put(
                f"/api/v1/platform/package-publishers/{publisher}/namespaces",
                json={"namespaces": ["testnet"]},
            )
        ).status_code == 200
        response = await client.post(
            "/api/v1/platform/packages",
            content=archive.read_bytes(),
            headers={"Content-Type": "application/octet-stream"},
        )
        assert response.status_code == 201, response.text
        assert (
            await client.post("/api/v1/platform/packages/" + response.json()["id"] + "/verify")
        ).status_code == 200
    # Cleanup belongs to the enclosing disposable Compose project. No installed DB/role is touched.
