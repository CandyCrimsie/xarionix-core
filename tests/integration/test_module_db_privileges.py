"""Maintenance rehearsal on a NEW disposable DB, not existing dev/prod volumes."""

import json
import secrets
import uuid

import httpx
import jwt
import psycopg
import pytest
import test_managed_stack as managed
from psycopg import sql

from app.core.config import Settings
from app.core.database import create_database, database_ready
from app.domains.modules.model import OPERATIONS
from app.main import create_app
from scripts.db_privileges import inspect

stack = managed.stack
pytestmark = pytest.mark.integration


async def test_split_owner_migrator_runtime_real_upgrade_and_api_mutations(stack):
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
    migrate(migrator, migration_secret, "head")
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
        assert operator.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0005_module_control",
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
    token = managed.token(stack, "integration-only")
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
    # Cleanup belongs to the enclosing disposable Compose project. No installed DB/role is touched.
