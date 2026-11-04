"""Opt-in REAL Docker/PostgreSQL/Keycloak tests. Never touch installed project volumes.

XARIONIX_RUN_DOCKER_TESTS=1 .venv/bin/pytest tests/integration -vv
The service-account grant exists only in this disposable test realm/client.
Production clients do not enable this grant.
"""

import asyncio
import copy
import json
import os
import re
import secrets
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path

import httpx
import jwt
import psycopg
import pytest
import yaml

from app.core.config import Settings
from app.core.database import create_database
from app.domains.identity.service import resolve_identity
from app.integrations.keycloak.oidc import OIDCVerifier
from app.main import create_app
from scripts import setup
from scripts.ci import compose_failure_kind, preflight, retry_compose_build

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]


class IsolatedStack(dict):
    def __repr__(self):
        return "<isolated Docker stack; credentials redacted>"


def poll(check, *, timeout=240):
    deadline = time.monotonic() + timeout
    while True:
        try:
            return check()
        except (httpx.HTTPError, AssertionError, KeyError):
            if time.monotonic() >= deadline:
                pytest.fail("Isolated stack readiness deadline exceeded")
            time.sleep(0.25)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    if os.environ.get("XARIONIX_RUN_DOCKER_TESTS") != "1":
        if os.environ.get("CI") == "true":
            pytest.fail(
                "CI integration must set XARIONIX_RUN_DOCKER_TESTS=1; silently skipped Docker tests are forbidden"
            )
        pytest.skip("Opt-in Docker integration: XARIONIX_RUN_DOCKER_TESTS=1")
    try:
        preflight()
    except RuntimeError as error:
        pytest.fail(str(error))
    folder = tmp_path_factory.mktemp("managed-stack")
    job = os.environ.get("CI_JOB_ID", "local")
    pipeline = os.environ.get("CI_PIPELINE_ID", "local")
    if not all(value == "local" or value.isdecimal() for value in (job, pipeline)):
        pytest.fail("Invalid CI project isolation identifiers")
    project = f"xarionix-test-{pipeline}-{job}-" + uuid.uuid4().hex[:8]
    core_port, keycloak_port, postgres_port = free_port(), free_port(), free_port()
    issuer = f"http://localhost:{keycloak_port}/realms/xarionix"
    config = setup.DEFAULTS | {key: secrets.token_hex(32) for key in setup.SECRETS}
    config |= {
        "PUBLIC_URL": f"http://localhost:{core_port}",
        "KEYCLOAK_PUBLIC_URL": f"http://localhost:{keycloak_port}",
        "OIDC_ISSUER": issuer,
        "BROWSER_REDIRECT_URI": "http://localhost:4200/auth/callback",
        "BROWSER_ORIGIN": "http://localhost:4200",
    }
    client_secret = secrets.token_hex(32)
    realm = setup.realm(config, development=True)
    realm["clients"].append(
        {
            "clientId": "integration-only",
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": client_secret,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            # Do not inherit realm defaults: the built-in ACR mapper races with
            # test-acr at the same priority. Keep exactly one writer per claim.
            "defaultClientScopes": [],
            "optionalClientScopes": [],
            "protocolMappers": [
                *copy.deepcopy(realm["clients"][1]["protocolMappers"]),
                {
                    "name": "test-subject",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-sub-mapper",
                    "config": {"access.token.claim": "true"},
                },
            ],
        }
    )
    # Test-only identities and authentication context, not a production MFA flow.
    # Explicit operator admission below is the ONLY source of human permissions.
    test_client = copy.deepcopy(realm["clients"][-1])
    for label in ("alice", "bob", "carol", "admin", "machine", "dave"):
        client = copy.deepcopy(test_client)
        client["clientId"] = "integration-" + label
        client["protocolMappers"] += [
            {
                "name": "test-acr",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-hardcoded-claim-mapper",
                "config": {
                    "claim.name": "acr",
                    "claim.value": "test-step-up",
                    "jsonType.label": "String",
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                },
            },
            {
                "name": "test-auth-time",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-hardcoded-claim-mapper",
                "config": {
                    "claim.name": "auth_time",
                    "claim.value": str(int(time.time())),
                    "jsonType.label": "long",
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                },
            },
        ]
        realm["clients"].append(client)
    module_secrets = {name: secrets.token_hex(32) for name in ("module-a", "module-b", "module-unknown")}
    for name, secret in module_secrets.items():
        realm["clients"].append(
            {
                "clientId": name,
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": secret,
                "serviceAccountsEnabled": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "defaultClientScopes": [],
                "optionalClientScopes": [],
                "protocolMappers": [
                    {
                        "name": "subject",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-sub-mapper",
                        "config": {"access.token.claim": "true"},
                    },
                    {
                        "name": "machine-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": {
                            "included.custom.audience": "xarionix-core-modules",
                            "access.token.claim": "true",
                            "id.token.claim": "false",
                        },
                    },
                    {
                        "name": "machine-purpose",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-hardcoded-claim-mapper",
                        "config": {
                            "claim.name": "xarionix_principal",
                            "claim.value": "machine",
                            "jsonType.label": "String",
                            "access.token.claim": "true",
                            "id.token.claim": "false",
                        },
                    },
                ],
            }
        )
    realm_path = folder / "realm.json"
    setup.atomic_write(realm_path, json.dumps(realm), 0o644)
    definition = yaml.safe_load((ROOT / "compose.dev.yaml").read_text())
    services = definition["services"]
    for name in ("core", "migrate"):
        services[name]["image"] = "xarionix-core-test:" + project
        if name == "core":
            services[name]["build"] = str(ROOT)
        services[name]["environment"] = dict(services[name]["environment"]) | {
            "XARIONIX_PUBLIC_URL": config["PUBLIC_URL"],
            "XARIONIX_OIDC_ISSUER": issuer,
            "XARIONIX_ADMIN_ACR_VALUES": '["test-step-up"]',
            "XARIONIX_ADMIN_AUTH_MAX_AGE_SECONDS": "300",
            "XARIONIX_MODULES_CHECK_IN_SECONDS": "1",
            "XARIONIX_MODULES_LEASE_SECONDS": "5",
        }
    services["core"]["ports"] = [f"127.0.0.1:{core_port}:8000"]
    services["postgres"]["ports"] = [f"127.0.0.1:{postgres_port}:5432"]
    for name in ("postgres", "keycloak-postgres"):
        services[name]["volumes"][1]["source"] = str(ROOT / "deploy/postgres/10-app-user.sh")
    services["keycloak"]["environment"]["KC_HOSTNAME"] = config["KEYCLOAK_PUBLIC_URL"]
    services["keycloak"]["ports"] = [f"127.0.0.1:{keycloak_port}:8080"]
    services["keycloak"]["volumes"][0]["source"] = str(realm_path)
    for service in services.values():
        service["labels"] = {"io.xarionix.test.job-id": job}
    for volume in definition["volumes"]:
        definition["volumes"][volume] = {"labels": {"io.xarionix.test.job-id": job}}
    definition["networks"] = {
        name: {"labels": {"io.xarionix.test.job-id": job}} for name in ("default", "agent")
    }
    services["core"]["networks"] = ["default", "agent"]
    services["keycloak"]["networks"] = ["default", "agent"]
    compose_path, env_path = folder / "compose.yaml", folder / ".env"
    setup.atomic_write(compose_path, yaml.safe_dump(definition))
    setup.atomic_write(env_path, setup.env_text(config))
    command = ["docker", "compose", "-p", project, "--env-file", str(env_path), "-f", str(compose_path)]
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith(("XARIONIX_", "COMPOSE_"))
    }

    def record_failure(arguments, kind, returncode, attempt, retry):
        # Static categories and Docker status fields only. Never persist raw stderr,
        # expanded Compose config, argv values, tokens or disposable credentials.
        phase = (
            arguments[0]
            if arguments and arguments[0] in {"config", "build", "up", "run", "exec", "restart", "ps"}
            else "other"
        )
        safe = []
        migration_error = None
        try:
            status = subprocess.run(
                command + ["ps", "--all", "--format", "json"],
                env=environment,
                capture_output=True,
                timeout=20,
            )
            value = status.stdout.decode()
            items = (
                json.loads(value)
                if value.startswith("[")
                else [json.loads(line) for line in value.splitlines()]
            )
            safe = [
                {key: item.get(key) for key in ("Service", "State", "Health", "ExitCode")} for item in items
            ]
            if any(item.get("Service") == "migrate" and item.get("ExitCode") for item in safe):
                migration_logs = subprocess.run(
                    command + ["logs", "--no-color", "--tail", "200", "migrate"],
                    env=environment,
                    capture_output=True,
                    timeout=20,
                )
                match = re.search(
                    rb"psycopg\.(?:errors\.)?([A-Z][A-Za-z]{1,63})",
                    migration_logs.stdout + migration_logs.stderr,
                )
                migration_error = match.group(1).decode() if match else "unclassified"
        except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, AttributeError):
            pass
        reports = ROOT / "reports"
        reports.mkdir(exist_ok=True)
        path = reports / "integration-diagnostics.json"
        try:
            history = json.loads(path.read_text()) if path.exists() else []
            history = [item for item in history if isinstance(item, dict) and "phase" in item]
        except (ValueError, TypeError):
            history = []
        history.append(
            {
                "project": project,
                "phase": phase,
                "kind": kind,
                "returncode": returncode,
                "attempt": attempt,
                "retry_planned": retry,
                "services": safe,
                "migration_error_class": migration_error,
            }
        )
        path.write_text(json.dumps(history[-20:]))
        print(
            f"Isolated stack phase={phase} kind={kind} exit={returncode} attempt={attempt} retry={retry} migration_error_class={migration_error}",
            flush=True,
        )

    def execute(arguments, timeout=600, extra_environment=None):
        if extra_environment and set(extra_environment) - {
            "XARIONIX_DB_USER",
            "XARIONIX_DB_NAME",
            "XARIONIX_DB_PASSWORD",
        }:
            pytest.fail("Only disposable database override variables are allowed")
        for attempt in (1, 2):
            try:
                result = subprocess.run(
                    command + arguments,
                    env=environment | (extra_environment or {}),
                    capture_output=True,
                    timeout=timeout,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                kind = (
                    "command_timeout"
                    if isinstance(error, subprocess.TimeoutExpired)
                    else "docker_unavailable"
                )
                record_failure(arguments, kind, None, attempt, False)
                pytest.fail(
                    f"Isolated stack command failed ({kind}); see reports/integration-diagnostics.json"
                )
            if result.returncode == 0:
                return result.stdout
            kind = compose_failure_kind(result.stdout + result.stderr)
            retry = retry_compose_build(arguments, kind, attempt)
            record_failure(arguments, kind, result.returncode, attempt, retry)
            if not retry:
                pytest.fail(
                    f"Isolated stack {arguments[0]} failed ({kind}, exit {result.returncode}); see reports/integration-diagnostics.json"
                )
            time.sleep(2)

    try:
        execute(["config", "-q"])
        execute(["build", "core"], timeout=1200)
        execute(["up", "-d", "postgres", "--wait", "--wait-timeout", "120"])
        execute(["run", "--rm", "migrate", "alembic", "upgrade", "0001_identity"])
        legacy_id = uuid.uuid4()
        with psycopg.connect(
            host="localhost",
            port=postgres_port,
            dbname="xarionix_core",
            user="core_app",
            password=config["DB_PASSWORD"],
        ) as connection:
            connection.execute(
                "INSERT INTO identities (id, issuer, subject) VALUES (%s,%s,%s)",
                (legacy_id, issuer, "legacy-before-sprint-2"),
            )
        execute(["run", "--rm", "migrate", "alembic", "upgrade", "0002_platform"])
        snapshot = {
            key: uuid.uuid4()
            for key in (
                "owner",
                "admin",
                "member",
                "company",
                "owner_member",
                "admin_member",
                "member_member",
                "employee",
                "invitation",
                "audit",
            )
        }
        with psycopg.connect(
            host="localhost",
            port=postgres_port,
            dbname="xarionix_core",
            user="core_app",
            password=config["DB_PASSWORD"],
        ) as db:
            for role in ("owner", "admin", "member"):
                db.execute(
                    "INSERT INTO users(id,display_name) VALUES (%s,%s)", (snapshot[role], "Sprint 2 " + role)
                )
                db.execute(
                    "INSERT INTO identities(id,issuer,subject,user_id,principal_type) VALUES (%s,%s,%s,%s,'human')",
                    (uuid.uuid4(), issuer, "migration-" + role, snapshot[role]),
                )
            db.execute(
                "INSERT INTO companies(id,name,slug,created_by_user_id) VALUES (%s,'Preserved company','migration-existing',%s)",
                (snapshot["company"], snapshot["owner"]),
            )
            for role in ("owner", "admin", "member"):
                db.execute(
                    "INSERT INTO memberships(id,company_id,user_id,role) VALUES (%s,%s,%s,%s)",
                    (snapshot[role + "_member"], snapshot["company"], snapshot[role], role),
                )
            db.execute(
                "INSERT INTO employees(id,company_id,user_id,display_name) VALUES (%s,%s,%s,'Preserved employee')",
                (snapshot["employee"], snapshot["company"], snapshot["member"]),
            )
            db.execute(
                "INSERT INTO invitations(id,company_id,created_by_user_id,role,token_hash,expires_at) VALUES (%s,%s,%s,'member',%s,now()+interval '1 day')",
                (snapshot["invitation"], snapshot["company"], snapshot["owner"], secrets.token_hex(32)),
            )
            db.execute(
                "INSERT INTO audit_events(id,action,resource_type,resource_id,company_id,details) VALUES (%s,'migration.seed','company',%s,%s,'{}')",
                (snapshot["audit"], snapshot["company"], snapshot["company"]),
            )
        if os.environ.get("XARIONIX_RUN_LOCK_BENCHMARKS") == "1":
            from scripts.locking_benchmark import run

            def benchmark_connection():
                return psycopg.connect(
                    host="localhost",
                    port=postgres_port,
                    dbname="xarionix_core",
                    user="core_app",
                    password=config["DB_PASSWORD"],
                )

            for revision in ("0002_platform", "0003_locking"):
                execute(["run", "--rm", "migrate", "alembic", "upgrade", revision])
                run(benchmark_connection, revision, ROOT / "reports" / f"benchmark-{revision}.json")
        execute(["up", "-d", "--build", "--wait", "--wait-timeout", "420"], timeout=1500)
        yield IsolatedStack(
            {
                "config": config,
                "issuer": issuer,
                "client_secret": client_secret,
                "postgres_port": postgres_port,
                "execute": execute,
                "legacy_id": legacy_id,
                "upgrade_snapshot": snapshot,
                "authentication_lock": threading.RLock(),
                "authentication_clients": {},
                "module_secrets": module_secrets,
                "agent_network": project + "_agent",
                "image": "xarionix-core-test:" + project,
            }
        )
    finally:
        # Destructive cleanup is limited to the generated random test project and its own volumes.
        cleanup = subprocess.run(
            command + ["down", "--volumes", "--remove-orphans"],
            env=environment,
            capture_output=True,
            timeout=120,
        )
        if cleanup.returncode:
            pytest.fail("Failed to clean isolated test project; no unrelated resources were removed")


def token(stack, client_id="integration-only", *, authentication_time=None):
    with stack["authentication_lock"], httpx.Client(timeout=10, trust_env=False) as client:
        if client_id != "integration-only":
            refresh_test_authentication(stack, client, client_id, authentication_time)
        response = client.post(
            stack["issuer"] + "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": stack["client_secret"],
            },
        )
        assert response.status_code == 200
        return response.json()["access_token"]


def refresh_test_authentication(stack, client, client_id, authentication_time):
    """Disposable realm only. Synthetic context tests enforcement, NOT human MFA."""
    with stack["authentication_lock"]:
        base = stack["config"]["KEYCLOAK_PUBLIC_URL"]
        if time.time() >= stack.get("admin_token_expires", 0):
            response = client.post(
                base + "/realms/master/protocol/openid-connect/token",
                data={
                    "client_id": "admin-cli",
                    "grant_type": "password",
                    "username": "bootstrap-admin",
                    "password": stack["config"]["KC_ADMIN_PASSWORD"],
                },
            )
            assert response.status_code == 200, "Disposable Keycloak administration unavailable"
            stack["admin_token"] = response.json()["access_token"]
            stack["admin_token_expires"] = time.time() + response.json()["expires_in"] - 30
        headers = {"Authorization": "Bearer " + stack["admin_token"]}
        url = base + "/admin/realms/xarionix/clients"
        if client_id not in stack["authentication_clients"]:
            response = client.get(url, params={"clientId": client_id}, headers=headers)
            assert response.status_code == 200 and len(response.json()) == 1
            value = response.json()[0]
            mapper = next(item for item in value["protocolMappers"] if item["name"] == "test-auth-time")
            stack["authentication_clients"][client_id] = (value["id"], mapper)
        identifier, mapper = stack["authentication_clients"][client_id]
        mapper = copy.deepcopy(mapper)
        mapper["config"]["claim.value"] = str(
            int(time.time()) if authentication_time is None else authentication_time
        )
        response = client.put(
            url + f"/{identifier}/protocol-mappers/models/{mapper['id']}", headers=headers, json=mapper
        )
        assert response.status_code == 204, "Cannot refresh disposable authentication context"


def test_real_managed_keycloak_token_me_and_postgres_identity(stack):
    access_token = token(stack)
    with httpx.Client(base_url=stack["config"]["PUBLIC_URL"], timeout=15, trust_env=False) as client:
        assert client.get("/health/ready").json() == {"status": "ready"}
        assert client.get("/api/v1/me").status_code == 401
        first = client.get("/api/v1/me", headers={"Authorization": "Bearer " + access_token})
        assert first.status_code == 200
        second = client.get("/api/v1/me", headers={"Authorization": "Bearer " + access_token})
        assert second.json()["id"] == first.json()["id"]
        identifier = uuid.UUID(first.json()["id"])
    with psycopg.connect(
        host="localhost",
        port=stack["postgres_port"],
        dbname="xarionix_core",
        user="core_app",
        password=stack["config"]["DB_PASSWORD"],
    ) as connection:
        row = connection.execute(
            "SELECT id, issuer, subject FROM identities WHERE id = %s", (identifier,)
        ).fetchone()
        assert row is not None and row[1] == stack["issuer"]
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0011_deployment_runtime",
        )
        assert connection.execute(
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
        ).fetchone() == (False,)
        assert connection.execute(
            "SELECT count(*) FROM identities WHERE issuer = %s AND subject = %s", (row[1], row[2])
        ).fetchone() == (1,)


def test_restarting_managed_keycloak_does_not_overwrite_realm(stack):
    with httpx.Client(base_url=stack["config"]["PUBLIC_URL"], timeout=15, trust_env=False) as client:

        def identity():
            response = client.get("/api/v1/me", headers={"Authorization": "Bearer " + token(stack)})
            assert response.status_code == 200
            return response.json()["id"]

        original = identity()
        stack["execute"](["up", "-d", "--no-build", "--wait", "--wait-timeout", "240"])
        assert poll(identity) == original
        stack["execute"](["restart", "postgres", "keycloak-postgres", "keycloak", "core"])
        assert poll(identity) == original
        assert poll(lambda: ready(client)) == 200


def ready(client):
    status = client.get("/health/ready").status_code
    assert status == 200
    return status


def test_discovery_jwks_and_engine_mount_options(stack):
    with httpx.Client(timeout=15, trust_env=False) as client:
        discovery = client.get(stack["issuer"] + "/.well-known/openid-configuration").json()
        assert discovery["issuer"] == stack["issuer"]
        keys = client.get(discovery["jwks_uri"]).json()["keys"]
        assert any(
            key.get("alg") == "RS256" and jwt.PyJWK.from_dict(key).key.key_size >= 2048 for key in keys
        )
    identifier = stack["execute"](["ps", "-q", "core"]).decode().strip()
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .HostConfig.Tmpfs}}", identifier],
        check=True,
        capture_output=True,
    )
    mounts = json.loads(result.stdout)
    assert set(mounts) == {"/tmp"}
    assert {"noexec", "nosuid", "nodev", "size=64m"} <= set(mounts["/tmp"].split(","))
    live_mounts = stack["execute"](
        [
            "exec",
            "-T",
            "core",
            "python",
            "-c",
            "print(next(l for l in open('/proc/mounts') if l.split()[1]=='/tmp'))",
        ]
    ).decode()
    assert "noexec" in live_mounts and "nosuid" in live_mounts and "size=65536k" in live_mounts


async def test_isolated_realm_authentication_context_is_consistent_for_every_principal(stack):
    config = Settings(
        environment="development",
        keycloak_mode="external",
        public_url=stack["config"]["PUBLIC_URL"],
        oidc_issuer=stack["issuer"],
        db_password=stack["config"]["DB_PASSWORD"],
    )
    subjects = set()
    async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
        verifier = OIDCVerifier(config, client)
        for label in ("alice", "bob", "carol", "admin", "machine", "dave"):
            # Verify the real signature, issuer, audience and expiry, not just
            # decode an unverified JWT or inspect the realm import JSON.
            claims = await verifier.verify(token(stack, "integration-" + label))
            assert claims.get("acr") == "test-step-up", f"Unexpected test ACR for {label}"
            assert type(claims.get("auth_time")) is int
            assert 0 <= time.time() - claims["auth_time"] <= 10
            assert claims["sub"] not in subjects
            subjects.add(claims["sub"])


async def test_external_mode_with_real_provider_and_concurrent_identity_provisioning(stack):
    config = Settings(
        environment="development",
        keycloak_mode="external",
        public_url=stack["config"]["PUBLIC_URL"],
        oidc_issuer=stack["issuer"],
        db_host="localhost",
        db_port=stack["postgres_port"],
        db_password=stack["config"]["DB_PASSWORD"],
    )
    # External resource server only: no bootstrap secret / Admin API client is supplied.
    app = create_app(config)
    access_token = token(stack)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=config.public_url) as client,
    ):
        response = await client.get("/api/v1/me", headers={"Authorization": "Bearer " + access_token})
        assert response.status_code == 200
        assert (await client.get("/health/ready")).status_code == 200
    engine, sessions = create_database(config)
    subject = "parallel-first-login-" + uuid.uuid4().hex

    async def resolve(issuer):
        async with sessions() as session:
            return await resolve_identity(session, issuer, subject)

    try:
        identifiers = await asyncio.gather(*(resolve(config.oidc_issuer) for _ in range(20)))
        assert len(set(identifiers)) == 1
        other = await resolve("https://other-issuer.example.test/realm")
        assert other != identifiers[0]
        with psycopg.connect(
            host="localhost",
            port=stack["postgres_port"],
            dbname="xarionix_core",
            user="core_app",
            password=stack["config"]["DB_PASSWORD"],
        ) as db:
            assert db.execute(
                "SELECT count(*) FROM users u WHERE NOT EXISTS (SELECT 1 FROM identities i WHERE i.user_id=u.id)"
            ).fetchone() == (0,)
    finally:
        await engine.dispose()


@pytest.fixture(scope="module")
def actors(stack):
    identities = {}
    for label in ("alice", "bob", "carol", "admin", "machine", "dave"):
        with httpx.Client(base_url=stack["config"]["PUBLIC_URL"], timeout=20, trust_env=False) as client:
            response = client.get(
                "/api/v1/me", headers={"Authorization": "Bearer " + token(stack, "integration-" + label)}
            )
            assert response.status_code == 200
            identities[label] = response.json()
        stack["execute"](
            [
                "exec",
                "-T",
                "core",
                "python",
                "-m",
                "scripts.platform_admin",
                "classify",
                "--identity-id",
                identities[label]["id"],
                "--principal-type",
                "service" if label == "machine" else "human",
            ]
        )
    bootstrap = [
        "exec",
        "-T",
        "core",
        "python",
        "-m",
        "scripts.platform_admin",
        "bootstrap",
        "--identity-id",
        identities["admin"]["id"],
    ]
    stack["execute"](bootstrap)
    stack["execute"](bootstrap)  # explicit, idempotent, not first-JWT bootstrap

    def request(label, method, path, **kwargs):
        headers = kwargs.pop("headers", {}) | {
            "Authorization": "Bearer " + token(stack, "integration-" + label)
        }
        with httpx.Client(base_url=stack["config"]["PUBLIC_URL"], timeout=30, trust_env=False) as client:
            return client.request(
                method,
                "/api/v1" + path,
                headers=headers,
                **kwargs,
            )

    return IsolatedStack({"identities": identities, "request": request})


def sql_connection(stack):
    return psycopg.connect(
        host="localhost",
        port=stack["postgres_port"],
        dbname="xarionix_core",
        user="core_app",
        password=stack["config"]["DB_PASSWORD"],
    )


@pytest.fixture
def restore_platform_admin_state(actors, stack):
    # This test intentionally revokes its own bootstrap administrator. Restore
    # the disposable DB even when an assertion fails, so later tests can report
    # their own failures rather than a cascading platform_admin_required error.
    with sql_connection(stack) as db:
        initial = [row[0] for row in db.execute("SELECT user_id FROM platform_admins WHERE active")]
    assert initial
    try:
        yield
    finally:
        with sql_connection(stack) as db:
            db.execute("SELECT id FROM platform_settings WHERE id=1 FOR UPDATE")
            db.execute("UPDATE platform_admins SET active=true WHERE user_id=ANY(%s)", (initial,))
            db.execute(
                "UPDATE platform_admins SET active=false WHERE user_id<>ALL(%s) AND active", (initial,)
            )


def test_sprint2_preserves_legacy_identity_and_safe_defaults(stack):
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT id, user_id, principal_type FROM identities WHERE id=%s", (stack["legacy_id"],)
        ).fetchone() == (stack["legacy_id"], stack["legacy_id"], "unclassified")
        assert db.execute("SELECT id FROM users WHERE id=%s", (stack["legacy_id"],)).fetchone() == (
            stack["legacy_id"],
        )
        assert db.execute("SELECT company_creation_policy FROM platform_settings").fetchone() == ("approval",)
        assert db.execute("SELECT count(*) FROM platform_admins").fetchone() == (0,)


def test_sprint2_profiles_machine_denial_and_no_global_role_injection(actors):
    call = actors["request"]
    value = call("alice", "PATCH", "/me", json={"display_name": "Engineer Alice"})
    assert value.status_code == 200 and value.json()["display_name"] == "Engineer Alice"
    assert call("alice", "GET", "/me").json()["display_name"] == "Engineer Alice"
    assert call("alice", "PATCH", "/me", json={"status": "suspended"}).status_code == 422
    assert call("alice", "PATCH", "/me", json={"id": str(uuid.uuid4())}).status_code == 422
    assert (
        call(
            "machine", "POST", "/companies", json={"name": "Forbidden", "slug": "forbidden-machine"}
        ).status_code
        == 403
    )
    assert call("machine", "PATCH", "/me", json={"display_name": "Pretend human"}).status_code == 403
    assert call("alice", "GET", "/platform/settings").status_code == 403
    assert (
        call("alice", "PATCH", "/platform/settings", json={"company_creation_policy": "open"}).status_code
        == 403
    )


def test_sprint2_company_policies_requests_and_atomic_approval(actors, stack):
    call = actors["request"]
    assert (
        call("admin", "PATCH", "/platform/settings", json={"company_creation_policy": "closed"}).status_code
        == 200
    )
    assert (
        call("alice", "POST", "/companies", json={"name": "Closed", "slug": "closed-isp"}).status_code == 403
    )
    assert (
        call(
            "alice", "POST", "/company-requests", json={"name": "Closed", "slug": "closed-request"}
        ).status_code
        == 403
    )
    assert (
        call("admin", "PATCH", "/platform/settings", json={"company_creation_policy": "approval"}).status_code
        == 200
    )
    result = call("alice", "POST", "/company-requests", json={"name": "Approved ISP", "slug": "approved-isp"})
    assert result.status_code == 201
    request_id = result.json()["id"]
    own = call("alice", "GET", "/company-requests/me").json()
    assert request_id in {item["id"] for item in own["items"]}
    assert call("admin", "GET", "/platform/company-requests").status_code == 200
    assert (
        call("alice", "POST", "/companies", json={"name": "No bypass", "slug": "approval-bypass"}).status_code
        == 403
    )
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(2) as pool:
        results = list(
            pool.map(
                lambda _: call("admin", "POST", f"/platform/company-requests/{request_id}/approve", json={}),
                range(2),
            )
        )
    assert sorted(item.status_code for item in results) == [200, 409]
    company_id = next(item.json()["company_id"] for item in results if item.status_code == 200)
    assert call("alice", "GET", f"/companies/{company_id}").status_code == 200
    # Global administration does not imply company membership.
    assert call("admin", "GET", f"/companies/{company_id}/employees").status_code == 404
    with sql_connection(stack) as db:
        assert db.execute("SELECT count(*) FROM companies WHERE slug='approved-isp'").fetchone() == (1,)
        assert db.execute(
            "SELECT role, status FROM memberships WHERE company_id=%s AND user_id=%s",
            (company_id, actors["identities"]["alice"]["user_id"]),
        ).fetchone() == ("owner", "active")
    for operation in ("reject", "cancel"):
        value = call(
            "bob", "POST", "/company-requests", json={"name": operation, "slug": f"request-{operation}"}
        )
        assert value.status_code == 201
        rid = value.json()["id"]
        assert call("alice", "POST", f"/company-requests/{rid}/cancel").status_code == 404
        path = (
            f"/platform/company-requests/{rid}/reject"
            if operation == "reject"
            else f"/company-requests/{rid}/cancel"
        )
        assert call("admin" if operation == "reject" else "bob", "POST", path, json={}).status_code == 200


def test_sprint2_concurrent_company_limit_and_unique_slug(actors, stack):
    from concurrent.futures import ThreadPoolExecutor

    call = actors["request"]
    assert (
        call(
            "admin",
            "PATCH",
            "/platform/settings",
            json={"company_creation_policy": "open", "max_owned_companies_per_user": 1},
        ).status_code
        == 200
    )
    with ThreadPoolExecutor(2) as pool:
        values = list(
            pool.map(
                lambda number: call(
                    "dave", "POST", "/companies", json={"name": "Concurrent", "slug": f"concurrent-{number}"}
                ),
                range(2),
            )
        )
    assert sorted(item.status_code for item in values) == [201, 409]
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM memberships WHERE user_id=%s AND role='owner'",
            (actors["identities"]["dave"]["user_id"],),
        ).fetchone() == (1,)
    assert (
        call("admin", "PATCH", "/platform/settings", json={"max_owned_companies_per_user": 10}).status_code
        == 200
    )
    value = call("bob", "POST", "/companies", json={"name": "Slug", "slug": "unique-isp"})
    assert value.status_code == 201
    assert call("carol", "POST", "/companies", json={"name": "Slug", "slug": "unique-isp"}).status_code == 409
    assert call("carol", "GET", "/companies?limit=101").status_code == 422


def test_sprint2_platform_user_suspend_restore_and_last_admin_protection(actors):
    call = actors["request"]
    machine = actors["identities"]["machine"]["user_id"]
    admin = actors["identities"]["admin"]["user_id"]
    assert (
        call("alice", "PATCH", f"/platform/users/{machine}", json={"status": "suspended"}).status_code == 403
    )
    assert (
        call("admin", "PATCH", f"/platform/users/{machine}", json={"status": "suspended"}).status_code == 200
    )
    assert call("machine", "GET", "/me").status_code == 403
    assert call("admin", "PATCH", f"/platform/users/{machine}", json={"status": "active"}).status_code == 200
    assert call("machine", "GET", "/me").status_code == 200
    assert call("admin", "PATCH", f"/platform/users/{admin}", json={"status": "suspended"}).status_code == 409
    assert call("admin", "GET", "/platform/users").status_code == 200


@pytest.fixture
def tenants(actors):
    call = actors["request"]
    response = call(
        "admin",
        "PATCH",
        "/platform/settings",
        json={"company_creation_policy": "open", "max_owned_companies_per_user": 100},
    )
    assert response.status_code == 200, response.json().get("detail")
    company_ids = {}
    for label in ("alice", "bob"):
        value = call(
            label,
            "POST",
            "/companies",
            json={"name": label + " ISP", "slug": label + "-tenant-" + uuid.uuid4().hex[:8]},
        )
        assert value.status_code == 201
        company_ids[label] = value.json()["id"]
    return company_ids


def test_sprint2_tenant_isolation_employees_and_explicit_links(actors, tenants):
    call = actors["request"]
    a, b = tenants["alice"], tenants["bob"]
    own = call("alice", "GET", "/me/companies").json()
    assert a in {item["id"] for item in own["items"]} and b not in {item["id"] for item in own["items"]}
    renamed = call("bob", "PATCH", f"/companies/{b}", json={"name": "Renamed company"})
    assert renamed.status_code == 200 and renamed.json()["id"] == b
    employee = call("bob", "POST", f"/companies/{b}/employees", json={"display_name": "No system account"})
    assert employee.status_code == 201 and employee.json()["user_id"] is None
    eid = employee.json()["id"]
    for path in (f"/companies/{b}/employees", f"/companies/{b}/members", f"/companies/{b}/invitations"):
        assert call("alice", "GET", path).status_code == 404
        assert call("admin", "GET", path).status_code == 404
    assert call("alice", "GET", f"/companies/{a}/employees/{eid}").status_code == 404
    assert (
        call(
            "alice", "PATCH", f"/companies/{a}/employees/{eid}", json={"display_name": "Wrong tenant"}
        ).status_code
        == 404
    )
    assert (
        call(
            "bob",
            "PATCH",
            f"/companies/{b}/employees/{eid}",
            json={"user_id": actors["identities"]["alice"]["user_id"]},
        ).status_code
        == 409
    )
    assert (
        call(
            "bob",
            "PATCH",
            f"/companies/{b}/employees/{eid}",
            json={"user_id": actors["identities"]["bob"]["user_id"], "position": "Engineer"},
        ).status_code
        == 200
    )
    assert call("bob", "GET", f"/companies/{b}/employees/{eid}").json()["position"] == "Engineer"
    # Company status affects domain access, but an explicit owner can restore it.
    assert call("bob", "PATCH", f"/companies/{b}", json={"status": "suspended"}).status_code == 200
    assert call("bob", "GET", f"/companies/{b}/employees").status_code == 403
    assert call("bob", "PATCH", f"/companies/{b}", json={"status": "active"}).status_code == 200
    assert call("bob", "PATCH", f"/companies/{b}", json={"status": "archived"}).status_code == 200
    assert call("bob", "PATCH", f"/companies/{b}", json={"status": "active"}).status_code == 200


def invite(actors, company_id, sender="alice", recipient="carol", **fields):
    value = actors["request"](
        sender,
        "POST",
        f"/companies/{company_id}/invitations",
        json={"recipient_user_id": actors["identities"][recipient]["user_id"], **fields},
    )
    assert value.status_code == 201
    return value.json()


def test_sprint2_invitations_concurrency_one_time_hash_and_membership_roles(actors, tenants, stack):
    from concurrent.futures import ThreadPoolExecutor

    call = actors["request"]
    company = tenants["alice"]
    issued = invite(actors, company)
    secret, iid = issued["secret"], issued["invitation"]["id"]
    with sql_connection(stack) as db:
        stored = db.execute("SELECT token_hash FROM invitations WHERE id=%s", (iid,)).fetchone()[0]
        assert stored != secret and len(stored) == 64
        events = db.execute("SELECT details FROM audit_events WHERE resource_id=%s", (iid,)).fetchall()
        assert all(secret not in str(event) and stored not in str(event) for event in events)
    listing = call("alice", "GET", f"/companies/{company}/invitations")
    assert secret not in listing.text and stored not in listing.text
    assert (
        call("bob", "POST", "/invitations/accept", json={"company_id": company, "secret": secret}).status_code
        == 403
    )
    assert (
        call(
            "carol", "POST", "/invitations/accept", json={"company_id": tenants["bob"], "secret": secret}
        ).status_code
        == 404
    )
    with ThreadPoolExecutor(2) as pool:
        values = list(
            pool.map(
                lambda _: call(
                    "carol", "POST", "/invitations/accept", json={"company_id": company, "secret": secret}
                ),
                range(2),
            )
        )
    assert sorted(value.status_code for value in values) == [200, 409]
    membership = next(value.json() for value in values if value.status_code == 200)
    mid = membership["id"]
    assert call("carol", "GET", f"/companies/{company}/employees").status_code == 200
    assert (
        call("carol", "POST", f"/companies/{company}/employees", json={"display_name": "Denied"}).status_code
        == 403
    )
    assert (
        call("alice", "PATCH", f"/companies/{company}/members/{mid}", json={"role": "admin"}).status_code
        == 200
    )
    assert (
        call("carol", "POST", f"/companies/{company}/invitations", json={"role": "admin"}).status_code == 403
    )
    assert (
        call("carol", "POST", f"/companies/{company}/employees", json={"display_name": "Allowed"}).status_code
        == 201
    )
    assert (
        call(
            "alice", "PATCH", f"/companies/{company}/members/{mid}", json={"status": "suspended"}
        ).status_code
        == 200
    )
    assert call("carol", "GET", f"/companies/{company}/employees").status_code == 404
    assert (
        call("alice", "PATCH", f"/companies/{company}/members/{mid}", json={"status": "active"}).status_code
        == 200
    )
    assert call("carol", "POST", f"/companies/{company}/leave").status_code == 200
    assert call("carol", "GET", f"/companies/{company}/employees").status_code == 404


def test_sprint2_invitation_expiration_revocation_email_and_escalation(actors, tenants, stack):
    call, company = actors["request"], tenants["alice"]
    revoked = invite(actors, company)
    iid = revoked["invitation"]["id"]
    assert call("alice", "DELETE", f"/companies/{company}/invitations/{iid}").status_code == 200
    assert (
        call(
            "carol", "POST", "/invitations/accept", json={"company_id": company, "secret": revoked["secret"]}
        ).status_code
        == 409
    )
    expired = invite(actors, company)
    with sql_connection(stack) as db:
        db.execute(
            "UPDATE invitations SET created_at=now()-interval '3 hours', expires_at=now()-interval '1 hour' WHERE id=%s",
            (expired["invitation"]["id"],),
        )
    assert (
        call(
            "carol", "POST", "/invitations/accept", json={"company_id": company, "secret": expired["secret"]}
        ).status_code
        == 409
    )
    email = invite(actors, company, recipient_email="verified@example.test")
    assert (
        call(
            "carol", "POST", "/invitations/accept", json={"company_id": company, "secret": email["secret"]}
        ).status_code
        == 403
    )
    assert (
        call("alice", "POST", f"/companies/{company}/invitations", json={"role": "owner"}).status_code == 422
    )
    assert (
        call("admin", "PATCH", "/platform/settings", json={"invitations_enabled": False}).status_code == 200
    )
    assert call("alice", "POST", f"/companies/{company}/invitations", json={}).status_code == 403
    assert call("admin", "PATCH", "/platform/settings", json={"invitations_enabled": True}).status_code == 200


def test_sprint2_last_owner_concurrent_demotion_and_transfer(actors, tenants, stack):
    from concurrent.futures import ThreadPoolExecutor

    call, company = actors["request"], tenants["alice"]
    issued = invite(actors, company)
    added = call(
        "carol", "POST", "/invitations/accept", json={"company_id": company, "secret": issued["secret"]}
    )
    assert added.status_code == 200
    target = added.json()["id"]
    members = call("alice", "GET", f"/companies/{company}/members").json()["items"]
    owner = next(item for item in members if item["user_id"] == actors["identities"]["alice"]["user_id"])
    assert call("alice", "DELETE", f"/companies/{company}/members/{owner['id']}").status_code == 409
    assert (
        call("alice", "PATCH", f"/companies/{company}/members/{target}", json={"role": "owner"}).status_code
        == 200
    )
    with ThreadPoolExecutor(2) as pool:
        values = list(
            pool.map(
                lambda pair: call(
                    pair[0], "PATCH", f"/companies/{company}/members/{pair[1]}", json={"role": "member"}
                ),
                [("alice", owner["id"]), ("carol", target)],
            )
        )
    assert sorted(value.status_code for value in values) == [200, 409]
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM memberships WHERE company_id=%s AND role='owner' AND status='active'",
            (company,),
        ).fetchone() == (1,)
    # A separate company tests explicit transfer without depending on race winner.
    other = tenants["bob"]
    item = invite(actors, other, sender="bob", recipient="alice")
    result = call(
        "alice", "POST", "/invitations/accept", json={"company_id": other, "secret": item["secret"]}
    )
    assert result.status_code == 200
    assert (
        call(
            "bob",
            "POST",
            f"/companies/{other}/transfer-ownership",
            json={"target_membership_id": result.json()["id"]},
        ).status_code
        == 200
    )
    members = call("alice", "GET", f"/companies/{other}/members").json()["items"]
    assert (
        next(row for row in members if row["user_id"] == actors["identities"]["bob"]["user_id"])["role"]
        == "admin"
    )


def test_sprint2_last_admin_database_backstops_and_append_only_audit(actors, stack):
    call = actors["request"]
    assert (
        call(
            "admin",
            "POST",
            "/companies",
            json={"name": "DB guard", "slug": "db-guard-" + uuid.uuid4().hex[:8]},
        ).status_code
        == 201
    )
    admin_id = actors["identities"]["admin"]["user_id"]
    assert call("admin", "DELETE", f"/platform/admins/{admin_id}").status_code == 409
    second = actors["identities"]["bob"]["user_id"]
    assert call("admin", "POST", "/platform/admins", json={"user_id": second}).status_code == 201
    assert call("admin", "DELETE", f"/platform/admins/{second}").status_code == 200
    with pytest.raises(psycopg.errors.CheckViolation), sql_connection(stack) as db:
        db.execute("UPDATE platform_admins SET active=false WHERE user_id=%s", (admin_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege), sql_connection(stack) as db:
        db.execute("DELETE FROM audit_events")
    with pytest.raises(psycopg.errors.CheckViolation), sql_connection(stack) as db:
        db.execute("UPDATE memberships SET role='member' WHERE role='owner'")
    with sql_connection(stack) as db:
        assert db.execute("SELECT active FROM platform_admins WHERE user_id=%s", (admin_id,)).fetchone() == (
            True,
        )
        assert db.execute(
            "SELECT count(*) FROM audit_events WHERE action='platform_admin.bootstrapped'"
        ).fetchone() == (1,)
    assert call("alice", "GET", "/platform/audit").status_code == 403
    response = call("admin", "GET", "/platform/audit?limit=100")
    assert response.status_code == 200 and response.json()["total"] > 0


def test_sprint2_concurrent_ownership_transfers_and_admin_revocations(
    actors, stack, restore_platform_admin_state
):
    from concurrent.futures import ThreadPoolExecutor

    call = actors["request"]
    assert (
        call(
            "admin",
            "PATCH",
            "/platform/settings",
            json={"company_creation_policy": "open", "max_owned_companies_per_user": 10},
        ).status_code
        == 200
    )
    created = call("carol", "POST", "/companies", json={"name": "Transfer race", "slug": "transfer-race"})
    assert created.status_code == 201
    cid = created.json()["id"]
    targets = []
    for label in ("bob", "dave"):
        issued = invite(actors, cid, sender="carol", recipient=label)
        joined = call(
            label, "POST", "/invitations/accept", json={"company_id": cid, "secret": issued["secret"]}
        )
        assert joined.status_code == 200
        targets.append(joined.json()["id"])
    with ThreadPoolExecutor(2) as pool:
        values = list(
            pool.map(
                lambda target: call(
                    "carol",
                    "POST",
                    f"/companies/{cid}/transfer-ownership",
                    json={"target_membership_id": target},
                ),
                targets,
            )
        )
    assert sorted(item.status_code for item in values) == [200, 403]
    admin_ids = {label: actors["identities"][label]["user_id"] for label in ("admin", "bob")}
    assert call("admin", "POST", "/platform/admins", json={"user_id": admin_ids["bob"]}).status_code == 201
    # Both participants must pass platform authorization/MFA before the race.
    for label in admin_ids:
        response = call(label, "GET", "/platform/settings")
        assert response.status_code == 200, (label, response.status_code, response.json().get("detail"))
    with ThreadPoolExecutor(2) as pool:
        values = list(
            pool.map(
                lambda label: (label, call(label, "DELETE", f"/platform/admins/{admin_ids[label]}")),
                ("admin", "bob"),
            )
        )
    assert sorted(item.status_code for _, item in values) == [200, 409], [
        (label, item.status_code, item.json().get("detail")) for label, item in values
    ]
    rejected = next(item for _, item in values if item.status_code == 409)
    assert rejected.json() == {"detail": {"code": "last_platform_admin"}}
    with sql_connection(stack) as db:
        assert db.execute("SELECT count(*) FROM platform_admins WHERE active").fetchone() == (1,)
    survivor = next(label for label, item in values if item.status_code == 409)
    assert call(survivor, "POST", "/platform/admins", json={"user_id": admin_ids["admin"]}).status_code == 201
    assert call("admin", "DELETE", f"/platform/admins/{admin_ids['bob']}").status_code == 200
    with pytest.raises(psycopg.errors.CheckViolation), sql_connection(stack) as db:
        db.execute("UPDATE users SET status='suspended' WHERE id=%s", (admin_ids["admin"],))


def test_sprint2_deferred_commit_failure_returns_conflict_and_rolls_back_everything(actors, stack):
    call = actors["request"]
    assert (
        call(
            "admin",
            "PATCH",
            "/platform/settings",
            json={"company_creation_policy": "open", "max_owned_companies_per_user": 10},
        ).status_code
        == 200
    )
    with sql_connection(stack) as db:
        before = db.execute("SELECT count(*) FROM companies").fetchone()[0]
        audits_before = db.execute("SELECT count(*) FROM audit_events").fetchone()[0]
        db.execute("""CREATE FUNCTION test_reject_company_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF NEW.action='company.created' THEN RAISE EXCEPTION 'test failure' USING ERRCODE='23514'; END IF;
            RETURN NULL; END $$""")
        db.execute(
            "CREATE CONSTRAINT TRIGGER test_reject_company_audit AFTER INSERT ON audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION test_reject_company_audit()"
        )
    try:
        result = call("alice", "POST", "/companies", json={"name": "Must rollback", "slug": "rollback-isp"})
        assert result.status_code == 409
        assert result.json() == {"detail": {"code": "data_conflict"}}
        with sql_connection(stack) as db:
            assert db.execute("SELECT count(*) FROM companies").fetchone()[0] == before
            assert db.execute("SELECT count(*) FROM audit_events").fetchone()[0] == audits_before
            assert db.execute("SELECT count(*) FROM companies WHERE slug='rollback-isp'").fetchone() == (0,)
    finally:
        with sql_connection(stack) as db:
            db.execute("DROP TRIGGER test_reject_company_audit ON audit_events")
            db.execute("DROP FUNCTION test_reject_company_audit()")
