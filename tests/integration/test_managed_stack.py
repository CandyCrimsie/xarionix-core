"""Opt-in REAL Docker/PostgreSQL/Keycloak tests. Never touch installed project volumes.

XARIONIX_RUN_DOCKER_TESTS=1 .venv/bin/pytest tests/integration -vv
The service-account grant exists only in this disposable test realm/client.
Production clients do not enable this grant.
"""

import asyncio
import copy
import json
import os
import secrets
import socket
import subprocess
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
from app.main import create_app
from scripts import setup
from scripts.ci import preflight

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
            "protocolMappers": copy.deepcopy(realm["clients"][1]["protocolMappers"]),
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
    definition["networks"] = {"default": {"labels": {"io.xarionix.test.job-id": job}}}
    compose_path, env_path = folder / "compose.yaml", folder / ".env"
    setup.atomic_write(compose_path, yaml.safe_dump(definition))
    setup.atomic_write(env_path, setup.env_text(config))
    command = ["docker", "compose", "-p", project, "--env-file", str(env_path), "-f", str(compose_path)]
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith(("XARIONIX_", "COMPOSE_"))
    }

    def execute(arguments, timeout=600):
        try:
            result = subprocess.run(
                command + arguments, env=environment, capture_output=True, timeout=timeout
            )
        except (OSError, subprocess.TimeoutExpired):
            pytest.fail(
                "Docker/Compose unavailable or timed out: integration requires the dedicated Docker runner"
            )
        if result.returncode:
            reports = ROOT / "reports"
            reports.mkdir(exist_ok=True)
            status = subprocess.run(
                command + ["ps", "--all", "--format", "json"], env=environment, capture_output=True
            )
            try:
                value = status.stdout.decode()
                items = (
                    json.loads(value)
                    if value.startswith("[")
                    else [json.loads(line) for line in value.splitlines()]
                )
                safe = [
                    {key: item.get(key) for key in ("Service", "State", "Health", "ExitCode")}
                    for item in items
                ]
                (reports / "integration-diagnostics.json").write_text(json.dumps(safe))
            except (ValueError, TypeError):
                pass
            pytest.fail(
                "Isolated stack command failed. See reports/integration-diagnostics.json; raw credentials/config are not logged"
            )
        return result.stdout

    try:
        execute(["config", "-q"])
        execute(["up", "-d", "--build", "--wait", "--wait-timeout", "420"], timeout=1500)
        yield IsolatedStack(
            {
                "config": config,
                "issuer": issuer,
                "client_secret": client_secret,
                "postgres_port": postgres_port,
                "execute": execute,
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


def token(stack):
    with httpx.Client(timeout=10, trust_env=False) as client:
        response = client.post(
            stack["issuer"] + "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "integration-only",
                "client_secret": stack["client_secret"],
            },
        )
        assert response.status_code == 200
        return response.json()["access_token"]


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
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0001_identity",)
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
    finally:
        await engine.dispose()
