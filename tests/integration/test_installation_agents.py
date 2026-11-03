"""Actual RBAC epochs, exact dependency pins and outbound Docker agent lifecycle."""

import asyncio
import subprocess
import uuid

import psycopg
import pytest
import test_managed_stack as managed
import test_module_control as control
import yaml
from pydantic import SecretStr
from test_module_installations import admin, apply, approve, bundles, installed, installer, prepare

from app.core.access import Context
from app.core.database import create_database
from app.domains.identity.model import Identity
from app.domains.rbac.authorization import effective
from app.domains.users.model import User
from scripts.setup import atomic_write

stack, actors, tenants = managed.stack, managed.actors, managed.tenants
modules = control.modules
pytestmark = pytest.mark.integration
# Imported pytest fixtures deliberately share the established isolated stack contracts.
__all__ = ["bundles", "installer"]


async def test_role_permissions_survive_disable_but_not_uninstall_reinstall(
    installer, actors, stack, bundles, tenants
):
    bundle = bundles()
    plan = prepare(actors, bundle)
    approve(actors, plan)
    await apply(installer, bundle, plan)
    value = installed(actors, bundle["manifest"]["module"]["id"])
    plan = prepare(actors, bundle, "enable", value["generation"])
    approve(actors, plan)
    await apply(installer, bundle, plan)
    key = bundle["manifest"]["permissions"]["definitions"][0]["key"]
    company = tenants["alice"]
    role = actors["request"](
        "alice",
        "POST",
        f"/companies/{company}/roles",
        json={"code": "module_access", "name": "Module access", "permissions": [key]},
    )
    assert role.status_code == 201, role.text
    with managed.sql_connection(stack) as db:
        member = db.execute(
            "SELECT id FROM memberships WHERE company_id=%s AND role='owner'", (company,)
        ).fetchone()[0]
    assert (
        actors["request"](
            "alice",
            "POST",
            f"/companies/{company}/members/{member}/roles",
            json={"role_id": role.json()["id"]},
        ).status_code
        == 204
    )
    cfg = installer.model_copy(
        update={"db_user": "core_app", "db_password": SecretStr(stack["config"]["DB_PASSWORD"])}
    )
    engine, sessions = create_database(cfg)

    async def allowed():
        async with sessions() as session, session.begin():
            identity = await session.get(Identity, uuid.UUID(actors["identities"]["alice"]["id"]))
            user = await session.get(User, identity.user_id)
            ctx = Context(session, identity, user, cfg, {})
            return key in (await effective(ctx, uuid.UUID(company))).permissions

    try:
        assert await allowed()
        for action in ("disable", "enable", "disable", "uninstall", "install", "enable"):
            value = installed(actors, value["module_id"])
            plan = prepare(actors, bundle, action, value["generation"])
            approve(actors, plan)
            await apply(installer, bundle, plan)
            expected = action == "enable" and value["generation"] == 3
            assert await allowed() is expected
        with managed.sql_connection(stack) as db:
            assert db.execute(
                "SELECT permission_generation FROM role_permissions WHERE role_id=%s AND permission_key=%s",
                (role.json()["id"], key),
            ).fetchone() == (1,)
            assert db.execute(
                "SELECT definition_generation FROM permissions WHERE key=%s", (key,)
            ).fetchone() == (3,)
        response = actors["request"](
            "alice",
            "PUT",
            f"/companies/{company}/roles/{role.json()['id']}/permissions",
            json={"expected_version": 1, "permissions": [key]},
        )
        assert response.status_code == 200, response.text
        assert await allowed()
    finally:
        await engine.dispose()


async def test_exact_dependency_pins_block_implicit_uninstall(installer, actors, bundles):
    dependency = bundles()
    for action, generation in (("install", 0), ("enable", 1)):
        p = prepare(actors, dependency, action, generation)
        approve(actors, p)
        await apply(installer, dependency, p)
    dependent = bundles(
        dependencies=[
            {
                "module_id": dependency["manifest"]["module"]["id"],
                "publisher_id": dependency["manifest"]["publisher"]["id"],
                "version": ">=1.0.0 <2.0.0",
            }
        ]
    )
    p = prepare(actors, dependent)
    assert p["plan"]["dependency_pins"][0]["package_sha256"] == dependency["package"]["package_sha256"]
    approve(actors, p)
    await apply(installer, dependent, p)
    p = prepare(actors, dependency, "disable", 2)
    approve(actors, p)
    await apply(installer, dependency, p)
    p = prepare(actors, dependency, "uninstall", 3, ready=False)
    assert "installed_dependents_require_explicit_replanning" in p["plan"]["blockers"]


async def test_real_agent_explicit_binding_stale_reconnect_and_disable(
    installer, actors, stack, bundles, modules, tmp_path
):
    module = modules()
    bundle = bundles(module=module["service"]["module_key"], module_type="autonomous")
    p = prepare(actors, bundle)
    approve(actors, p)
    await apply(installer, bundle, p)
    value = installed(actors, bundle["manifest"]["module"]["id"])
    iid = module["instance"]["id"]
    assert value["runtime"]["state"] == "awaiting_connection" and value["runtime"]["instance_id"] is None
    bound = admin(
        actors,
        "POST",
        f"/module-installations/{value['id']}/bind-instance",
        json={
            "instance_id": iid,
            "package_sha256": bundle["package"]["package_sha256"],
            "expected_generation": 1,
            "expected_revision": 0,
        },
    )
    assert bound.status_code == 200, bound.text
    p = prepare(actors, bundle, "enable", 1, ready=False)
    assert "autonomous_agent_not_ready" in p["plan"]["blockers"]
    project = "xarionix-install-agent-" + uuid.uuid4().hex[:12]
    compose = {
        "services": {
            "agent": {
                "image": stack["image"],
                "command": ["python", "-m", "scripts.module_agent"],
                "user": "10001:10001",
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "environment": {
                    "XARIONIX_AGENT_CORE_URL": "http://core:8000",
                    "XARIONIX_AGENT_ISSUER": stack["issuer"],
                    "XARIONIX_AGENT_CLIENT_ID": module["client_id"],
                    "XARIONIX_AGENT_CLIENT_SECRET": module["client_secret"],
                    "XARIONIX_AGENT_INSTANCE_ID": iid,
                    "XARIONIX_AGENT_ISOLATED_HTTP": "true",
                    "XARIONIX_AGENT_TEST_OIDC_TRANSPORT": "http://keycloak:8080/realms/xarionix",
                },
                "networks": ["control"],
            }
        },
        "networks": {"control": {"external": True, "name": stack["agent_network"]}},
    }
    path = tmp_path / "agent.yaml"
    atomic_write(path, yaml.safe_dump(compose))
    command = ["docker", "compose", "-p", project, "-f", str(path)]

    def run(*args):
        result = subprocess.run(command + list(args), capture_output=True, timeout=60)
        assert result.returncode == 0, "Isolated installation-agent operation failed"
        return result.stdout

    def state(expected):
        response = admin(actors, "GET", f"/module-installations/{value['id']}")
        if response.status_code != 200:
            detail = response.json().get("detail")
            code = detail.get("code", "unclassified") if isinstance(detail, dict) else "unclassified"
            raise RuntimeError(
                f"Installation state endpoint failed: HTTP {response.status_code}, code={code}"
            )
        current = response.json()
        assert current["runtime"]["state"] == expected, current["runtime"]["state"]
        return current

    try:
        run("up", "-d")
        managed.poll(lambda: state("connected"), timeout=45)
        p = prepare(actors, bundle, "enable", 1)
        approve(actors, p)
        await apply(installer, bundle, p)
        identifier = run("ps", "-q", "agent").decode().strip()
        disconnected = await asyncio.to_thread(
            subprocess.run,
            ["docker", "network", "disconnect", stack["agent_network"], identifier],
            capture_output=True,
            timeout=15,
        )
        assert disconnected.returncode == 0
        managed.poll(lambda: state("stale"), timeout=105)
        with managed.sql_connection(stack) as db:
            assert db.execute("SELECT core_module_available(%s,90)", (value["namespace"],)).fetchone() == (
                False,
            )
        reconnected = await asyncio.to_thread(
            subprocess.run,
            ["docker", "network", "connect", stack["agent_network"], identifier],
            capture_output=True,
            timeout=15,
        )
        assert reconnected.returncode == 0
        # Long outage may leave the existing agent in its documented 60s backoff,
        # plus HTTP timeout/token refresh. Do not shorten production retry policy.
        managed.poll(lambda: state("connected"), timeout=150)
        for action, generation in (("disable", 2), ("enable", 3), ("disable", 4), ("uninstall", 5)):
            p = prepare(actors, bundle, action, generation)
            approve(actors, p)
            await apply(installer, bundle, p)
        final = admin(actors, "GET", f"/module-installations/{value['id']}").json()
        assert final["status"] == "removed" and not final["runtime"]["binding_active"]
        service = admin(actors, "GET", f"/module-services/{module['service']['id']}").json()
        assert service["status"] == "active" and run("ps", "-q", "agent").decode().strip() == identifier
        logs = run("logs", "--no-color", "agent").decode()
        assert (
            "agent_check_in_ok" in logs
            and module["client_secret"] not in logs
            and module["token"] not in logs
        )
    finally:
        run("down", "--remove-orphans")


async def test_unbind_and_replacement_do_not_restore_legacy_machine_access(
    installer, actors, stack, bundles, modules, tenants
):
    module_key = "enrolled-" + uuid.uuid4().hex[:12]
    old_agent = modules(module_key=module_key)
    new_agent = modules(module_key=module_key)
    bundle = bundles(module=module_key, module_type="autonomous")
    p = prepare(actors, bundle)
    approve(actors, p)
    await apply(installer, bundle, p)
    value = installed(actors, module_key)
    cid = tenants["alice"]
    for agent in (old_agent, new_agent):
        iid = agent["instance"]["id"]
        assert (
            admin(
                actors,
                "PUT",
                f"/module-instances/{iid}/companies/{cid}",
                json={"status": "active", "operations": ["core.modules.metadata.read"]},
            ).status_code
            == 200
        )
        assert (
            control.machine_request(
                stack, agent["token"], "POST", "/check-in", json=control.heartbeat(agent)
            ).status_code
            == 200
        )

    def metadata(agent):
        return control.machine_request(
            stack, agent["token"], "GET", f"/instances/{agent['instance']['id']}/companies/{cid}"
        )

    def bind(instance, revision, generation):
        response = admin(
            actors,
            "POST",
            f"/module-installations/{value['id']}/bind-instance",
            json={
                "instance_id": instance,
                "package_sha256": bundle["package"]["package_sha256"],
                "expected_generation": generation,
                "expected_revision": revision,
            },
        )
        assert response.status_code == 200, response.text

    # Never-enrolled 4A services retain their explicitly granted legacy scopes.
    assert metadata(old_agent).status_code == 200
    bind(old_agent["instance"]["id"], 0, 1)
    assert metadata(old_agent).status_code == 403
    p = prepare(actors, bundle, "enable", 1)
    approve(actors, p)
    await apply(installer, bundle, p)
    assert metadata(old_agent).status_code == 200
    bind(None, 1, 2)
    assert metadata(old_agent).status_code == 403
    bind(new_agent["instance"]["id"], 2, 2)
    assert metadata(new_agent).status_code == 200
    assert metadata(old_agent).status_code == 403
    with managed.sql_connection(stack) as db:
        with pytest.raises(psycopg.errors.CheckViolation):
            db.execute(
                "UPDATE module_instances SET installation_managed=false WHERE id=%s",
                (old_agent["instance"]["id"],),
            )
    control.ready_for_poll(stack, old_agent)
    assert (
        control.machine_request(
            stack, old_agent["token"], "POST", "/check-in", json=control.heartbeat(old_agent)
        ).status_code
        == 200
    )
