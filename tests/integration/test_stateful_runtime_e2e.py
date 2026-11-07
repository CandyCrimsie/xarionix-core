"""Required native rootless E2E. Real SDK/OCI, Core, PostgreSQL, Keycloak and business rows."""

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import test_managed_stack as managed
from stateful_helpers import stateful_package
from test_deployment_control import deployment_identity as deployment_identity
from test_module_gateway_e2e import gateway_identity
from test_module_installations import admin, apply, approve, installed, prepare
from test_module_installations import installer as installer
from test_runtime_e2e import live_agent as live_agent
from test_runtime_e2e import runtime_status, wait_job, wait_stopped
from test_sprint3 import grant, new_role

from app.domains.packages.storage import Storage
from scripts.deployment_agent.engine import Engine

stack, actors, tenants = managed.stack, managed.actors, managed.tenants
pytestmark = [pytest.mark.integration, pytest.mark.runtime]


@pytest.fixture(scope="module")
def runtime_engine():
    if os.environ.get("XARIONIX_RUN_STATEFUL_TESTS") != "1":
        pytest.skip("Separate required stateful native job; set XARIONIX_RUN_STATEFUL_TESTS=1")
    raw = os.environ.get("XARIONIX_RUNTIME_ENGINE_SOCKET")
    if not raw:
        pytest.fail(
            "Stateful E2E requires a dedicated native rootless socket; no Docker Desktop/DinD fallback"
        )
    path = Path(raw)
    with httpx.Client(transport=httpx.HTTPTransport(uds=str(path)), trust_env=False) as client:
        info = client.get("http://engine/v1.52/info").json()
    outer = subprocess.check_output(["docker", "info", "--format", "{{.ID}}"], text=True).strip()
    assert info["ID"] != outer and info["Containers"] == 0
    assert info["OSType"] == "linux" and "name=rootless" in info["SecurityOptions"]
    assert str(info["CgroupVersion"]) == "2" and all(
        info[k] for k in ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota")
    )
    engine = Engine(path, info["ID"])
    engine.platform = "linux/" + {"x86_64": "amd64", "aarch64": "arm64"}.get(
        info["Architecture"], info["Architecture"]
    )
    engine.test_images, engine.test_installations = set(), set()
    before = {r["Id"] for r in engine.call("GET", "/images/json")}
    try:
        yield engine
    finally:
        # Only this fixture's disposable installations, after live_agent removed their containers.
        for volume in engine.call("GET", "/volumes").get("Volumes") or []:
            labels = volume.get("Labels") or {}
            if (
                labels.get("io.xarionix.storage.installation") in engine.test_installations
                and labels.get("io.xarionix.storage.engine") == engine.expected_id
            ):
                engine.call("DELETE", "/volumes/" + volume["Name"])
        for digest in sorted(engine.test_images):
            image = engine.call("GET", "/images/" + digest + "/json")
            if image and image["Id"] not in before:
                engine.call("DELETE", "/images/" + image["Id"], params={"force": "false", "noprune": "true"})
        engine.close()


def publish(actors, engine, value, store):
    result = admin(
        actors,
        "POST",
        "/packages",
        headers={"Content-Type": "application/octet-stream"},
        content=value["path"].read_bytes(),
    )
    assert result.status_code == 201, result.text
    store.publish(value["path"], value["report"]["package_sha256"])
    engine.test_images.update({value["contract"]["image_digest"], value["contract"]["config_digest"]})
    return value | {"package": result.json(), "storage": store}


@pytest.fixture
def runtime_bundle(actors, runtime_engine, tmp_path):
    publisher = "stateful-" + uuid4().hex[:12]
    value = stateful_package(tmp_path / "v1", platform=runtime_engine.platform, publisher=publisher)
    response = admin(
        actors,
        "POST",
        "/package-publishers",
        json={"publisher_id": publisher, "display_name": "SDK storage E2E"},
    )
    assert response.status_code == 201, response.text
    pid = response.json()["id"]
    response = admin(
        actors,
        "POST",
        f"/package-publishers/{pid}/keys",
        json={"key_id": "test-key", "public_key": value["trust"].keys[0].public_key},
    )
    assert response.status_code == 201, response.text
    assert (
        admin(
            actors, "PUT", f"/package-publishers/{pid}/namespaces", json={"namespaces": ["hello"]}
        ).status_code
        == 200
    )
    return publish(actors, runtime_engine, value, Storage(tmp_path / "cas")) | {"publisher": publisher}


def deployment(actors, installation, host, operation="start", *, backup=None, migrate=False, expected=201):
    current = runtime_status(actors, installation["id"])
    body = {
        "idempotency_key": str(uuid4()),
        "installation_id": installation["id"],
        "host_id": host["id"],
        "operation": operation,
        "expected_installation_generation": installation["generation"],
        "expected_deployment_generation": current["generation"] if current else 0,
        "profile": "module-api-stateful-v1",
    }
    if backup:
        body["backup_id"] = backup
    if migrate:
        body["allow_migration"] = True
    response = admin(actors, "POST", "/deployment-plans", json=body)
    assert response.status_code == expected, response.text
    if expected != 201:
        return response
    plan = response.json()
    assert plan["body"]["storage"]["maximum_bytes"] == 67108864
    response = admin(
        actors, "POST", f"/deployment-plans/{plan['id']}/approve", json={"digest": plan["digest"]}
    )
    assert response.status_code == 200, response.text
    return wait_job(actors, installation["id"], response.json()["job_id"])


async def test_real_stateful_company_data_restart_upgrade_migration_backup_restore_and_retention(
    stack, actors, tenants, installer, runtime_bundle, runtime_engine, live_agent, tmp_path
):
    bundle, engine = runtime_bundle, runtime_engine
    host, _, _ = live_agent
    plan = prepare(actors, bundle)
    assert plan["plan"]["module_storage"]["required_profile"] == "module-api-stateful-v1"
    approve(actors, plan)
    await apply(installer, bundle, plan)
    installation = installed(actors, "hello-business")
    engine.test_installations.add(installation["id"])
    identity = gateway_identity(stack)
    response = admin(
        actors,
        "POST",
        f"/deployment-hosts/{host['id']}/gateway-identity",
        json={"issuer": stack["issuer"], "subject": identity["subject"], "client_id": identity["client_id"]},
    )
    assert response.status_code == 201, response.text
    deployment(actors, installation, host)
    print("Stateful E2E: initial schema and real rootless isolation passed", flush=True)
    enabled = prepare(actors, bundle, "enable", installation["generation"])
    approve(actors, enabled)
    await apply(installer, bundle, enabled)
    installation = installed(actors, "hello-business")
    # A new installation generation requires a reviewed exact runtime configuration.
    deployment(actors, installation, host)
    environment = {k: os.environ[k] for k in ("PATH", "LANG") if k in os.environ}
    environment |= {
        "XARIONIX_GATEWAY_" + key: str(value)
        for key, value in {
            "CORE_URL": stack["config"]["PUBLIC_URL"],
            "ISSUER": stack["issuer"],
            "CLIENT_ID": identity["client_id"],
            "CLIENT_SECRET": identity["secret"],
            "HOST_ID": host["id"],
            "ENGINE_SOCKET": engine.socket,
            "ENGINE_ID": engine.expected_id,
            "STORAGE_ROOT": host["storage_root"],
            "ISOLATED_HTTP": "true",
        }.items()
    }
    process = await asyncio.to_thread(
        subprocess.Popen,
        [sys.executable, "-m", "scripts.gateway_agent"],
        cwd=managed.ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    call = actors["request"]
    a, b = tenants["alice"], tenants["bob"]

    def operation(actor, company, op="items-read", body=None):
        return call(
            actor, "POST", f"/companies/{company}/modules/hello-business/operations/{op}", json=body or {}
        )

    def values(actor, company):
        result = operation(actor, company)
        assert result.status_code == 200, result.text
        assert result.json()["body"]["company_id"] == company
        return {item["name"] for item in result.json()["body"]["items"]}

    def grant_access():
        for actor, company in (("alice", a), ("bob", b)):
            role = new_role(
                actors, company, ["hello.items.read", "hello.items.create", "hello.status.read"], actor=actor
            )
            members = call(actor, "GET", f"/companies/{company}/members").json()["items"]
            member = next(m["id"] for m in members if m["user_id"] == actors["identities"][actor]["user_id"])
            assert grant(actors, company, member, role["id"], actor=actor).status_code == 204

    async def enable_version(value):
        current = installed(actors, "hello-business")
        assert operation("alice", a).status_code in {403, 404, 409}
        plan = prepare(actors, value, "enable", current["generation"])
        approve(actors, plan)
        await apply(installer, value, plan)
        current = installed(actors, "hello-business")
        deployment(actors, current, host)
        grant_access()  # Explicit reviewed grants for the new permission epoch.
        return current

    try:
        grant_access()
        deadline = time.monotonic() + 20
        status = operation("alice", a, "status-read")
        while status.status_code in {503, 504} and time.monotonic() < deadline:
            assert process.poll() is None
            await asyncio.sleep(0.2)
            status = operation("alice", a, "status-read")
        assert status.status_code == 200, status.text
        for actor, company, name in (("alice", a, "A1"), ("bob", b, "B1")):
            created = operation(actor, company, "items-create", {"name": name})
            if created.status_code != 200:
                current = runtime_status(actors, installation["id"])
                print(
                    "Stateful E2E write diagnostic",
                    actor,
                    {
                        k: current.get(k)
                        for k in (
                            "observed",
                            "health",
                            "desired",
                            "generation",
                            "safe_error_code",
                            "last_seen",
                        )
                    },
                    flush=True,
                )
            assert created.status_code == 200, created.text  # Never retry an uncertain write.
        assert values("alice", a) == {"A1"} and values("bob", b) == {"B1"}
        print("Stateful E2E: separate company rows persisted", flush=True)
        assert operation("alice", b).status_code == 404
        assert operation("alice", a, "items-create", {"name": "bad", "company_id": b}).status_code != 200
        deployment(actors, installation, host, "restart")
        assert values("alice", a) == {"A1"} and values("bob", b) == {"B1"}
        print("Stateful E2E: restart persistence passed", flush=True)
        key = bundle["path"].parent / "private.key"
        compatible = publish(
            actors,
            engine,
            stateful_package(
                tmp_path / "v111",
                platform=engine.platform,
                publisher=bundle["publisher"],
                version="1.1.1",
                key=key,
            ),
            bundle["storage"],
        )
        update = prepare(actors, compatible, "update", installation["generation"])
        approve(actors, update)
        await apply(installer, compatible, update)
        installation = installed(actors, "hello-business")
        wait_stopped(actors, installation["id"], "quarantined")
        deployment(actors, installation, host, "upgrade")
        installation = await enable_version(compatible)
        assert values("alice", a) == {"A1"} and values("bob", b) == {"B1"}
        print("Stateful E2E: compatible upgrade persistence passed", flush=True)
        deployment(actors, installation, host, "stop")
        migrated = publish(
            actors,
            engine,
            stateful_package(
                tmp_path / "v120",
                platform=engine.platform,
                publisher=bundle["publisher"],
                version="1.2.0",
                schema=2,
                key=key,
            ),
            bundle["storage"],
        )
        update = prepare(actors, migrated, "update", installation["generation"])
        approve(actors, update)
        await apply(installer, migrated, update)
        installation = installed(actors, "hello-business")
        wait_stopped(actors, installation["id"], "quarantined")
        # Catalog update and its security stop advance the allocation revision.
        # Back up the stopped previous runtime after this reconciliation, before
        # any new image is allowed to migrate the data.
        deployment(actors, installation, host, "backup")
        metadata = admin(actors, "GET", f"/runtime-deployments/{installation['id']}/storage").json()
        backup = metadata["items"][0]["id"]
        first_epoch = metadata["allocation"]["epoch_id"]
        print("Stateful E2E: stopped-writer backup passed", flush=True)
        refused = deployment(actors, installation, host, "upgrade", expected=409)
        assert refused.json()["detail"]["code"] == "storage_migration_requires_fresh_backup_and_approval"
        deployment(actors, installation, host, "upgrade", backup=backup, migrate=True)
        installation = await enable_version(migrated)
        print("Stateful E2E: approved schema migration passed", flush=True)
        assert values("alice", a) == {"A1"} and values("bob", b) == {"B1"}
        assert operation("alice", a, "items-create", {"name": "A2"}).status_code == 200
        rollback = prepare(actors, compatible, "rollback", installation["generation"])
        approve(actors, rollback)
        await apply(installer, compatible, rollback)
        installation = installed(actors, "hello-business")
        wait_stopped(actors, installation["id"], "quarantined")
        refused = deployment(actors, installation, host, "rollback", expected=409)
        assert refused.json()["detail"]["code"] == "storage_schema_incompatible"
        # Quarantine has already physically stopped the writer. Do not enqueue
        # a redundant ordinary stop that security reconciliation can supersede.
        deployment(actors, installation, host, "restore", backup=backup)
        metadata = admin(actors, "GET", f"/runtime-deployments/{installation['id']}/storage").json()
        assert metadata["allocation"]["epoch_id"] != first_epoch
        assert metadata["allocation"]["data_schema_version"] == 1
        assert metadata["allocation"]["retained_epoch_count"] == 1
        deployment(actors, installation, host)
        installation = await enable_version(compatible)
        print("Stateful E2E: restore into new epoch and compatible rollback passed", flush=True)
        assert values("alice", a) == {"A1"} and values("bob", b) == {"B1"}
        status = runtime_status(actors, installation["id"])
        info = engine.inspect(status["container_id"])
        assert info["Config"]["User"] == "10001:10001" and info["HostConfig"]["ReadonlyRootfs"] is True
        assert info["HostConfig"]["NetworkMode"] == "none" and len(info["Mounts"]) == 1
        assert info["Mounts"][0]["Type"] == "volume" and info["Mounts"][0]["Destination"] == "/data"
        assert all(
            not any(secret in entry for secret in ("DB_PASSWORD=", "CLIENT_SECRET=", "ACCESS_TOKEN="))
            for entry in info["Config"]["Env"]
        )
        disabled = prepare(actors, compatible, "disable", installation["generation"])
        approve(actors, disabled)
        await apply(installer, compatible, disabled)
        installation = installed(actors, "hello-business")
        wait_stopped(actors, installation["id"], "quarantined")
        deployment(actors, installation, host, "deprovision")
        uninstall = prepare(actors, compatible, "uninstall", installation["generation"])
        approve(actors, uninstall)
        await apply(installer, compatible, uninstall)
        retained = admin(actors, "GET", f"/runtime-deployments/{installation['id']}/storage")
        assert (
            retained.status_code == 200
            and retained.json()["allocation"]["epoch_id"] == metadata["allocation"]["epoch_id"]
        )
        volumes = engine.call("GET", "/volumes")["Volumes"]
        assert (
            len(
                [
                    v
                    for v in volumes
                    if (v.get("Labels") or {}).get("io.xarionix.storage.installation") == installation["id"]
                ]
            )
            == 2
        )
        assert (
            admin(actors, "DELETE", f"/runtime-deployments/{installation['id']}/storage").status_code == 405
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
