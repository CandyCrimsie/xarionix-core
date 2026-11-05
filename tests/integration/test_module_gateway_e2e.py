"""Real signed OCI business handler, Core/PG/Keycloak and a dedicated native rootless daemon.

A forwarded Unix socket to a native Linux host is allowed: enforcement is measured
inside that daemon's runtime, not inferred from the pytest client's OS. No DinD skip.
"""

import asyncio
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import jwt
import pytest
import test_managed_stack as managed
from package_helpers import manifest_data
from runtime_helpers import runtime_package
from test_deployment_control import deployment_identity as deployment_identity
from test_module_installations import admin, apply, approve, installed, prepare
from test_module_installations import installer as installer
from test_runtime_e2e import deploy as control_deploy
from test_runtime_e2e import live_agent as live_agent
from test_runtime_e2e import runtime_status, wait_health, wait_job, wait_stopped
from test_sprint3 import grant, join, new_role

from app.domains.packages.storage import Storage
from scripts.deployment_agent.engine import Engine, EngineFailure

stack, actors, tenants = managed.stack, managed.actors, managed.tenants
pytestmark = [pytest.mark.integration, pytest.mark.runtime]


@pytest.fixture(scope="module")
def runtime_engine():
    if os.environ.get("XARIONIX_RUN_GATEWAY_TESTS") != "1":
        pytest.skip("Separate required module-gateway runtime job; set XARIONIX_RUN_GATEWAY_TESTS=1")
    raw = os.environ.get("XARIONIX_RUNTIME_ENGINE_SOCKET")
    if not raw:
        pytest.fail("Gateway E2E requires a dedicated native rootless engine Unix socket")
    path = Path(raw)
    with httpx.Client(transport=httpx.HTTPTransport(uds=str(path)), trust_env=False) as client:
        info = client.get("http://engine/v1.52/info").json()
    outer = subprocess.check_output(["docker", "info", "--format", "{{.ID}}"], text=True).strip()
    assert info["ID"] != outer and info["Containers"] == 0, "Refusing non-dedicated/nonempty runtime engine"
    assert info["OSType"] == "linux" and "name=rootless" in info["SecurityOptions"]
    assert info["CgroupVersion"] == "2" and all(
        info[k] for k in ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota")
    )
    engine = Engine(path, info["ID"])
    existing_images = {row["Id"] for row in engine.call("GET", "/images/json")}
    engine.test_images = set()
    engine.platform = "linux/" + {"x86_64": "amd64", "aarch64": "arm64"}.get(
        info["Architecture"], info["Architecture"]
    )
    try:
        yield engine
    finally:
        # Exact signed digests from this fixture only; preserve all pre-existing cache images.
        for digest in sorted(engine.test_images):
            image = engine.call("GET", "/images/" + digest + "/json")
            if image and image["Id"] not in existing_images:
                engine.call("DELETE", "/images/" + image["Id"], params={"force": "false", "noprune": "true"})
        engine.close()


@pytest.fixture
def runtime_bundle(actors, runtime_engine, tmp_path):
    suffix = uuid.uuid4().hex[:10]
    tag = "xarionix-hello-business:test-" + suffix
    archive = tmp_path / "business-image.tar"
    subprocess.run(
        [
            "docker",
            "build",
            "--platform",
            runtime_engine.platform,
            "--tag",
            tag,
            "examples/modules/hello-business",
        ],
        cwd=managed.ROOT,
        check=True,
        capture_output=True,
        timeout=300,
    )
    try:
        subprocess.run(
            ["docker", "save", "--output", str(archive), tag], check=True, capture_output=True, timeout=120
        )
    finally:
        subprocess.run(["docker", "image", "rm", tag], check=False, capture_output=True, timeout=30)
    data = json.loads((managed.ROOT / "examples/modules/hello-business/manifest.json").read_text())
    data["module"]["id"] = "business-" + suffix
    data["publisher"]["id"] = "publisher-" + suffix
    api = (managed.ROOT / "examples/modules/hello-business/module-api-v1.json").read_bytes()

    def add_api(folder):
        (folder / "payload/resources/module-api-v1.json").write_bytes(api)

    path, trust, report, contract = runtime_package(
        tmp_path / "package",
        source=archive,
        module=data["module"]["id"],
        namespace="hello",
        publisher=data["publisher"]["id"],
        manifest=data,
        transform=add_api,
    )
    runtime_engine.test_images.update({contract["image_digest"], contract["config_digest"]})
    pub = admin(
        actors,
        "POST",
        "/package-publishers",
        json={"publisher_id": data["publisher"]["id"], "display_name": "Gateway E2E"},
    )
    assert pub.status_code == 201, pub.text
    pid = pub.json()["id"]
    key = admin(
        actors,
        "POST",
        f"/package-publishers/{pid}/keys",
        json={"key_id": "test-key", "public_key": trust.keys[0].public_key},
    )
    assert key.status_code == 201, key.text
    assert (
        admin(
            actors, "PUT", f"/package-publishers/{pid}/namespaces", json={"namespaces": ["hello"]}
        ).status_code
        == 200
    )
    uploaded = admin(
        actors,
        "POST",
        "/packages",
        headers={"Content-Type": "application/octet-stream"},
        content=path.read_bytes(),
    )
    assert uploaded.status_code == 201, uploaded.text
    storage = Storage(tmp_path / "cas")
    storage.publish(path, report["package_sha256"])
    return {
        "package": uploaded.json(),
        "manifest": data,
        "storage": storage,
        "path": path,
        "contract": contract,
        "publisher": pid,
        "key": key.json()["id"],
        "namespace": "hello",
    }


def gateway_identity(stack):
    name, secret = "gateway-" + uuid.uuid4().hex[:12], secrets.token_hex(32)
    with httpx.Client(timeout=20, trust_env=False) as client:
        managed.refresh_test_authentication(stack, client, "integration-admin", None)
        response = client.post(
            stack["config"]["KEYCLOAK_PUBLIC_URL"] + "/admin/realms/xarionix/clients",
            headers={"Authorization": "Bearer " + stack["admin_token"]},
            json={
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
                        "name": "sub",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-sub-mapper",
                        "config": {"access.token.claim": "true"},
                    },
                    {
                        "name": "aud",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": {
                            "included.custom.audience": "xarionix-core-gateway",
                            "access.token.claim": "true",
                            "id.token.claim": "false",
                        },
                    },
                    {
                        "name": "purpose",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-hardcoded-claim-mapper",
                        "config": {
                            "claim.name": "xarionix_principal",
                            "claim.value": "gateway",
                            "jsonType.label": "String",
                            "access.token.claim": "true",
                            "id.token.claim": "false",
                        },
                    },
                ],
            },
        )
        assert response.status_code == 201
    response = httpx.post(
        stack["issuer"] + "/protocol/openid-connect/token",
        data={"grant_type": "client_credentials", "client_id": name, "client_secret": secret},
        timeout=10,
        trust_env=False,
    )
    assert response.status_code == 200
    subject = jwt.decode(response.json()["access_token"], options={"verify_signature": False})["sub"]
    return managed.IsolatedStack({"client_id": name, "secret": secret, "subject": subject})


def deploy(actors, installation, host):
    current = runtime_status(actors, installation["id"])
    response = admin(
        actors,
        "POST",
        "/deployment-plans",
        json={
            "idempotency_key": str(uuid.uuid4()),
            "installation_id": installation["id"],
            "host_id": host["id"],
            "operation": "start",
            "profile": "module-api-private-v1",
            "expected_installation_generation": installation["generation"],
            "expected_deployment_generation": current["generation"] if current else 0,
        },
    )
    assert response.status_code == 201, response.text
    plan = response.json()
    assert (
        plan["body"]["api_contract_sha256"] and plan["body"]["gateway_protocol"] == "module-gateway-poll-v1"
    )
    response = admin(
        actors, "POST", f"/deployment-plans/{plan['id']}/approve", json={"digest": plan["digest"]}
    )
    assert response.status_code == 200, response.text
    return wait_job(actors, installation["id"], response.json()["job_id"])


def publish_version_two(actors, bundle, engine, folder):
    folder.mkdir()
    archive = folder / "image.tar"
    tag = "xarionix-business:version2-" + uuid.uuid4().hex[:12]
    try:
        subprocess.run(
            [
                "docker",
                "build",
                "--platform",
                engine.platform,
                "--build-arg",
                "HELLO_VERSION=2.0.0",
                "--tag",
                tag,
                "examples/modules/hello-business",
            ],
            cwd=managed.ROOT,
            check=True,
            capture_output=True,
            timeout=300,
        )
        subprocess.run(
            ["docker", "save", "--output", str(archive), tag], check=True, capture_output=True, timeout=120
        )
    finally:
        subprocess.run(["docker", "image", "rm", tag], capture_output=True, timeout=30)
    manifest = json.loads(json.dumps(bundle["manifest"]))
    manifest["module"]["version"] = "2.0.0"
    manifest["permissions"]["definitions"][0]["key"] = "hello.status_v2.read"
    api = json.loads((managed.ROOT / "examples/modules/hello-business/module-api-v1.json").read_text())
    api["operations"][0].update(id="status-read-v2", permission="hello.status_v2.read")

    def add_api(distribution):
        (distribution / "payload/resources/module-api-v1.json").write_text(json.dumps(api))

    path, _, report, contract = runtime_package(
        folder / "package",
        source=archive,
        manifest=manifest,
        module=manifest["module"]["id"],
        namespace="hello",
        publisher=manifest["publisher"]["id"],
        version="2.0.0",
        key=bundle["path"].parent / "private.key",
        transform=add_api,
    )
    engine.test_images.update({contract["image_digest"], contract["config_digest"]})
    uploaded = admin(
        actors,
        "POST",
        "/packages",
        headers={"Content-Type": "application/octet-stream"},
        content=path.read_bytes(),
    )
    assert uploaded.status_code == 201, uploaded.text
    bundle["storage"].publish(path, report["package_sha256"])
    return bundle | {"package": uploaded.json(), "path": path, "manifest": manifest, "contract": contract}


async def deploy_isolated_peer(actors, installer, bundle, host, folder):
    namespace = "peer" + uuid.uuid4().hex[:10]
    publisher = bundle["manifest"]["publisher"]["id"]
    assert (
        admin(
            actors,
            "PUT",
            f"/package-publishers/{bundle['publisher']}/namespaces",
            json={"namespaces": ["hello", namespace]},
        ).status_code
        == 200
    )
    data = manifest_data(module="peer-" + uuid.uuid4().hex[:10], publisher=publisher, namespace=namespace)
    path, _, report, contract = runtime_package(
        folder,
        manifest=data,
        source=bundle["path"].parent.parent / "business-image.tar",
        module=data["module"]["id"],
        publisher=publisher,
        namespace=namespace,
        key=bundle["path"].parent / "private.key",
    )
    uploaded = admin(
        actors,
        "POST",
        "/packages",
        headers={"Content-Type": "application/octet-stream"},
        content=path.read_bytes(),
    )
    assert uploaded.status_code == 201, uploaded.text
    bundle["storage"].publish(path, report["package_sha256"])
    peer = bundle | {"package": uploaded.json(), "manifest": data, "contract": contract, "path": path}
    plan = prepare(actors, peer)
    approve(actors, plan)
    await apply(installer, peer, plan)
    installation = installed(actors, data["module"]["id"])
    control_deploy(actors, installation, host, "start")  # Legacy offline profile stays offline.
    return runtime_status(actors, installation["id"])


async def test_real_company_business_request_in_isolated_signed_runtime(
    stack, actors, tenants, installer, runtime_bundle, live_agent, runtime_engine, tmp_path
):
    bundle, engine = runtime_bundle, runtime_engine
    host, launch, deployment_processes = live_agent
    plan = prepare(actors, bundle)
    assert plan["plan"]["module_api"]["required_profile"] == "module-api-private-v1"
    approve(actors, plan)
    await apply(installer, bundle, plan)
    installation = installed(actors, bundle["manifest"]["module"]["id"])
    identity = gateway_identity(stack)
    bound = admin(
        actors,
        "POST",
        f"/deployment-hosts/{host['id']}/gateway-identity",
        json={"issuer": stack["issuer"], "subject": identity["subject"], "client_id": identity["client_id"]},
    )
    assert bound.status_code == 201, bound.text
    deploy(actors, installation, host)
    plan = prepare(actors, bundle, "enable", installation["generation"])
    approve(actors, plan)
    await apply(installer, bundle, plan)
    installation = installed(actors, bundle["manifest"]["module"]["id"])
    environment = {k: os.environ[k] for k in ("PATH", "LANG") if k in os.environ}
    values = {
        "CORE_URL": stack["config"]["PUBLIC_URL"],
        "ISSUER": stack["issuer"],
        "CLIENT_ID": identity["client_id"],
        "CLIENT_SECRET": identity["secret"],
        "HOST_ID": host["id"],
        "ENGINE_SOCKET": str(engine.socket),
        "ENGINE_ID": engine.expected_id,
        "STORAGE_ROOT": host["storage_root"],
        "ISOLATED_HTTP": "true",
    }
    environment.update({"XARIONIX_GATEWAY_" + k: v for k, v in values.items()})

    def launch_gateway():
        return subprocess.Popen(
            [sys.executable, "-m", "scripts.gateway_agent"],
            cwd=managed.ROOT,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    process = launch_gateway()
    module = bundle["manifest"]["module"]["id"]
    a, b = tenants["alice"], tenants["bob"]
    call = actors["request"]

    def operation(actor, company, operation="items-read", body=None, **kwargs):
        return call(
            actor,
            "POST",
            f"/companies/{company}/modules/{module}/operations/{operation}",
            json=body or {},
            **kwargs,
        )

    try:
        # Platform administration and company ownership never imply module permissions.
        assert operation("admin", a).status_code == 404
        assert operation("alice", a).status_code == 403
        assert operation("alice", b).status_code == 404
        for label, cid in (("alice", a), ("bob", b)):
            role = new_role(
                actors, cid, ["hello.items.read", "hello.items.create", "hello.status.read"], actor=label
            )
            members = call(label, "GET", f"/companies/{cid}/members").json()["items"]
            own = next(m["id"] for m in members if m["user_id"] == actors["identities"][label]["user_id"])
            assert grant(actors, cid, own, role["id"], actor=label).status_code == 204
        deadline = time.monotonic() + 20
        while True:
            response = operation("alice", a, "status-read")
            if response.status_code != 503 or time.monotonic() >= deadline:
                break
            assert process.poll() is None, "Real Gateway Agent terminated"
            await asyncio.sleep(0.2)
        assert response.status_code == 200, response.text
        proof = response.json()["body"]
        assert proof["request_id"] == response.json()["request_id"] and proof["process_nonce"]
        timings = []
        for label, cid, name in (("alice", a, "item-a1"), ("bob", b, "item-b1")):
            started = time.monotonic()
            response = operation(label, cid, "items-create", {"name": name})
            timings.append(time.monotonic() - started)
            assert response.status_code == 200, response.text
            data = response.json()["body"]
            assert data["company_id"] == cid and data["actor_id"] == actors["identities"][label]["user_id"]
            assert [i["name"] for i in data["items"]] == [name]
        response = operation(
            "alice", a, headers={"X-Company-Id": b, "X-User-Id": actors["identities"]["bob"]["user_id"]}
        )
        assert response.status_code == 200 and response.json()["body"]["company_id"] == a
        assert [i["name"] for i in response.json()["body"]["items"]] == ["item-a1"]
        member = join(actors, a)
        read = new_role(actors, a, ["hello.items.read"])
        assert grant(actors, a, member, read["id"]).status_code == 204
        assert operation("carol", a).status_code == 200
        assert (
            call(
                "alice", "PATCH", f"/companies/{a}/members/{member}", json={"status": "suspended"}
            ).status_code
            == 200
        )
        assert operation("carol", a).status_code == 404
        assert (
            call("alice", "PATCH", f"/companies/{a}/members/{member}", json={"status": "active"}).status_code
            == 200
        )
        assert operation("carol", a).status_code == 200
        assert call("alice", "PATCH", f"/companies/{a}", json={"status": "suspended"}).status_code == 200
        assert operation("alice", a).status_code == 403
        assert call("alice", "PATCH", f"/companies/{a}", json={"status": "active"}).status_code == 200
        assert operation("carol", a, "items-create", {"name": "denied"}).status_code == 403
        assert (
            call("alice", "DELETE", f"/companies/{a}/members/{member}/roles/{read['id']}").status_code == 204
        )
        assert operation("carol", a).status_code == 403
        assert operation("alice", a, "unknown-operation").status_code == 404
        status = runtime_status(actors, installation["id"])
        info = engine.inspect(status["container_id"])
        assert info["HostConfig"]["NetworkMode"] == "none" and info["Mounts"] == []
        assert not info["HostConfig"]["PortBindings"]
        measured = json.loads(
            engine.execute(
                info["Id"],
                "import socket,json,os; print(json.dumps({'interfaces':socket.if_nameindex(),'socket':os.path.exists('/var/run/docker.sock')}))",
            )
        )
        assert measured == {"interfaces": [[1, "lo"]], "socket": False}
        isolation = engine.execute(
            info["Id"],
            """import socket,json,os,http.client
denied={}
for label,address in [('postgres',('127.0.0.1',"""
            + str(stack["postgres_port"])
            + """)),
 ('keycloak_admin',('127.0.0.1',"""
            + str(int(stack["config"]["KEYCLOAK_PUBLIC_URL"].rsplit(":", 1)[1]))
            + """)),
 ('metadata',('169.254.169.254',80)),('external',('198.51.100.10',443))]:
 s=socket.socket(); s.settimeout(.25)
 try: denied[label]=s.connect_ex(address)!=0
 finally: s.close()
s=socket.socket(socket.AF_UNIX)
try:
 s.connect('/run/user/1000/docker.sock'); denied['engine']=False
except OSError: denied['engine']=True
finally: s.close()
denied['host_files']=not os.path.exists('/home/candy/.ssh')
c=http.client.HTTPConnection('127.0.0.1',8080,timeout=2); c.request('GET','/health/ready')
print(json.dumps({'denied':denied,'allowed_health':c.getresponse().status==200}))
""",
        )
        isolation = json.loads(isolation)
        assert isolation["allowed_health"] and all(isolation["denied"].values()), isolation
        # Agent reconnect never creates another container or loses the module process.
        process.terminate()
        process.wait(timeout=20)
        process = launch_gateway()
        await asyncio.sleep(1)
        response = operation("alice", a, "status-read")
        assert response.status_code == 200, response.text
        assert response.json()["body"]["process_nonce"] == proof["process_nonce"]
        rows = engine.call(
            "GET",
            "/containers/json",
            params={
                "all": "true",
                "filters": json.dumps({"label": ["io.xarionix.deployment.host=" + host["id"]]}),
            },
        )
        assert len(rows) == 1
        # Read-only control operations must retain the signed API binding as well.
        control_deploy(actors, installation, host, "inspect", profile="module-api-private-v1")
        response = operation("alice", a, "status-read")
        assert response.status_code == 200, response.text
        assert response.json()["body"]["process_nonce"] == proof["process_nonce"]

        # Real hostile/slow module output is bounded; the next healthy call recovers.
        engine.execute(
            info["Id"], "from pathlib import Path; Path('/tmp/gateway-fault').write_text('headers')"
        )
        response = operation("alice", a)
        assert response.status_code == 200, response.text
        assert not {"set-cookie", "location", "access-control-allow-origin"} & set(response.headers)
        engine.execute(
            info["Id"], "from pathlib import Path; Path('/tmp/gateway-fault').write_text('unicode')"
        )
        response = operation("alice", a)
        assert response.status_code == 200 and response.json()["body"]["unicode"] == "я" * 20000
        engine.execute(
            info["Id"], "from pathlib import Path; Path('/tmp/gateway-fault').write_text('unicode-request')"
        )
        response = operation("alice", a, body={"payload": "я" * 20000})
        assert response.status_code == 200, response.text
        assert response.json()["body"]["received_utf8_bytes"] == 40014
        engine.execute(
            info["Id"], "from pathlib import Path; Path('/tmp/gateway-fault').write_text('oversized')"
        )
        response = operation("alice", a)
        assert response.status_code == 502, response.text
        engine.execute(info["Id"], "from pathlib import Path; Path('/tmp/gateway-fault').write_text('slow')")
        started = time.monotonic()
        response = operation("alice", a)
        timeout_seconds = time.monotonic() - started
        assert response.status_code in {502, 504}, response.text
        assert timeout_seconds < 18
        engine.execute(info["Id"], "from pathlib import Path; Path('/tmp/gateway-fault').unlink()")
        assert operation("alice", a).status_code == 200

        # Revocation does not wait for remote work; late data is denied after execution.
        assert grant(actors, a, member, read["id"]).status_code == 204
        engine.execute(
            info["Id"], "from pathlib import Path; Path('/tmp/gateway-fault').write_text('paused')"
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(operation, "carol", a)
            deadline = time.monotonic() + 20
            while (
                engine.execute(
                    info["Id"], "from pathlib import Path; print(Path('/tmp/gateway-entered').exists())"
                ).strip()
                != b"True"
            ):
                assert time.monotonic() < deadline
                await asyncio.sleep(0.1)
            started = time.monotonic()
            assert (
                call("alice", "DELETE", f"/companies/{a}/members/{member}/roles/{read['id']}").status_code
                == 204
            )
            revoke_seconds = time.monotonic() - started
            assert revoke_seconds < 3, "Business wait must not hold a company transaction lock"
            engine.execute(
                info["Id"],
                "from pathlib import Path; Path('/tmp/gateway-release').touch(); Path('/tmp/gateway-fault').unlink()",
            )
            response = pending.result(timeout=20)
            assert response.status_code in {403, 504}, response.text
        engine.execute(
            info["Id"],
            "from pathlib import Path; Path('/tmp/gateway-entered').unlink(); Path('/tmp/gateway-release').unlink()",
        )

        # Kill Core DURING an actual write: delivery/result is unknown, never automatically replayed.
        engine.execute(
            info["Id"], "from pathlib import Path; Path('/tmp/gateway-fault').write_text('paused')"
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(operation, "alice", a, "items-create", {"name": "survived-core-restart"})
            deadline = time.monotonic() + 20
            while (
                engine.execute(
                    info["Id"], "from pathlib import Path; print(Path('/tmp/gateway-entered').exists())"
                ).strip()
                != b"True"
            ):
                assert time.monotonic() < deadline
                await asyncio.sleep(0.1)
            stack["execute"](["kill", "-s", "SIGKILL", "core"])
            stack["execute"](["up", "--no-deps", "-d", "--wait", "--wait-timeout", "60", "core"])
            engine.execute(
                info["Id"],
                "from pathlib import Path; Path('/tmp/gateway-release').touch(); Path('/tmp/gateway-fault').unlink()",
            )
            try:
                lost = pending.result(timeout=20)
                assert lost.status_code in {502, 503, 504}, lost.text
            except httpx.HTTPError:
                pass  # A killed process cannot return a response; the client must treat the write as unknown.

        def core_ready():
            result = httpx.get(stack["config"]["PUBLIC_URL"] + "/health/ready", timeout=5, trust_env=False)
            assert result.status_code == 200
            return True

        managed.poll(core_ready, timeout=60)
        deadline = time.monotonic() + 30
        while True:
            response = operation("alice", a, "status-read")
            if response.status_code != 503 or time.monotonic() >= deadline:
                break
            await asyncio.sleep(0.2)
        assert response.status_code == 200, response.text
        assert response.json()["body"]["process_nonce"] == proof["process_nonce"]
        assert sum(i["name"] == "survived-core-restart" for i in response.json()["body"]["items"]) == 1
        engine.execute(
            info["Id"],
            "from pathlib import Path; Path('/tmp/gateway-entered').unlink(); Path('/tmp/gateway-release').unlink()",
        )

        # Repeated actual read calls under concurrency, plus bounded process memory observation.
        def core_memory():
            value = stack["execute"](
                [
                    "exec",
                    "-T",
                    "core",
                    "python",
                    "-c",
                    "import json,pathlib; s=pathlib.Path('/proc/1/status').read_text().splitlines(); print(json.dumps({k:next(x.split(':')[1].strip() for x in s if x.startswith(k+':')) for k in ('VmRSS','VmHWM')}))",
                ]
            )
            return json.loads(value)

        memory_before = core_memory()
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as pool:
            reads = list(pool.map(lambda _: operation("alice", a), range(2)))
        concurrent_seconds = time.monotonic() - started
        assert all(r.status_code == 200 for r in reads), [r.status_code for r in reads]
        memory_after = core_memory()
        peer = await deploy_isolated_peer(actors, installer, bundle, host, tmp_path / "peer")
        probe = """import os,json,http.client
c=http.client.HTTPConnection('127.0.0.1',8080,timeout=2); c.request('GET','/version')
print(json.dumps({'namespace':os.readlink('/proc/self/ns/net'),'reply':json.loads(c.getresponse().read(4096))}))
"""
        self_probe = json.loads(engine.execute(info["Id"], probe))
        peer_probe = json.loads(engine.execute(peer["container_id"], probe))
        assert self_probe["namespace"] != peer_probe["namespace"]
        assert self_probe["reply"]["process_nonce"] == proof["process_nonce"]
        assert self_probe["reply"]["process_nonce"] != peer_probe["reply"]["process_nonce"]
        assert engine.inspect(peer["container_id"])["HostConfig"]["NetworkMode"] == "none"
        # Crash the process (exit=1), not an administrative Docker kill/manual stop.
        try:
            engine.execute(info["Id"], "import os,signal; os.kill(1,signal.SIGUSR1)")
        except EngineFailure:
            pass  # The signal may terminate the short exec along with its container namespace.
        wait_health(actors, installation["id"], "healthy", restarted=True)
        response = operation("alice", a, "status-read")
        assert response.status_code == 200, response.text
        assert response.json()["body"]["process_nonce"] != proof["process_nonce"]

        second = await asyncio.to_thread(publish_version_two, actors, bundle, engine, tmp_path / "version2")
        for target_bundle, action, runtime_action, op, permission, expected_version in (
            (second, "update", "upgrade", "status-read-v2", "hello.status_v2.read", "2.0.0"),
            (bundle, "rollback", "rollback", "status-read", "hello.status.read", "1.0.0"),
        ):
            installation = installed(actors, module)
            change = prepare(actors, target_bundle, action, installation["generation"])
            approve(actors, change)
            await apply(installer, target_bundle, change)
            installation = installed(actors, module)
            assert operation("alice", a).status_code in {403, 404, 409}
            control_deploy(actors, installation, host, runtime_action, profile="module-api-private-v1")
            enable = prepare(actors, target_bundle, "enable", installation["generation"])
            approve(actors, enable)
            await apply(installer, target_bundle, enable)
            assert operation("alice", a, op).status_code == 403  # New/retired epoch is never auto-granted.
            fresh = new_role(actors, a, [permission])
            members = call("alice", "GET", f"/companies/{a}/members").json()["items"]
            own = next(m["id"] for m in members if m["user_id"] == actors["identities"]["alice"]["user_id"])
            assert grant(actors, a, own, fresh["id"]).status_code == 204
            response = operation("alice", a, op)
            assert response.status_code == 200, response.text
            assert response.json()["body"]["version"] == expected_version
            retired_op = "status-read" if expected_version == "2.0.0" else "status-read-v2"
            assert operation("alice", a, retired_op).status_code == 404
        installation = installed(actors, module)
        disabled = prepare(actors, bundle, "disable", installation["generation"])
        approve(actors, disabled)
        await apply(installer, bundle, disabled)
        assert operation("alice", a).status_code in {403, 404, 409}
        wait_stopped(actors, installation["id"], "quarantined")
        installation = installed(actors, module)
        control_deploy(actors, installation, host, "start", profile="module-api-private-v1")
        enabled = prepare(actors, bundle, "enable", installation["generation"])
        approve(actors, enabled)
        await apply(installer, bundle, enabled)
        assert operation("alice", a, "status-read").status_code == 200
        # Gateway principal disable/re-enable is separate from irreversible publisher revocation.
        identity_path = f"/deployment-hosts/{host['id']}/gateway-identity"
        assert admin(actors, "PATCH", identity_path, json={"status": "disabled"}).status_code == 200
        assert operation("alice", a, "status-read").status_code in {403, 409}
        assert admin(actors, "PATCH", identity_path, json={"status": "active"}).status_code == 200
        deadline = time.monotonic() + 30
        while True:
            response = operation("alice", a, "status-read")
            if response.status_code == 200 or time.monotonic() >= deadline:
                break
            assert response.status_code in {503, 504}, response.text
            await asyncio.sleep(0.2)
        assert response.status_code == 200, response.text
        assert admin(actors, "POST", f"/package-publishers/{bundle['publisher']}/revoke").status_code == 200
        assert operation("alice", a, "status-read").status_code in {403, 409}
        wait_stopped(actors, installation["id"], "quarantined")
        target = managed.ROOT / "reports/gateway-benchmark.json"
        target.parent.mkdir(exist_ok=True)
        target.write_text(
            json.dumps(
                {
                    "real_container": True,
                    "write_latency_seconds": timings,
                    "network": "none",
                    "engine": "native-rootless",
                    "process_nonce": proof["process_nonce"],
                    "timeout_observed_seconds": timeout_seconds,
                    "revoke_during_dispatch_seconds": revoke_seconds,
                    "isolation": isolation,
                    "two_concurrent_reads_seconds": concurrent_seconds,
                    "core_memory_before": memory_before,
                    "core_memory_after": memory_after,
                    "separate_module_namespaces": True,
                }
            )
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
