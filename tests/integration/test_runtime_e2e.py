"""Positive runtime E2E on a dedicated native rootless engine, never a mock provider.

Set XARIONIX_RUN_RUNTIME_TESTS=1 and XARIONIX_RUNTIME_ENGINE_SOCKET to an EMPTY,
dedicated rootless daemon. The ordinary Docker context runs the disposable Core
stack and must be a DIFFERENT daemon. No production sockets/volumes are accepted.
"""

import asyncio
import ipaddress
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest
import test_managed_stack as managed
from runtime_helpers import runtime_package
from test_deployment_control import deployment_identity as deployment_identity
from test_deployment_control import image_archive as image_archive
from test_deployment_control import runtime_bundle as runtime_bundle
from test_module_installations import admin, apply, approve, installed, prepare
from test_module_installations import installer as installer

from scripts.deployment_agent.engine import Engine, EngineFailure

stack, actors = managed.stack, managed.actors
pytestmark = [pytest.mark.integration, pytest.mark.runtime]


@pytest.fixture(scope="module", autouse=True)
def runtime_opt_in():
    if os.environ.get("XARIONIX_RUN_RUNTIME_TESTS") != "1":
        pytest.skip("Native rootless runtime E2E is a separate required runtime-runner job")
    if sys.platform != "linux" or not os.environ.get("XARIONIX_RUNTIME_ENGINE_SOCKET"):
        pytest.fail("Runtime E2E requires Linux and an explicit dedicated rootless Unix socket")


@pytest.fixture(scope="module")
def runtime_engine(runtime_opt_in):
    socket = Path(os.environ["XARIONIX_RUNTIME_ENGINE_SOCKET"])
    with httpx.Client(transport=httpx.HTTPTransport(uds=str(socket)), trust_env=False) as client:
        response = client.get("http://engine/v1.52/info")
        response.raise_for_status()
        info = response.json()
    outer = subprocess.run(
        ["docker", "info", "--format", "{{.ID}}"], check=True, capture_output=True, text=True, timeout=20
    ).stdout.strip()
    assert info["ID"] != outer, "Runtime engine must not be the Core/DB stack engine"
    assert info["Containers"] == 0, "Refusing a nonempty engine: use a dedicated disposable runtime host"
    assert "name=rootless" in info["SecurityOptions"] and info["CgroupVersion"] == "2"
    assert all(info[k] for k in ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota")), (
        "Native delegated CPU/RAM/PID limits are mandatory; DinD flags alone are insufficient"
    )
    engine = Engine(socket, info["ID"])
    yield engine
    engine.close()


def runtime_status(actors, installation_id):
    result = admin(actors, "GET", "/runtime-deployments", params={"limit": 100})
    assert result.status_code == 200
    return next((r for r in result.json()["items"] if r["installation_id"] == installation_id), None)


def stack_address(stack, service):
    identifier = stack["execute"](["ps", "-q", service]).decode().strip()
    result = subprocess.run(
        [
            "docker",
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
            identifier,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return str(ipaddress.ip_address(result.stdout.split()[0]))


def wait_job(actors, identifier, job_id, *, success=True):
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        response = admin(actors, "GET", f"/runtime-deployments/{identifier}/jobs")
        assert response.status_code == 200
        job = next((j for j in response.json()["items"] if j["id"] == job_id), None)
        if job and job["state"] in {"succeeded", "failed", "cancelled", "expired"}:
            assert job["state"] == ("succeeded" if success else "failed"), job
            return job
        time.sleep(0.25)
    pytest.fail("Real Deployment Agent did not acknowledge the runtime job before its deadline")


def wait_health(actors, installation_id, expected, *, restarted=False):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status = runtime_status(actors, installation_id)
        if status and status["health"] == expected and (not restarted or status["restart_count"] >= 1):
            return status
        time.sleep(0.25)
    pytest.fail("Real runtime supervision did not converge to the expected health")


def publish_runtime(actors, bundle, folder, source, *, version, module=None, namespace=None):
    from app.domains.deployments.artifacts import validate_runtime
    from app.domains.packages.archive import verify

    private = bundle["path"].parent / "private.key"
    publisher = json.loads((bundle["path"].parent / "manifest.json").read_text())["publisher"]["id"]
    module, namespace = module or bundle["manifest"]["module"]["id"], namespace or bundle["namespace"]
    path, trust, report, contract = runtime_package(
        folder,
        source=source,
        module=module,
        namespace=namespace,
        publisher=publisher,
        version=version,
        key=private,
    )
    started = time.monotonic()
    checked = verify(path, trust)
    assert checked.core_compatible and validate_runtime(path, checked.manifest).model_dump() == contract
    verification_seconds = time.monotonic() - started
    uploaded = admin(
        actors,
        "POST",
        "/packages",
        headers={"Content-Type": "application/octet-stream"},
        content=path.read_bytes(),
    )
    assert uploaded.status_code == 201, uploaded.text
    bundle["storage"].publish(path, report["package_sha256"])
    return {
        "package": uploaded.json(),
        "manifest": {"module": {"id": module}},
        "storage": bundle["storage"],
        "contract": contract,
        "namespace": namespace,
        "verification_seconds": verification_seconds,
    }


async def build_version(actors, bundle, folder, version, *, ready=True):
    tag = "xarionix-hello:variant-" + uuid.uuid4().hex[:12]
    folder.mkdir()
    archive = folder / "image.tar"
    try:
        await asyncio.to_thread(
            subprocess.run,
            [
                "docker",
                "build",
                "--tag",
                tag,
                "--build-arg",
                "HELLO_VERSION=" + version,
                "--build-arg",
                "HELLO_READY=" + str(ready).lower(),
                "examples/modules/hello-runtime",
            ],
            cwd=managed.ROOT,
            check=True,
            capture_output=True,
            timeout=300,
        )
        await asyncio.to_thread(
            subprocess.run,
            ["docker", "save", "--output", str(archive), tag],
            check=True,
            capture_output=True,
            timeout=120,
        )
        return publish_runtime(actors, bundle, folder / "package", archive, version=version)
    finally:
        await asyncio.to_thread(
            subprocess.run, ["docker", "image", "rm", tag], capture_output=True, timeout=30
        )


def deploy(actors, installation, host, operation, *, success=True):
    # Metadata changes can legitimately queue a safety stop concurrently. Wait
    # for it, then explicitly prepare/approve a FRESH snapshot; never retry a
    # queued execution or reuse approval across generations.
    for _ in range(4):
        history = admin(actors, "GET", f"/runtime-deployments/{installation['id']}/jobs").json()["items"]
        for active in (j for j in history if j["state"] in {"queued", "leased"}):
            assert active["operation"] in {"quarantine", "retire"}
            wait_job(actors, installation["id"], active["id"])
        current = runtime_status(actors, installation["id"])
        prepared = admin(
            actors,
            "POST",
            "/deployment-plans",
            json={
                "idempotency_key": str(uuid.uuid4()),
                "installation_id": installation["id"],
                "host_id": host["id"],
                "operation": operation,
                "expected_installation_generation": installation["generation"],
                "expected_deployment_generation": current["generation"] if current else 0,
            },
        )
        if (
            prepared.status_code == 409
            and prepared.json()["detail"]["code"] == "deployment_generation_conflict"
        ):
            continue
        assert prepared.status_code == 201, prepared.text
        plan = prepared.json()
        result = admin(
            actors, "POST", f"/deployment-plans/{plan['id']}/approve", json={"digest": plan["digest"]}
        )
        if result.status_code == 409 and result.json()["detail"]["code"] in {
            "deployment_generation_conflict",
            "deployment_operation_in_progress",
            "deployment_plan_stale",
        }:
            continue
        assert result.status_code == 200, result.text
        return wait_job(actors, installation["id"], result.json()["job_id"], success=success)
    pytest.fail("Safety reconciliation did not stabilize before fresh explicit approval")


def wait_stopped(actors, identifier, desired):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        row = runtime_status(actors, identifier)
        if (
            row
            and row["desired"] == desired
            and row["observed"] == "stopped"
            and row["generation"] == row["observed_generation"]
        ):
            return row
        time.sleep(0.25)
    pytest.fail("Security stop was not physically acknowledged by the real agent")


@pytest.fixture
def live_agent(stack, actors, deployment_identity, runtime_engine, runtime_bundle, tmp_path):
    identifier = str(uuid.uuid4())
    identity, engine = deployment_identity, runtime_engine
    registered = admin(
        actors,
        "POST",
        "/deployment-hosts",
        json={
            "id": identifier,
            "name": "Native isolated E2E host",
            "issuer": stack["issuer"],
            "subject": identity["subject"],
            "client_id": identity["client_id"],
            "engine_id": engine.expected_id,
            "platform": runtime_bundle["contract"]["platform"],
        },
    )
    assert registered.status_code == 201, registered.text
    state = tmp_path / "agent-state"
    # Do not inherit CI/DB/Core/admin secrets into the real separate agent process.
    environment = {key: os.environ[key] for key in ("PATH", "LANG") if key in os.environ}
    values = {
        "CORE_URL": stack["config"]["PUBLIC_URL"],
        "ISSUER": stack["issuer"],
        "CLIENT_ID": identity["client_id"],
        "CLIENT_SECRET": identity["secret"],
        "HOST_ID": identifier,
        "ENGINE_SOCKET": str(Path(os.environ["XARIONIX_RUNTIME_ENGINE_SOCKET"])),
        "ENGINE_ID": engine.expected_id,
        "STORAGE_ROOT": str(state),
        "ISOLATED_HTTP": "true",
    }
    environment.update({"XARIONIX_DEPLOYMENT_" + key: value for key, value in values.items()})

    def launch():
        return subprocess.Popen(
            [sys.executable, "-m", "scripts.deployment_agent"],
            cwd=managed.ROOT,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    process = launch()
    running = [process]
    target = registered.json()
    target["storage_root"] = str(state)
    try:
        yield target, launch, running
    finally:
        for child in running:
            child.terminate()
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        # Only this test's registered host is touched; no global prune or volume removal.
        rows = engine.call(
            "GET",
            "/containers/json",
            params={
                "all": "true",
                "filters": json.dumps({"label": ["io.xarionix.deployment.host=" + identifier]}),
            },
        )
        for row in rows:
            engine.stop(row["Id"])
            engine.call("DELETE", "/containers/" + row["Id"], params={"v": "false"})


async def test_real_agent_offline_artifact_isolation_lifecycle_upgrade_rollback_and_recovery(
    stack, actors, installer, runtime_bundle, live_agent, runtime_engine, image_archive, tmp_path
):
    bundle, engine = runtime_bundle, runtime_engine
    target, launch, processes = live_agent
    plan = prepare(actors, bundle)
    approve(actors, plan)
    await apply(installer, bundle, plan)
    installation = installed(actors, bundle["manifest"]["module"]["id"])
    timings = {}

    for operation, state in (
        ("provision", "stopped"),
        ("start", "running"),
        ("stop", "stopped"),
        ("start", "running"),
        ("restart", "running"),
    ):
        start = time.monotonic()
        job = deploy(actors, installation, target, operation)
        timings[operation] = round(time.monotonic() - start, 3)
        assert job["result"]["report"]["state"] == state
    preserved_data = (
        Path(target["storage_root"]) / "installations" / installation["id"] / "data" / "preserved.txt"
    )
    preserved_data.write_text("test user data, never a cleanup target")
    status = runtime_status(actors, installation["id"])
    assert status["health"] == "healthy" and status["image_digest"] == bundle["contract"]["image_digest"]
    container = engine.inspect(status["container_id"])
    assert container["HostConfig"]["NetworkMode"] == "none"
    assert container["Mounts"] == [] and container["HostConfig"]["PortBindings"] in (None, {})
    assert not any("XARIONIX" in value or "SECRET" in value for value in container["Config"]["Env"])
    # These execute in the actual runtime namespace, with actual cgroup enforcement.
    assert (
        json.loads(engine.execute(container["Id"], "import os,json; print(json.dumps(os.getuid()))")) == 10001
    )
    assert (
        engine.execute(
            container["Id"], "import pathlib; assert not pathlib.Path('/var/run/docker.sock').exists()"
        )
        == b""
    )
    assert (
        engine.execute(
            container["Id"],
            "import pathlib; p=pathlib.Path('/etc/probe');\ntry: p.touch()\nexcept OSError: pass\nelse: raise AssertionError('writable root')",
        )
        == b""
    )
    for service, port in (("postgres", 5432), ("keycloak", 8080)):
        hostname = await asyncio.to_thread(stack_address, stack, service)
        source = f"import socket\ntry: socket.create_connection(({hostname!r},{port}),timeout=1)\nexcept OSError: pass\nelse: raise AssertionError('network escaped')"
        assert engine.execute(container["Id"], source) == b""
    enable = prepare(actors, bundle, "enable", installation["generation"])
    approve(actors, enable)
    await apply(installer, bundle, enable)
    installation = installed(actors, bundle["manifest"]["module"]["id"])
    with managed.sql_connection(stack) as db:
        assert db.execute("SELECT core_module_available(%s,90)", (bundle["namespace"],)).fetchone() == (True,)

    # A killed agent recovers from its durable journal; it does not duplicate the runtime.
    processes[-1].terminate()
    processes[-1].wait(timeout=15)
    before = status["container_id"]
    started_reconcile = time.monotonic()
    processes.append(launch())
    job = deploy(actors, installation, target, "reconcile")
    assert job["result"]["report"]["container_id"] == before
    timings["reconcile_after_restart"] = round(time.monotonic() - started_reconcile, 3)

    # Health is supervised after ACK; an unhealthy process does not retain RBAC.
    current = runtime_status(actors, installation["id"])
    engine.execute(current["container_id"], "from pathlib import Path; Path('/tmp/not-ready').touch()")
    wait_health(actors, installation["id"], "unhealthy")
    with managed.sql_connection(stack) as db:
        assert db.execute("SELECT core_module_available(%s,90)", (bundle["namespace"],)).fetchone() == (
            False,
        )
    engine.execute(current["container_id"], "from pathlib import Path; Path('/tmp/not-ready').unlink()")
    wait_health(actors, installation["id"], "healthy")
    # Docker API kill is a manual stop, not an application crash, and intentionally
    # suppresses restart policy. Make the demo PID 1 itself exit nonzero instead.
    try:
        engine.execute(current["container_id"], "import os,signal; os.kill(1,signal.SIGUSR1)")
    except EngineFailure:
        pass  # The crashing PID namespace may terminate this exec too.
    wait_health(actors, installation["id"], "healthy", restarted=True)

    # Two independent installations on one host, no accidental singleton runtime.
    other_namespace = bundle["namespace"] + "b"
    assert (
        admin(
            actors,
            "PUT",
            f"/package-publishers/{bundle['publisher']}/namespaces",
            json={"namespaces": [bundle["namespace"], other_namespace]},
        ).status_code
        == 200
    )
    other = publish_runtime(
        actors,
        bundle,
        tmp_path / "other",
        image_archive,
        version="1.0.0",
        module=installation["module_id"] + "-two",
        namespace=other_namespace,
    )
    plan = prepare(actors, other)
    approve(actors, plan)
    await apply(installer, other, plan)
    other_installation = installed(actors, other["manifest"]["module"]["id"])
    other_job = deploy(actors, other_installation, target, "start")
    assert other_job["result"]["report"]["container_id"] != current["container_id"]
    timings["artifact_verification"] = round(other["verification_seconds"], 3)

    async def metadata(target_bundle, action):
        current_installation = installed(actors, installation["module_id"])
        plan = prepare(actors, target_bundle, action, current_installation["generation"])
        approve(actors, plan)
        await apply(installer, target_bundle, plan)
        return installed(actors, installation["module_id"])

    second = await build_version(actors, bundle, tmp_path / "v2", "2.0.0")
    installation = await metadata(second, "update")
    upgrade = deploy(actors, installation, target, "upgrade")
    assert (
        upgrade["result"]["report"]["image_digest"]
        == second["contract"]["image_digest"]
        != bundle["contract"]["image_digest"]
    )
    installation = await metadata(bundle, "rollback")
    rollback = deploy(actors, installation, target, "rollback")
    assert rollback["result"]["report"]["image_digest"] == bundle["contract"]["image_digest"]

    # A signed but permanently unready version must fail BOTH upgrade and rollback.
    broken = await build_version(actors, bundle, tmp_path / "v3", "3.0.0", ready=False)
    installation = await metadata(broken, "update")
    failed = deploy(actors, installation, target, "upgrade", success=False)
    assert failed["result"]["report"]["safe_error_code"] == "health_failed"
    good = await build_version(actors, bundle, tmp_path / "v4", "4.0.0")
    installation = await metadata(good, "update")
    deploy(actors, installation, target, "upgrade")
    installation = await metadata(broken, "rollback")
    failed = deploy(actors, installation, target, "rollback", success=False)
    assert failed["result"]["report"]["safe_error_code"] == "health_failed"
    installation = await metadata(good, "rollback")
    deploy(actors, installation, target, "rollback")
    # A terminal publisher revoke closes RBAC immediately and physically stops
    # BOTH real runtimes, without temporarily restoring trust for cleanup.
    assert admin(actors, "POST", f"/package-publishers/{bundle['publisher']}/revoke").status_code == 200
    with managed.sql_connection(stack) as db:
        assert db.execute("SELECT core_module_available(%s,90)", (bundle["namespace"],)).fetchone() == (
            False,
        )
    wait_stopped(actors, installation["id"], "quarantined")
    wait_stopped(actors, other_installation["id"], "quarantined")
    result = admin(
        actors,
        "POST",
        f"/module-installations/{installation['id']}/retire",
        json={"expected_installation_generation": installation["generation"], "state": "retired"},
    )
    assert result.status_code == 200, result.text
    wait_stopped(actors, installation["id"], "retired")
    deploy(actors, other_installation, target, "deprovision")
    deploy(actors, installation, target, "deprovision")
    assert preserved_data.read_text() == "test user data, never a cleanup target"
    assert runtime_status(actors, installation["id"])["observed"] == "not_provisioned"
    with managed.sql_connection(stack) as db:
        assert (
            db.execute(
                "SELECT count(*) FROM deployment_jobs WHERE installation_id=%s", (installation["id"],)
            ).fetchone()[0]
            >= 10
        )
        assert db.execute(
            "SELECT count(*) FROM module_installations WHERE id=%s", (installation["id"],)
        ).fetchone() == (1,)
        assert (
            db.execute(
                "SELECT count(*) FROM audit_events WHERE resource_id=%s", (installation["id"],)
            ).fetchone()[0]
            > 0
        )
    print("Real local runtime timings (seconds, not SLA):", json.dumps(timings, sort_keys=True))
    benchmark_report = managed.ROOT / "reports/runtime-benchmark.json"
    benchmark_report.parent.mkdir(parents=True, exist_ok=True)
    benchmark_report.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "scope": "disposable-local-not-sla",
                "platform": bundle["contract"]["platform"],
                "independent_installations": 2,
                "seconds": timings,
            },
            sort_keys=True,
        )
    )
