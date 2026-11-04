import json
import socket
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from app.domains.deployments.contracts import PROFILES, Delivery
from scripts.deployment_agent.engine import HEALTH_PROBE, ISOLATION_PROBE, Engine, EngineFailure
from scripts.deployment_agent.protocol import Config, Protocol, ProtocolFailure, Rejected
from scripts.deployment_agent.state import State


@pytest.fixture
def delivery():
    return Delivery(
        id=uuid.uuid4(),
        fence=uuid.uuid4(),
        host_id=uuid.uuid4(),
        installation_id=uuid.uuid4(),
        operation="start",
        generation=1,
        lease_until=datetime.now(UTC) + timedelta(seconds=120),
        package_sha256="a" * 64,
        package_size=100,
        runtime={
            "schema_version": 1,
            "engine": "oci",
            "platform": "linux/amd64",
            "image_digest": "sha256:" + "a" * 64,
            "config_digest": "sha256:" + "b" * 64,
            "health_contract": "http-python-v1",
            "health_port": 8080,
        },
        profile="offline-small-v1",
        engine_id="dedicated-test-engine",
        trust={"schema_version": 1, "keys": []},
    )


class Docker:
    def __init__(self, job):
        self.job, self.containers, self.calls = job, {}, []
        self.healthy, self.loaded = True, True
        self.containerd = False
        self.empty_exec_stream = False
        self.manifest_digest = job.runtime.image_digest
        self.info = {
            "ID": job.engine_id,
            "SecurityOptions": ["name=rootless", "name=seccomp,profile=builtin"],
            "Architecture": "x86_64",
            "CgroupVersion": "2",
            "MemoryLimit": True,
            "SwapLimit": True,
            "PidsLimit": True,
            "CpuCfsQuota": True,
        }
        limits = PROFILES[job.profile]
        self.measured = {
            "uid": 10001,
            "caps": "0" * 16,
            "nnp": "1",
            "seccomp": "2",
            "memory": str(limits["memory"]),
            "swap": "0",
            "pids": str(limits["pids"]),
            "cpu": f"{limits['cpu_quota']} 100000",
        }
        self.execs = {}

    def handle(self, request):
        path = request.url.path.removeprefix("/v1.52")
        self.calls.append((request.method, path))
        data = json.loads(request.content) if request.content and path != "/images/load" else {}
        if path == "/info":
            return httpx.Response(200, json=self.info)
        if path == "/images/load":
            self.loaded = True
            return httpx.Response(200, content=b'{"stream":"loaded"}\n')
        if path.startswith("/images/"):
            return (
                httpx.Response(
                    200,
                    json={
                        "Id": self.job.runtime.image_digest
                        if self.containerd
                        else self.job.runtime.config_digest,
                        **({"Descriptor": {"digest": self.manifest_digest}} if self.containerd else {}),
                        "Os": "linux",
                        "Architecture": "amd64",
                        "Config": {"Env": ["MODULE_DEFAULT=public"]},
                    },
                )
                if self.loaded
                else httpx.Response(404)
            )
        if path == "/containers/json":
            return httpx.Response(
                200, json=[{"Id": k, "Labels": v["Config"]["Labels"]} for k, v in self.containers.items()]
            )
        if path == "/containers/create":
            identifier = f"{len(self.containers) + 1:064x}"
            config = {k: v for k, v in data.items() if k != "HostConfig"}
            config["Env"] = ["MODULE_DEFAULT=public"]
            self.containers[identifier] = {
                "Id": identifier,
                "Image": data["Image"],
                "Config": config,
                "HostConfig": data["HostConfig"],
                "State": {"Running": False},
                "RestartCount": 0,
                "Mounts": [],
            }
            return httpx.Response(201, json={"Id": identifier})
        if path.startswith("/exec/"):
            key = path.split("/")[2]
            source = self.execs[key]
            if path.endswith("/json"):
                return httpx.Response(
                    200,
                    json={
                        "Running": False,
                        "ExitCode": 0 if source == ISOLATION_PROBE or self.healthy else 1,
                    },
                )
            content = json.dumps(self.measured).encode() if source == ISOLATION_PROBE else b""
            if not content and self.empty_exec_stream:
                return httpx.Response(200, content=b"")
            header = b"\x01\x00\x00\x00" + len(content).to_bytes(4, "big")
            return httpx.Response(200, content=header + content)
        if path.startswith("/containers/"):
            identifier = path.split("/")[2]
            if request.method == "DELETE":
                self.containers.pop(identifier, None)
                return httpx.Response(204)
            if identifier not in self.containers:
                return httpx.Response(404)
            if path.endswith("/json"):
                return httpx.Response(200, json=self.containers[identifier])
            if path.endswith("/exec"):
                key = "exec-" + str(len(self.execs) + 1)
                assert data["Cmd"][:3] == ["/usr/local/bin/python", "-I", "-c"]
                assert data["Cmd"][3] in {ISOLATION_PROBE, HEALTH_PROBE}
                self.execs[key] = data["Cmd"][3]
                return httpx.Response(201, json={"Id": key})
            if path.endswith("/start"):
                self.containers[identifier]["State"]["Running"] = True
                return httpx.Response(204)
            if path.endswith("/stop"):
                self.containers[identifier]["State"]["Running"] = False
                return httpx.Response(204)
        raise AssertionError((request.method, path))


@pytest.fixture
def engine(delivery):
    fake = Docker(delivery)
    engine = Engine.__new__(Engine)
    engine.expected_id = delivery.engine_id
    engine.client = httpx.Client(
        transport=httpx.MockTransport(fake.handle), base_url="http://deployment-engine/v1.52"
    )
    yield engine, fake
    engine.close()


def test_rootless_identity_and_every_required_control_are_checked(engine, delivery):
    adapter, fake = engine
    adapter.available(delivery)
    for key in ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota"):
        fake.info[key] = False
        with pytest.raises(EngineFailure, match="isolation_unavailable"):
            adapter.available(delivery)
        fake.info[key] = True
    fake.info["SecurityOptions"] = ["name=seccomp"]
    with pytest.raises(EngineFailure, match="rootless_engine_required"):
        adapter.available(delivery)
    fake.info["ID"] = "different-engine"
    with pytest.raises(EngineFailure, match="identity_mismatch"):
        adapter.available(delivery)


def test_engine_with_unrelated_workloads_is_not_a_dedicated_runtime_engine(engine, delivery):
    adapter, fake = engine
    fake.containers["f" * 64] = {"Config": {"Labels": {}}}
    with pytest.raises(EngineFailure, match="dedicated_engine_required"):
        adapter.available(delivery)


@pytest.mark.parametrize("failure", [None, "isolation_unavailable"])
def test_read_only_operator_preflight_never_mutates_or_prints_credentials(monkeypatch, capsys, failure):
    from unittest.mock import MagicMock

    from scripts.deployment_agent import preflight

    adapter = MagicMock()
    if failure:
        adapter.available.side_effect = EngineFailure(failure)
    monkeypatch.setattr(preflight, "Engine", lambda *args: adapter)
    monkeypatch.setattr(
        "sys.argv",
        [
            "preflight",
            "--socket",
            "/run/user/1000/test.sock",
            "--engine-id",
            "test-engine",
            "--host-id",
            str(uuid.uuid4()),
            "--platform",
            "linux/amd64",
        ],
    )
    assert preflight.main() == (2 if failure else 0)
    value = json.loads(capsys.readouterr().out)
    assert value["ready"] is (failure is None)
    adapter.available.assert_called_once()
    adapter.apply.assert_not_called()
    adapter.close.assert_called_once()


@pytest.mark.parametrize("operation", ["start", "provision", "upgrade", "rollback", "reconcile"])
def test_isolated_creation_and_duplicate_start_have_one_container(engine, delivery, operation):
    adapter, fake = engine
    job = delivery.model_copy(update={"operation": operation})
    calls = []
    first = adapter.apply(job, lambda: calls.append("authorize"))
    second = adapter.apply(job, lambda: calls.append("authorize"))
    assert len(fake.containers) == 1 and first.container_id == second.container_id
    assert first.health == ("unknown" if operation == "provision" else "healthy")
    actual = next(iter(fake.containers.values()))
    assert actual["HostConfig"]["NetworkMode"] == "none"
    assert actual["HostConfig"]["ReadonlyRootfs"] and actual["Config"]["User"] == "10001:10001"
    assert actual["Config"]["Env"] == ["MODULE_DEFAULT=public"]
    assert len(calls) >= 2


def test_containerd_manifest_identity_and_classic_config_identity_are_both_pinned(engine, delivery):
    adapter, fake = engine
    fake.containerd = True
    report = adapter.apply(delivery, lambda: None)
    assert report.health == "healthy"
    assert next(iter(fake.containers.values()))["Image"] == delivery.runtime.image_digest
    fake.manifest_digest = "sha256:" + "f" * 64
    with pytest.raises(EngineFailure, match="image_identity_mismatch"):
        adapter.report(delivery)


def test_successful_exec_without_stdout_is_not_a_failed_health_check(engine, delivery):
    adapter, fake = engine
    fake.empty_exec_stream = True
    assert adapter.apply(delivery, lambda: None).health == "healthy"


@pytest.mark.parametrize("operation", ["stop", "quarantine", "retire", "deprovision"])
def test_safety_operations_do_not_require_trust_or_working_cgroup_support(engine, delivery, operation):
    adapter, fake = engine
    adapter.apply(delivery, lambda: None)
    fake.info["MemoryLimit"] = False
    report = adapter.apply(delivery.model_copy(update={"operation": operation}), lambda: None)
    assert report.state == ("not_provisioned" if operation == "deprovision" else "stopped")
    assert len(fake.containers) == (0 if operation == "deprovision" else 1)
    if fake.containers:
        assert not next(iter(fake.containers.values()))["State"]["Running"]


def test_inspect_is_read_only_and_restart_does_not_provision_missing_container(engine, delivery):
    adapter, fake = engine
    assert (
        adapter.apply(delivery.model_copy(update={"operation": "inspect"}), lambda: None).state
        == "not_provisioned"
    )
    assert not any(method in {"POST", "DELETE"} for method, path in fake.calls)
    with pytest.raises(EngineFailure, match="runtime_missing"):
        adapter.apply(delivery.model_copy(update={"operation": "restart"}), lambda: None)
    adapter.apply(delivery, lambda: None)
    before = len(fake.containers)
    adapter.apply(delivery.model_copy(update={"operation": "restart"}), lambda: None)
    assert len(fake.containers) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("uid", 0),
        ("caps", "0000000000000001"),
        ("nnp", "0"),
        ("seccomp", "0"),
        ("memory", "max"),
        ("swap", "max"),
        ("pids", "max"),
        ("cpu", "max 100000"),
    ],
)
def test_actual_kernel_controls_must_match_approved_limits(engine, delivery, field, value):
    adapter, fake = engine
    adapter.apply(delivery, lambda: None)
    fake.measured[field] = value
    with pytest.raises(EngineFailure, match="isolation_unavailable"):
        adapter.report(delivery)


def test_failed_post_start_isolation_probe_stops_unacknowledged_container(engine, delivery):
    adapter, fake = engine
    fake.measured["memory"] = "max"
    with pytest.raises(EngineFailure, match="isolation_unavailable"):
        adapter.apply(delivery, lambda: None)
    assert len(fake.containers) == 1
    assert not next(iter(fake.containers.values()))["State"]["Running"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("NetworkMode", "host"),
        ("Privileged", True),
        ("ReadonlyRootfs", False),
        ("CapDrop", []),
        ("SecurityOpt", []),
        ("SecurityOpt", ["no-new-privileges", "seccomp=unconfined"]),
        ("CapAdd", ["SYS_ADMIN"]),
        ("CgroupnsMode", "host"),
        ("Tmpfs", {"/etc": "rw,size=64m"}),
        ("Memory", 0),
        ("CpuQuota", 0),
        ("CpuPeriod", 0),
        ("PidsLimit", 0),
        ("Binds", ["/var/run/docker.sock:/var/run/docker.sock"]),
        ("Devices", [{}]),
        ("DeviceRequests", [{}]),
        ("PortBindings", {"8080/tcp": [{}]}),
        ("PidMode", "host"),
        ("IpcMode", "host"),
    ],
)
def test_inspect_rejects_changed_security_configuration(engine, delivery, field, value):
    adapter, fake = engine
    adapter.apply(delivery, lambda: None)
    next(iter(fake.containers.values()))["HostConfig"][field] = value
    with pytest.raises(EngineFailure, match="isolation_unavailable"):
        adapter.report(delivery)


def test_approval_is_rechecked_before_mutating_engine(engine, delivery):
    adapter, fake = engine

    def rejected():
        raise Rejected("policy_changed")

    with pytest.raises(Rejected):
        adapter.apply(delivery, rejected)
    assert not fake.containers


def test_unhealthy_readiness_does_not_report_healthy(engine, delivery, monkeypatch):
    adapter, fake = engine
    fake.healthy = False
    moments = iter([0, 100])
    monkeypatch.setattr("scripts.deployment_agent.engine.time.monotonic", lambda: next(moments))
    with pytest.raises(EngineFailure, match="health_failed"):
        adapter.apply(delivery, lambda: None)
    assert not next(iter(fake.containers.values()))["State"]["Running"]


def test_durable_sequence_fencing_duplicate_receipt_and_restart(tmp_path, delivery):
    root = (tmp_path / "agent").resolve()
    state = State(root)
    assert state.sequence() == 1 and state.accept(delivery) is None
    state.completed(delivery, {"success": True})
    assert state.accept(delivery) == {"success": True}
    state.close()
    state = State(root)
    try:
        assert state.sequence() == 2
        assert state.jobs()[0].id == delivery.id
        with pytest.raises(ValueError, match="identity_conflict"):
            state.accept(delivery.model_copy(update={"id": uuid.uuid4()}))
        state.accept(delivery.model_copy(update={"id": uuid.uuid4(), "generation": 2}))
        with pytest.raises(ValueError, match="stale_generation"):
            state.accept(delivery)
        with pytest.raises(BlockingIOError):
            State(root)
    finally:
        state.close()


def test_installation_storage_is_private_separate_and_staging_cleanup_preserves_data(tmp_path, delivery):
    state = State((tmp_path / "agent").resolve())
    try:
        first = state.workspace(delivery.installation_id)
        second = state.workspace(uuid.uuid4())
        assert first != second and first.stat().st_mode & 0o077 == 0
        data = first / "data" / "preserved.txt"
        data.write_text("user-owned test data")
        (first / "cache" / "package.xpkg").write_bytes(b"partial untrusted staging")
        state.clear_staging(delivery.installation_id)
        assert data.read_text() == "user-owned test data"
        assert not (first / "cache" / "package.xpkg").exists()
        other = first / "cache" / "image.tar"
        other.symlink_to(data)
        with pytest.raises(ValueError, match="staging_denied"):
            state.clear_staging(delivery.installation_id)
        assert data.exists()
    finally:
        state.close()


def test_state_and_engine_refuse_symlinks_and_server_socket(tmp_path):
    root = tmp_path / "real"
    root.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError):
        State(link)
    for path in (Path("/var/run/docker.sock"), Path("/run/docker.sock"), Path("relative")):
        with pytest.raises(EngineFailure):
            Engine(path, "dedicated")
    # macOS AF_UNIX has a short path limit; pytest's nested temp path can exceed it.
    with (
        tempfile.TemporaryDirectory(prefix="xdp-", dir="/tmp") as folder,
        socket.socket(socket.AF_UNIX) as listener,
    ):
        path = Path(folder).resolve() / "engine.sock"
        listener.bind(str(path))
        adapter = Engine(path.resolve(), "dedicated")
        adapter.close()


def config(tmp_path, **changes):
    return Config(
        core_url="https://core.example.test",
        issuer="https://id.example.test/realms/xarionix",
        client_id="deployment",
        client_secret="unit-test-only-credential-not-deployed",
        host_id=uuid.uuid4(),
        engine_socket=tmp_path / "engine.sock",
        engine_id="dedicated-test-engine",
        storage_root=tmp_path / "state",
        **changes,
    )


def test_deployment_transport_has_no_insecure_production_fallback(tmp_path):
    value = config(tmp_path)
    for field, payload in [
        ("core_url", "http://remote.example.test"),
        ("test_oidc_transport", "http://keycloak:8080/realms/xarionix"),
    ]:
        with pytest.raises(ValidationError):
            Config.model_validate(value.model_dump() | {field: payload})


def test_oidc_discovery_token_and_polling_are_bounded(tmp_path):
    settings = config(tmp_path)
    calls = []

    def handle(request):
        calls.append(request)
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": settings.issuer,
                    "token_endpoint": settings.issuer + "/protocol/openid-connect/token",
                },
            )
        if request.url.path.endswith("/token"):
            assert b"grant_type=client_credentials" in request.content
            return httpx.Response(
                200, json={"access_token": "opaque-test-token", "token_type": "Bearer", "expires_in": 300}
            )
        assert request.headers["Authorization"] == "Bearer opaque-test-token"
        return httpx.Response(200, json={"jobs": []})

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        protocol = Protocol(settings, client)
        assert protocol.request("/check-in", {"sequence": 1}) == {"jobs": []}
        assert protocol.token() == "opaque-test-token" and len(calls) == 3


@pytest.mark.parametrize(
    "status,payload", [(401, {}), (403, {}), (500, {}), (200, []), (200, {"payload": "x" * 524289})]
)
def test_protocol_failure_never_echoes_private_response(tmp_path, status, payload):
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(status, json=payload))
    ) as client:
        with pytest.raises(ProtocolFailure) as error:
            Protocol(config(tmp_path), client).json("GET", "https://core.example.test")
        assert "unit-test-only-credential" not in str(error.value)
