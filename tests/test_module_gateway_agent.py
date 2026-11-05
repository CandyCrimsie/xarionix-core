import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import test_deployment_agent as offline
from test_module_gateway import contract_data

from app.domains.module_gateway.contracts import APIContract, Dispatch, ExecutionContext
from scripts.deployment_agent.engine import API_ISOLATION_PROBE, Engine, EngineFailure
from scripts.deployment_agent.ipc import BRIDGE
from scripts.deployment_agent.protocol import ProtocolFailure
from scripts.deployment_agent.state import State
from scripts.gateway_agent import GatewayAgent, acknowledged

offline_delivery = offline.delivery


@pytest.fixture
def delivery(offline_delivery):
    return offline_delivery.model_copy(
        update={
            "profile": "module-api-private-v1",
            "api_contract": APIContract.model_validate(contract_data()),
        }
    )


@pytest.fixture
def frame(delivery):
    return Dispatch(
        context=ExecutionContext(
            request_id=uuid4(),
            company_id=uuid4(),
            actor_id=uuid4(),
            operation_id="objects-read",
            permission="testnet.objects.read",
            installation_id=delivery.installation_id,
            installation_generation=1,
            deployment_generation=delivery.generation,
            deadline=datetime.now(UTC) + timedelta(seconds=10),
        ),
        package_sha256=delivery.package_sha256,
        contract_sha256=delivery.api_contract.digest(),
        image_digest=delivery.runtime.image_digest,
        body={},
        response_max_bytes=65536,
    )


class PrivateDocker(offline.Docker):
    def __init__(self, job):
        super().__init__(job)
        self.network = {"none": {}}
        self.socket_visible = False

    def handle(self, request):
        path = request.url.path.removeprefix("/v1.52")
        if path.endswith("/exec"):
            data = json.loads(request.content)
            if data["Cmd"][3] in {API_ISOLATION_PROBE, BRIDGE}:
                assert data["Cmd"] == ["/usr/local/bin/python", "-I", "-c", data["Cmd"][3]]
                key = ("d" if data["Cmd"][3] == BRIDGE else "e") * 64
                self.execs[key] = data["Cmd"][3]
                return httpx.Response(201, json={"Id": key})
        if path.startswith("/exec/") and self.execs.get(path.split("/")[2]) == API_ISOLATION_PROBE:
            if path.endswith("/json"):
                return httpx.Response(200, json={"Running": False, "ExitCode": 0})
            data = json.dumps({"interfaces": ["lo"], "engine": self.socket_visible}).encode()
            return httpx.Response(200, content=b"\1\0\0\0" + len(data).to_bytes(4, "big") + data)
        result = super().handle(request)
        if path == "/containers/create":
            for info in self.containers.values():
                info["NetworkSettings"] = {"Networks": self.network, "Ports": {}}
        return result


@pytest.fixture
def engine(delivery, tmp_path):
    fake = PrivateDocker(delivery)
    adapter = Engine.__new__(Engine)
    adapter.expected_id, adapter.socket = delivery.engine_id, tmp_path / "unused.sock"
    adapter.client = httpx.Client(transport=httpx.MockTransport(fake.handle), base_url="http://engine/v1.52")
    yield adapter, fake
    adapter.close()


@pytest.mark.parametrize("fault", ["foreign_network", "socket", "cgroup"])
def test_private_post_start_inspection_failure_stops_runtime(engine, delivery, fault):
    adapter, fake = engine
    if fault == "foreign_network":
        fake.network = {"none": {}, "bridge": {}}
    elif fault == "socket":
        fake.socket_visible = True
    else:
        fake.measured["memory"] = "max"
    with pytest.raises(EngineFailure, match="isolation_unavailable"):
        adapter.apply(delivery, lambda: None)
    assert not any(c["State"]["Running"] for c in fake.containers.values())


@pytest.mark.parametrize(
    "change",
    [
        {"package_sha256": "0" * 64},
        {"contract_sha256": "0" * 64},
        {"image_digest": "sha256:" + "0" * 64},
        {"response_max_bytes": 1000000},
    ],
)
def test_runtime_binding_is_checked_before_any_engine_call(engine, delivery, frame, change):
    adapter, fake = engine
    with pytest.raises(EngineFailure, match="runtime_binding_changed"):
        adapter.business(delivery, frame.model_copy(update=change))
    assert fake.calls == []


def test_business_calls_use_constant_bridge_command_and_stdin(engine, delivery, frame, monkeypatch):
    adapter, fake = engine
    adapter.apply(delivery, lambda: None)
    observed = []

    def exchange(path, identifier, payload, timeout, maximum):
        observed.append(json.loads(payload))
        return {"body": {"actual": "operation"}}

    monkeypatch.setattr("scripts.deployment_agent.engine.exchange", exchange)
    assert adapter.business(delivery, frame) == {"body": {"actual": "operation"}}
    assert observed[0]["context"]["company_id"] == str(frame.context.company_id)
    assert BRIDGE in fake.execs.values()


def test_local_journal_must_acknowledge_exact_generation(tmp_path, delivery, frame):
    root = (tmp_path / "journal").resolve()
    state = State(root)
    try:
        state.accept(delivery)
        config = SimpleNamespace(storage_root=root, host_id=delivery.host_id, engine_id=delivery.engine_id)
        with pytest.raises(ValueError, match="not_acknowledged"):
            acknowledged(config, frame)
        state.completed(delivery, {"success": True, "report": {"state": "running"}})
        assert acknowledged(config, frame) == delivery
        stale = frame.model_copy(
            update={"context": frame.context.model_copy(update={"deployment_generation": 99})}
        )
        with pytest.raises(ValueError, match="not_acknowledged"):
            acknowledged(config, stale)
        config.host_id = uuid4()
        with pytest.raises(ValueError, match="host_binding_changed"):
            acknowledged(config, frame)
    finally:
        state.close()


def test_claim_rejection_does_not_call_module_or_retry(frame, monkeypatch):
    calls = []

    class Protocol:
        config = object()

        def request(self, path, payload):
            calls.append(path)
            raise ProtocolFailure("revoked")

    class Engine:
        def business(self, job, frame):
            pytest.fail("Revoked request must not reach the module")

    agent = GatewayAgent(Protocol(), Engine())
    try:
        agent.execute(frame, uuid4())
        assert calls == ["/claim"]
    finally:
        agent.close()
