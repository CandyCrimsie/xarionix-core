import json
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.v1 import module_schemas as dto
from app.core.module_body_limit import ModuleBodyLimit
from app.domains.modules import authorization, service
from app.domains.modules.model import OPERATIONS, ModuleCommand, ModuleInstance, ModuleService
from scripts.module_agent import Agent, AgentConfig, AgentFailure, Revoked, backoff


def test_machine_binding_is_exact_and_not_a_user_claim():
    assert authorization.binding(
        {"iss": "https://id.test", "sub": "service-uuid", "azp": "billing", "xarionix_principal": "machine"}
    ) == ("https://id.test", "service-uuid", "billing")


@pytest.mark.parametrize(
    "changes",
    [
        {"azp": None},
        {"sub": ""},
        {"iss": None},
        {"client_id": "other"},
        {"xarionix_principal": "human"},
        {"azp": "x" * 121},
    ],
)
def test_binding_denies_missing_or_conflicting_verified_claims(changes):
    with pytest.raises(HTTPException, match="machine_binding_invalid"):
        authorization.binding(
            {
                "iss": "https://id.test",
                "sub": "uuid",
                "azp": "billing",
                "xarionix_principal": "machine",
                **changes,
            }
        )


@pytest.fixture
def machine(settings):
    from sqlalchemy.ext.asyncio import AsyncSession

    db = MagicMock(spec=AsyncSession)
    db.scalar, db.scalars, db.execute, db.flush, db.get = (
        AsyncMock(),
        AsyncMock(),
        AsyncMock(),
        AsyncMock(),
        AsyncMock(),
    )
    ctx = authorization.MachineContext(
        db,
        settings,
        {"iss": "https://id.test", "sub": "uuid", "azp": "module", "xarionix_principal": "machine"},
        "request-1234",
    )
    parent = ModuleService(id=uuid.uuid4(), status="active", operations=sorted(OPERATIONS))
    instance = ModuleInstance(
        id=uuid.uuid4(),
        service_id=parent.id,
        status="active",
        health="healthy",
        last_seen=None,
        next_check_in_at=None,
    )
    db.scalar.side_effect = [parent, instance]
    return ctx, parent, instance


@pytest.mark.parametrize(
    "state,status",
    [
        ("unknown", 403),
        ("disabled", 403),
        ("revoked", 403),
        ("wrong_instance", 404),
        ("disabled_instance", 403),
        ("operation", 403),
    ],
)
async def test_machine_authorization_fails_closed(machine, state, status):
    ctx, parent, instance = machine
    if state in {"disabled", "revoked"}:
        parent.status = state
    if state == "disabled_instance":
        instance.status = "disabled"
    if state == "operation":
        parent.operations = []
    ctx.session.scalar.side_effect = [
        None if state == "unknown" else parent,
        None if state == "wrong_instance" else instance,
    ]
    with pytest.raises(HTTPException) as error:
        await authorization.require(ctx, instance.id, "core.modules.connect")
    assert error.value.status_code == status
    ctx.session.add.assert_not_called()


async def test_machine_scope_is_explicit_and_never_membership(machine):
    ctx, _, instance = machine
    ctx.session.scalar.side_effect = [None]
    with pytest.raises(HTTPException):
        await authorization.company(ctx, instance.id, uuid.uuid4(), "core.modules.metadata.read")
    assert "memberships" not in str(ctx.session.scalar.call_args.args[0])


@pytest.mark.parametrize(
    "parent_status,instance_status,age,health,expected",
    [
        ("active", "active", 1, "healthy", "connected"),
        ("active", "active", 1, "error", "error"),
        ("active", "active", 91, "healthy", "stale"),
        ("disabled", "active", 1, "healthy", "disabled"),
        ("revoked", "active", 1, "healthy", "revoked"),
        ("active", "revoked", 1, "healthy", "revoked"),
        ("active", "disabled", 1, "healthy", "disabled"),
    ],
)
def test_server_derives_connection_state(machine, parent_status, instance_status, age, health, expected):
    _, parent, instance = machine
    parent.status, instance.status, instance.health = parent_status, instance_status, health
    now = datetime.now(UTC)
    instance.last_seen = now - timedelta(seconds=age)
    assert service.connection_state(parent, instance, 90, now) == expected


@pytest.mark.parametrize(
    "changes",
    [
        {"protocol_version": True},
        {"protocol_version": "1"},
        {"protocol_version": 2},
        {"agent_version": "<svg>"},
        {"user_id": str(uuid.uuid4())},
        {"company_id": str(uuid.uuid4())},
    ],
)
def test_bounded_agent_schema_rejects_contract_and_context_injection(changes):
    with pytest.raises(ValidationError):
        dto.CheckIn(
            instance_id=uuid.uuid4(),
            **({"protocol_version": 1, "agent_version": "0.1.0", "health": "healthy"} | changes),
        )


async def test_heartbeat_has_server_time_rate_limit_and_no_global_gate(machine):
    ctx, _, instance = machine
    result = MagicMock()
    result.all.return_value = []
    ctx.session.scalars.return_value = result
    result = await service.check_in(
        ctx, dto.CheckIn(instance_id=instance.id, protocol_version=1, health="healthy", agent_version="0.1.0")
    )
    assert result.connection_state == "connected" and result.server_time == instance.last_seen
    assert instance.next_check_in_at > instance.last_seen
    assert all("platform_settings" not in str(call.args) for call in ctx.session.execute.await_args_list)
    ctx.session.scalar.side_effect = [machine[1], instance]
    with pytest.raises(HTTPException, match="module_check_in_rate_limited"):
        await service.check_in(
            ctx,
            dto.CheckIn(instance_id=instance.id, protocol_version=1, health="healthy", agent_version="0.1.0"),
        )


@pytest.mark.parametrize(
    "state",
    ["missing", "expired", "pending", "wrong_result", "completed_conflict", "completed_same", "delivered"],
)
async def test_ack_is_scoped_bounded_and_idempotent(machine, state):
    ctx, parent, instance = machine
    value = ModuleCommand(
        id=uuid.uuid4(),
        instance_id=instance.id,
        operation="ping",
        state="delivered",
        expires_at=datetime.now(UTC) + timedelta(seconds=60),
    )
    if state == "expired":
        value.expires_at -= timedelta(seconds=120)
    if state == "pending":
        value.state = "pending"
    if state.startswith("completed"):
        value.state, value.result = "completed", {"kind": "pong"}
    ctx.session.scalar.side_effect = [parent, instance, None if state == "missing" else value]
    result = (
        {"kind": "status", "health": "healthy", "agent_version": "0.1.0"}
        if state in {"wrong_result", "completed_conflict"}
        else {"kind": "pong"}
    )
    payload = dto.Acknowledgement(instance_id=instance.id, result=result)
    if state in {"completed_same", "delivered"}:
        assert await service.acknowledge(ctx, value.id, payload) is value
        assert value.state == "completed"
        assert ctx.session.add.call_count == (0 if state == "completed_same" else 1)
    else:
        with pytest.raises(HTTPException):
            await service.acknowledge(ctx, value.id, payload)
        ctx.session.add.assert_not_called()


@pytest.fixture
def agent_config():
    return AgentConfig(
        core_url="https://core.example.test",
        issuer="https://id.example.test/realms/xarionix",
        client_id="test-agent",
        client_secret="a" * 32,
        instance_id=uuid.uuid4(),
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"core_url": "http://core.example.test"},
        {"core_url": "https://user:pass@core.test"},
        {"test_oidc_transport": "http://keycloak:8080/realms/xarionix"},
        {"isolated_http": True, "core_url": "http://attacker.test"},
        {"core_url": "https://core.test?token=bad"},
    ],
)
def test_agent_transport_is_strict_and_secret_repr_is_redacted(agent_config, changes):
    with pytest.raises(ValidationError):
        AgentConfig(**(agent_config.model_dump() | changes))
    assert agent_config.client_secret.get_secret_value() not in repr(agent_config)


def agent_transport(config, handler):
    def respond(request):
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": config.issuer,
                    "token_endpoint": config.issuer + "/protocol/openid-connect/token",
                },
            )
        return handler(request)

    return httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=False)


def test_agent_refreshes_token_and_reauthenticates_once_on_401(agent_config):
    calls = {"tokens": 0, "core": 0}

    def response(request):
        if request.url.path.endswith("/token"):
            calls["tokens"] += 1
            return httpx.Response(
                200, json={"access_token": "signed-test-token", "expires_in": 60, "token_type": "Bearer"}
            )
        calls["core"] += 1
        return httpx.Response(
            401 if calls["core"] == 1 else 200, json={"commands": [], "check_in_seconds": 15}
        )

    now = [0]
    with agent_transport(agent_config, response) as client:
        agent = Agent(agent_config, client, clock=lambda: now[0])
        assert agent.step() == 15
        assert calls == {"tokens": 2, "core": 2}
        agent.token()
        assert calls["tokens"] == 2
        now[0] = 100
        agent.token()
        assert calls["tokens"] == 3


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_agent_failure_diagnostics_never_echo_body_token_or_secret(agent_config, status):
    def response(request):
        if request.url.path.endswith("/token"):
            return httpx.Response(
                200, json={"access_token": "SECRET_JWT", "expires_in": 60, "token_type": "Bearer"}
            )
        return httpx.Response(status, json={"detail": "PRIVATE_CREDENTIALS"})

    with agent_transport(agent_config, response) as client:
        with pytest.raises(AgentFailure) as error:
            Agent(agent_config, client).step()
        assert "SECRET" not in str(error.value) and "PRIVATE" not in str(error.value)
        assert isinstance(error.value, Revoked) == (status in {401, 403, 404})


def test_agent_lost_ack_response_retries_same_cached_result(agent_config):
    command = {
        "id": str(uuid.uuid4()),
        "operation": "ping",
        "expires_at": (datetime.now(UTC) + timedelta(seconds=60)).isoformat(),
        "attempt": 1,
        "request_id": "request-1234",
    }
    acknowledgements = []

    def response(request):
        if request.url.path.endswith("/token"):
            return httpx.Response(
                200, json={"access_token": "signed", "expires_in": 60, "token_type": "Bearer"}
            )
        if request.url.path.endswith("/ack"):
            acknowledgements.append(json.loads(request.content))
            if len(acknowledgements) == 1:
                raise httpx.ReadError("SECRET in transport must not escape")
            return httpx.Response(200, json={"state": "completed"})
        return httpx.Response(200, json={"commands": [command], "check_in_seconds": 15})

    with agent_transport(agent_config, response) as client:
        agent = Agent(agent_config, client)
        with pytest.raises(AgentFailure):
            agent.step()
        assert len(agent.pending) == 1
        assert agent.step() == 15
        assert all(item == acknowledgements[0] for item in acknowledgements)
        assert not agent.pending and len(agent.results) == 1


def test_backoff_is_bounded_and_jittered_without_sleep():
    assert backoff(1, lambda: 0) == 1.6
    assert backoff(100, lambda: 1) == 60
    assert 0 < backoff(3, lambda: 0) < backoff(3, lambda: 1)


async def test_module_payload_limit_handles_chunked_body_before_application():
    reached = False

    async def application(scope, receive, send):
        nonlocal reached
        reached = True

    messages = iter(
        [
            {"type": "http.request", "body": b"x" * 9000, "more_body": True},
            {"type": "http.request", "body": b"x" * 9000, "more_body": False},
        ]
    )

    async def receive():
        return next(messages)

    send = AsyncMock()
    await ModuleBodyLimit(application)(
        {"type": "http", "path": "/api/v1/module-agent/check-in"}, receive, send
    )
    assert not reached
    assert send.await_args_list[0].args[0]["status"] == 413
