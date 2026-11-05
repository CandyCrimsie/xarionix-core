import asyncio
import copy
import json
import time
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException
from package_helpers import manifest_data
from pydantic import ValidationError

from app.domains.module_gateway.authorization import Verdict
from app.domains.module_gateway.contracts import (
    API_RESOURCE,
    APIContract,
    Result,
    SessionOpen,
    json_bytes,
)
from app.domains.module_gateway.transport import Relay
from app.domains.packages.archive import verify
from app.domains.packages.codec import PackageError, canonical
from app.domains.packages.schema import Manifest, TrustKey, TrustStore
from app.integrations.keycloak.oidc import OIDCVerifier
from app.main import create_app
from scripts.xpkg import keygen, pack


def contract_data():
    return {
        "schema_version": 1,
        "operations": [
            {
                "id": "objects-read",
                "method": "POST",
                "permission": "testnet.objects.read",
                "request": {"kind": "json", "max_bytes": 65536},
                "response": {"kind": "json", "max_bytes": 65536},
            }
        ],
    }


@pytest.fixture
def verdict(settings):
    return Verdict(
        uuid4(),
        uuid4(),
        3,
        7,
        "a" * 64,
        "b" * 64,
        "sha256:" + "c" * 64,
        uuid4(),
        uuid4(),
        "test-module",
        APIContract.model_validate(contract_data()).operations[0],
        {"iss": settings.oidc_issuer, "sub": "human", "exp": time.time() + 60},
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(schema_version=True),
        lambda d: d.update(schema_version=2),
        lambda d: d.update(target_url="http://169.254.169.254"),
        lambda d: d["operations"][0].update(method="GET"),
        lambda d: d["operations"][0].update(id="../../admin"),
        lambda d: d["operations"][0].update(shell="id"),
        lambda d: d["operations"][0]["request"].update(max_bytes=1048577),
        lambda d: d["operations"].append(copy.deepcopy(d["operations"][0])),
    ],
)
def test_signed_contract_is_closed(mutation):
    data = contract_data()
    mutation(data)
    with pytest.raises(ValidationError):
        APIContract.model_validate(data)


@pytest.mark.parametrize("permission", ["core.users.read", "other.objects.read", "testnet.unknown.read"])
def test_signed_operation_requires_declared_own_permission(permission):
    data = contract_data()
    data["operations"][0]["permission"] = permission
    with pytest.raises(PackageError, match="module_api_permission_invalid"):
        APIContract.model_validate(data).bound(Manifest.model_validate(manifest_data()))


def test_contract_is_additional_v1_signed_inventory(tmp_path):
    payload = tmp_path / "payload"
    (payload / "resources").mkdir(parents=True)
    (payload / "resources" / "module-api-v1.json").write_bytes(canonical(contract_data()))
    template = tmp_path / "manifest.json"
    template.write_text(json.dumps(manifest_data()))
    private = tmp_path / "private.key"
    public = keygen(private, tmp_path / "public.key")["public_key"]
    package = tmp_path / "api.xpkg"
    pack(payload, template, private, "test-publisher", "test-key", package)
    trust = TrustStore(
        schema_version=1,
        keys=[
            TrustKey(
                publisher_id="test-publisher", key_id="test-key", public_key=public, namespaces=["testnet"]
            )
        ],
    )
    checked = verify(package, trust)
    assert checked.manifest.schema_version == 1
    assert checked.api_contract == contract_data()
    assert [a.path for a in checked.manifest.artifacts] == [API_RESOURCE]


@pytest.mark.parametrize("body,limit", [(float("nan"), 100), ("a" * 100, 10), ([[]] * 10001, 1000000)])
def test_json_resource_limits(body, limit):
    with pytest.raises(ValueError):
        json_bytes(body, limit=limit)


def test_json_nesting_and_nonnumeric_versions():
    nested = {}
    for _ in range(18):
        nested = {"nested": nested}
    with pytest.raises(ValueError):
        json_bytes(nested, limit=65536)
    with pytest.raises(ValidationError):
        SessionOpen(schema_version=True, protocol="module-gateway-poll-v1")


@pytest.fixture
def relay(settings):
    return Relay(settings, None)


def response(frame, session, **changes):
    c = frame.context
    return Result(
        session_id=session,
        request_id=c.request_id,
        installation_id=c.installation_id,
        installation_generation=c.installation_generation,
        deployment_generation=c.deployment_generation,
        body={"answer": 42},
        **changes,
    )


async def offered(relay, verdict):
    session = relay.open(verdict.host_id, 1, time.time() + 60)
    task = asyncio.create_task(relay.invoke(verdict, {"query": "hello"}))
    await asyncio.sleep(0)
    frames = await relay.poll(verdict.host_id, session, 1, 1)
    assert len(frames) == 1
    return session, task, frames[0]


async def test_operation_delivery_claim_result_and_no_database_transaction(relay, verdict, monkeypatch):
    calls = []

    async def recheck(database, config, claims, company, module, operation):
        calls.append((company, operation))
        return verdict

    monkeypatch.setattr("app.domains.module_gateway.transport.authorize", recheck)
    session, task, frame = await offered(relay, verdict)
    assert "Authorization" not in frame.model_dump_json()
    await relay.claim(verdict.host_id, session, frame.context.request_id, 1)
    await relay.complete(verdict.host_id, response(frame, session), 1)
    result = await task
    assert result["body"] == {"answer": 42} and len(calls) == 2
    assert not relay.pending
    with pytest.raises(HTTPException, match="409"):
        await relay.complete(verdict.host_id, response(frame, session), 1)


async def test_revocation_before_claim_denies_dispatch(relay, verdict, monkeypatch):
    async def denied(*args):
        raise HTTPException(403, detail={"code": "company_permission_denied"})

    monkeypatch.setattr("app.domains.module_gateway.transport.authorize", denied)
    session, task, frame = await offered(relay, verdict)
    with pytest.raises(HTTPException):
        await relay.claim(verdict.host_id, session, frame.context.request_id, 1)
    with pytest.raises(HTTPException) as error:
        await task
    assert error.value.status_code == 403 and not relay.pending


async def test_duplicate_claim_cannot_execute_twice(relay, verdict, monkeypatch):
    async def allow(*args):
        return verdict

    monkeypatch.setattr("app.domains.module_gateway.transport.authorize", allow)
    session, task, frame = await offered(relay, verdict)
    await relay.claim(verdict.host_id, session, frame.context.request_id, 1)
    with pytest.raises(HTTPException):
        await relay.claim(verdict.host_id, session, frame.context.request_id, 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not relay.pending


async def test_session_replacement_never_replays_write(relay, verdict):
    session, task, frame = await offered(relay, verdict)
    new = relay.open(verdict.host_id, 1, time.time() + 60)
    assert new != session
    with pytest.raises(HTTPException) as error:
        await task
    assert error.value.detail["code"] == "gateway_session_lost" and not relay.pending


async def test_wrong_host_revision_session_and_correlation_are_denied(relay, verdict):
    session, task, frame = await offered(relay, verdict)
    for host, sid, revision, rid in [
        (uuid4(), session, 1, frame.context.request_id),
        (verdict.host_id, uuid4(), 1, frame.context.request_id),
        (verdict.host_id, session, 2, frame.context.request_id),
        (verdict.host_id, session, 1, uuid4()),
    ]:
        with pytest.raises(HTTPException):
            relay.correlation(host, sid, rid, revision)
    with pytest.raises(HTTPException):
        await relay.poll(verdict.host_id, session, 1, 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_capacity_and_disconnection(relay, verdict):
    with pytest.raises(HTTPException) as disconnected:
        await relay.invoke(verdict, {})
    assert disconnected.value.status_code == 503
    session, task, frame = await offered(relay, verdict)
    relay.config.gateway_per_installation = 1
    with pytest.raises(HTTPException) as full:
        await relay.invoke(verdict, {})
    assert full.value.status_code == 429
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.parametrize(
    "principal,audience",
    [
        ("machine", "xarionix-core-modules"),
        ("deployment", "xarionix-core-deployment"),
        ("gateway", "xarionix-core-gateway"),
    ],
)
async def test_gateway_and_machine_credentials_are_not_human(provider, principal, audience):
    app = create_app(provider.settings)
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as oidc:
        app.state.oidc = OIDCVerifier(provider.settings, oidc)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=provider.settings.public_url
        ) as client:
            response = await client.post(
                f"/api/v1/companies/{uuid4()}/modules/test-module/operations/objects-read",
                json={},
                headers={
                    "Authorization": "Bearer " + provider.token(aud=audience, xarionix_principal=principal)
                },
            )
            assert response.status_code == 401


@pytest.mark.parametrize(
    "body", [b'{"x":1,"x":2}', b'{"x":NaN}', b"[" * 2000 + b"]" * 2000, b'{"x":"' + b"a" * 66000 + b'"}']
)
async def test_raw_gateway_input_is_bounded_before_auth(provider, body):
    app = create_app(provider.settings)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=provider.settings.public_url
    ) as client:
        response = await client.post(
            f"/api/v1/companies/{uuid4()}/modules/test-module/operations/objects-read", content=body
        )
        assert response.status_code in {413, 422}


@pytest.mark.parametrize("purpose", [{"name": "gateway"}, ["gateway"]])
async def test_non_string_principal_is_denied_instead_of_becoming_server_error(provider, purpose):
    app = create_app(provider.settings)
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as oidc:
        app.state.oidc = OIDCVerifier(provider.settings, oidc)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=provider.settings.public_url
        ) as client:
            response = await client.post(
                f"/api/v1/companies/{uuid4()}/modules/test-module/operations/objects-read",
                json={},
                headers={"Authorization": "Bearer " + provider.token(xarionix_principal=purpose)},
            )
            assert response.status_code == 401
