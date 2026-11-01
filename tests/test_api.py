import json
import logging
import uuid
from contextlib import asynccontextmanager

import httpx
import pytest

from app.core.logging import SafeJSONFormatter
from app.integrations.keycloak.oidc import OIDCVerifier
from app.main import create_app


@pytest.fixture
async def api(provider, monkeypatch):
    app = create_app(provider.settings)
    identifier = uuid.uuid4()
    calls = []

    @asynccontextmanager
    async def session():
        yield object()

    async def resolve(session, issuer, subject):
        calls.append((issuer, subject))
        return identifier

    async def ready(engine):
        return True

    monkeypatch.setattr("app.api.v1.routes.resolve_identity", resolve)
    monkeypatch.setattr("app.main.database_ready", ready)
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as oidc_client:
        app.state.oidc = OIDCVerifier(provider.settings, oidc_client)
        app.state.engine = object()
        app.state.sessions = session
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://core.example.test"
        ) as client:
            yield app, client, calls, identifier


async def test_me_requires_verified_access_token(api, provider):
    app, client, calls, identifier = api
    for headers in (
        {},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer invalid"},
        {"Authorization": "Bearer " + provider.token(aud="wrong")},
    ):
        response = await client.get("/api/v1/me", headers=headers)
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert calls == []
    response = await client.get("/api/v1/me", headers={"Authorization": "Bearer " + provider.token()})
    assert response.status_code == 200
    assert response.json() == {
        "id": str(identifier),
        "issuer": provider.settings.oidc_issuer,
        "subject": "person-1",
    }
    assert calls == [(provider.settings.oidc_issuer, "person-1")]


async def test_health_and_system_info_disclose_no_configuration(api, provider, monkeypatch):
    app, client, _, _ = api
    assert (await client.get("/health/live")).json() == {"status": "ok"}
    assert (await client.get("/health/ready")).json() == {"status": "ready"}
    assert (await client.get("/api/v1/system/info")).status_code == 401
    response = await client.get(
        "/api/v1/system/info", headers={"Authorization": "Bearer " + provider.token()}
    )
    assert response.json() == {"product": "Xarionix Core", "version": "0.1.0", "api_version": "v1"}

    async def not_ready(engine):
        return False

    monkeypatch.setattr("app.main.database_ready", not_ready)
    response = await client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}
    assert (await client.get("/docs")).status_code == 404
    assert (await client.get("/openapi.json")).status_code == 404


async def test_request_id_and_generic_errors(api, monkeypatch):
    app, client, _, _ = api
    response = await client.get("/health/live", headers={"X-Request-ID": "chosen-request-123"})
    assert response.headers["X-Request-ID"] == "chosen-request-123"
    response = await client.get("/health/live", headers={"X-Request-ID": "bad input"})
    assert len(response.headers["X-Request-ID"]) == 32
    assert response.headers["Cache-Control"] == "no-store"

    async def broken(engine):
        raise RuntimeError("password=private-address:5432/secret")

    monkeypatch.setattr("app.main.database_ready", broken)
    response = await client.get("/health/ready")
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}


def test_log_formatter_drops_tokens_headers_cookies_errors_and_urls():
    record = logging.LogRecord(
        "httpx", logging.ERROR, "secret-path", 1, "Bearer highly-sensitive password=secret", (), None
    )
    record.event = "http_request"
    record.request_id = "chosen-request-123"
    record.headers = {"Authorization": "sensitive", "Cookie": "private"}
    output = SafeJSONFormatter().format(record)
    assert json.loads(output)["event"] == "http_request"
    assert all(value not in output for value in ("sensitive", "password", "Cookie", "secret-path"))
