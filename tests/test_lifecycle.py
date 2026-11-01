import ssl
from contextlib import nullcontext
from unittest.mock import AsyncMock

import httpx
import pytest

from app.main import create_app


@pytest.mark.parametrize("provider_status", [200, 503])
@pytest.mark.parametrize("shutdown_error", [False, True])
async def test_real_lifespan_validates_oidc_without_unsafe_tls_and_cleans_resources(
    provider, monkeypatch, provider_status, shutdown_error
):
    provider.status = provider_status
    async_client = httpx.AsyncClient
    engine = AsyncMock()
    monkeypatch.setattr("app.main.create_database", lambda config: (engine, object()))
    clients = []

    def oidc_client(**kwargs):
        assert isinstance(kwargs["verify"], ssl.SSLContext)
        assert kwargs["verify"].verify_mode == ssl.CERT_REQUIRED
        assert kwargs["verify"].check_hostname is True
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        client = async_client(transport=httpx.MockTransport(provider.handle), **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr("app.main.httpx.AsyncClient", oidc_client)
    app = create_app(provider.settings)
    with pytest.raises(RuntimeError) if shutdown_error else nullcontext():
        async with app.router.lifespan_context(app):
            async with async_client(
                transport=httpx.ASGITransport(app=app), base_url=provider.settings.public_url
            ) as client:
                assert (await client.get("/health/live")).json() == {"status": "ok"}
                assert (await client.get("/api/v1/me")).status_code == 401
                assert await app.state.oidc.ready() is (provider_status == 200)
                if shutdown_error:
                    raise RuntimeError("test-only shutdown failure")
    assert len(clients) == 1 and clients[0].is_closed
    engine.dispose.assert_awaited_once()
