import asyncio
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import Settings
from app.integrations.keycloak.oidc import InvalidToken, OIDCVerifier, ProviderUnavailable


async def test_valid_external_token(provider):
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        verifier = OIDCVerifier(provider.settings, client, lambda: provider.now)
        assert (await verifier.verify(provider.token()))["sub"] == "person-1"
        assert await verifier.ready()
        assert len(provider.requests) == 2


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://attacker.test/realm"},
        {"aud": "wrong-api"},
        {"exp": 1},
        {"nbf": int(time.time()) + 3600},
        {"iat": int(time.time()) + 3600},
        {"typ": "ID"},
        {"sub": ""},
        {"sub": "x" * 256},
        {"sub": None},
        {"exp": None},
        {"exp": "9999999999"},
        {"exp": True},
        {"exp": float("inf")},
    ],
)
async def test_invalid_claims_are_denied(provider, claims):
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        verifier = OIDCVerifier(provider.settings, client)
        with pytest.raises(InvalidToken):
            await verifier.verify(provider.token(**claims))


@pytest.mark.parametrize("missing", ["exp", "iat", "iss", "aud", "sub"])
async def test_required_claims(provider, missing):
    claims = jwt.decode(provider.token(), options={"verify_signature": False})
    del claims[missing]
    token = jwt.encode(claims, provider.key, algorithm="RS256", headers={"kid": provider.kid})
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        with pytest.raises(InvalidToken):
            await OIDCVerifier(provider.settings, client).verify(token)


async def test_unsigned_hmac_and_wrong_signature_denied(provider):
    claims = jwt.decode(provider.token(), options={"verify_signature": False})
    forged_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tokens = [
        jwt.encode(claims, None, algorithm="none", headers={"kid": provider.kid}),
        jwt.encode(
            claims, "attacker-secret-which-is-not-trusted", algorithm="HS256", headers={"kid": provider.kid}
        ),
        jwt.encode(claims, forged_key, algorithm="RS256", headers={"kid": provider.kid}),
        "bad",
        "x" * 16385,
    ]
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        verifier = OIDCVerifier(provider.settings, client)
        for token in tokens:
            with pytest.raises(InvalidToken):
                await verifier.verify(token)


@pytest.mark.parametrize(
    "header",
    [{"jku": "https://evil.test"}, {"jwk": {}}, {"x5u": "https://evil.test"}, {"crit": ["x"]}, {"kid": ""}],
)
async def test_token_cannot_supply_its_own_keys(provider, header):
    claims = jwt.decode(provider.token(), options={"verify_signature": False})
    token = jwt.encode(claims, provider.key, algorithm="RS256", headers={"kid": provider.kid} | header)
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        with pytest.raises(InvalidToken):
            await OIDCVerifier(provider.settings, client).verify(token)
    assert not provider.requests


async def test_key_rotation_and_refresh_stampede_protection(provider):
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        verifier = OIDCVerifier(provider.settings, client, lambda: provider.now)
        await verifier.verify(provider.token())
        provider.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        provider.kid = "key-2"
        provider.now += 11
        results = await asyncio.gather(*(verifier.verify(provider.token()) for _ in range(30)))
        assert all(item["sub"] == "person-1" for item in results)
        assert len(provider.requests) == 3  # Discovery cached; one serialized JWKS rotation refresh.


async def test_unknown_kid_is_rate_limited_and_expired_keys_never_used(provider):
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        verifier = OIDCVerifier(provider.settings, client, lambda: provider.now)
        valid = provider.token()
        await verifier.verify(valid)
        provider.kid = "missing"
        for _ in range(20):
            with pytest.raises(InvalidToken):
                await verifier.verify(provider.token())
        assert len(provider.requests) == 2
        provider.status = 503
        assert (await verifier.verify(valid))["sub"] == "person-1"
        provider.now += 301
        assert not await verifier.ready()
        with pytest.raises(InvalidToken):
            await verifier.verify(valid)


@pytest.mark.parametrize(
    "jwks",
    [
        {"keys": []},
        {"keys": [None]},
        {"keys": [{}]},
        {"keys": [{"kid": "x", "alg": "RS256", "kty": "RSA", "n": "bad", "e": "AQAB"}]},
    ],
)
async def test_malformed_jwks_fails_closed(provider, jwks):
    provider.jwks = jwks
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        verifier = OIDCVerifier(provider.settings, client)
        assert not await verifier.ready()
        with pytest.raises(InvalidToken):
            await verifier.verify(provider.token())


@pytest.mark.parametrize(
    "uri",
    [
        "https://evil.test/keys",
        "http://169.254.169.254/metadata",
        "https://auth.example.test/realms/xarionix/../other",
        "https://auth.example.test/realms/xarionix/keys?redirect=bad",
    ],
)
async def test_discovery_cannot_redirect_key_fetches(provider, uri):
    provider.discovery["jwks_uri"] = uri
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        assert not await OIDCVerifier(provider.settings, client).ready()
    assert len(provider.requests) == 1


async def test_unavailable_jwks_no_authentication_bypass(provider):
    def unavailable(request):
        raise httpx.ConnectError("private address and secret must not reach response")

    async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as client:
        verifier = OIDCVerifier(provider.settings, client)
        assert not await verifier.ready()
        with pytest.raises(InvalidToken):
            await verifier.verify(provider.token())


async def test_managed_transport_keeps_public_issuer(provider):
    config = Settings(
        **(
            provider.settings.model_dump()
            | {"keycloak_mode": "managed", "oidc_backchannel": "http://keycloak:8080/realms/xarionix"}
        )
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        verifier = OIDCVerifier(config, client)
        assert (await verifier.verify(provider.token()))["iss"] == provider.settings.oidc_issuer
        assert all(
            request.startswith("http://keycloak:8080/realms/xarionix/") for request in provider.requests
        )
        with pytest.raises(ProviderUnavailable):
            verifier.transport_url("http://untrusted/keys")


async def test_private_duplicate_and_weak_keys_rejected(provider):
    public = provider.public_key()
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    import json

    for keys in (
        [public, public],
        [public | {"d": "secret"}],
        [public | json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(weak.public_key()))],
    ):
        provider.jwks = {"keys": keys}
        async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
            assert not await OIDCVerifier(provider.settings, client).ready()


async def test_wrong_discovery_issuer_is_not_trusted(provider):
    provider.discovery["issuer"] = "https://other.example.test/realms/xarionix"
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        verifier = OIDCVerifier(provider.settings, client)
        assert not await verifier.ready()
        with pytest.raises(InvalidToken):
            await verifier.verify(provider.token())
    assert len(provider.requests) == 1


@pytest.mark.parametrize("content", [b"not JSON", b"[]", b"x" * 262145])
async def test_malformed_or_oversized_metadata_denied(provider, content):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=content))
    ) as client:
        assert not await OIDCVerifier(provider.settings, client).ready()


async def test_provider_429_does_not_trigger_unbounded_retries(provider):
    provider.status = 429
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as client:
        verifier = OIDCVerifier(provider.settings, client, lambda: provider.now)
        for _ in range(100):
            with pytest.raises(InvalidToken):
                await verifier.verify(provider.token())
        assert len(provider.requests) == 1
