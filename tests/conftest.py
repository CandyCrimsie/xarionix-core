import json
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        keycloak_mode="external",
        public_url="https://core.example.test",
        oidc_issuer="https://auth.example.test/realms/xarionix",
        db_password="test-password-not-for-deployment-123456",
    )


@pytest.fixture(scope="session")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Provider:
    def __init__(self, settings: Settings, signing_key: rsa.RSAPrivateKey):
        self.settings, self.key = settings, signing_key
        self.kid = "key-1"
        self.now = 100.0
        self.requests: list[str] = []
        self.status = 200
        self.discovery: dict[str, Any] = {
            "issuer": settings.oidc_issuer,
            "jwks_uri": settings.oidc_issuer + "/protocol/openid-connect/certs",
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        self.jwks: dict[str, Any] | None = None

    def public_key(self) -> dict[str, Any]:
        return json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key())) | {
            "kid": self.kid,
            "alg": "RS256",
            "use": "sig",
        }

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        data = (
            self.discovery
            if request.url.path.endswith("openid-configuration")
            else (self.jwks or {"keys": [self.public_key()]})
        )
        return httpx.Response(self.status, json=data)

    def token(self, **overrides: Any) -> str:
        now = int(time.time())
        claims = {
            "iss": self.settings.oidc_issuer,
            "aud": "xarionix-core",
            "sub": "person-1",
            "exp": now + 300,
            "iat": now - 10,
            "nbf": now - 10,
            "typ": "Bearer",
        } | overrides
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": self.kid})


@pytest.fixture
def provider(settings: Settings, signing_key: rsa.RSAPrivateKey) -> Provider:
    return Provider(settings, signing_key)
