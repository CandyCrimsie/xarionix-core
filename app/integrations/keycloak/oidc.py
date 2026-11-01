import asyncio
import json
import math
import time
from collections.abc import Callable
from typing import Any

import httpx
import jwt

from app.core.config import Settings, validate_url


class InvalidToken(Exception):
    pass


class ProviderUnavailable(Exception):
    pass


class OIDCVerifier:
    def __init__(
        self, settings: Settings, client: httpx.AsyncClient, clock: Callable[[], float] = time.monotonic
    ):
        self.settings = settings
        self.client = client
        self.clock = clock
        self.lock = asyncio.Lock()
        self.keys: dict[str, jwt.PyJWK] = {}
        self.expires = 0.0
        self.retry_after = 0.0
        self.jwks_uri: str | None = None

    def transport_url(self, public_url: str) -> str:
        issuer = self.settings.oidc_issuer
        try:
            validate_url(public_url, development=self.settings.environment == "development")
        except ValueError:
            raise ProviderUnavailable() from None
        # Both modes validate the SAME public issuer. Only managed transport is remapped.
        if not public_url.startswith(issuer + "/"):
            raise ProviderUnavailable()
        if self.settings.oidc_backchannel:
            return self.settings.oidc_backchannel + public_url[len(issuer) :]
        return public_url

    async def document(self, url: str) -> dict[str, Any]:
        try:
            async with self.client.stream("GET", self.transport_url(url)) as response:
                response.raise_for_status()
                data = bytearray()
                async for chunk in response.aiter_bytes(8192):
                    data.extend(chunk)
                    if len(data) > 262144:
                        raise ProviderUnavailable()
            value = json.loads(data)
            if not isinstance(value, dict):
                raise ProviderUnavailable()
            return value
        except (httpx.HTTPError, ValueError, TypeError) as error:
            raise ProviderUnavailable() from error

    async def refresh(self, *, unknown_kid: str | None = None) -> None:
        async with self.lock:
            now = self.clock()
            if now < self.expires and (unknown_kid is None or unknown_kid in self.keys):
                return
            if now < self.retry_after:
                if now < self.expires:
                    return
                raise ProviderUnavailable()
            self.retry_after = now + self.settings.oidc_refresh_cooldown
            try:
                if self.jwks_uri is None:
                    discovery = await self.document(
                        self.settings.oidc_issuer + "/.well-known/openid-configuration"
                    )
                    if discovery.get("issuer") != self.settings.oidc_issuer:
                        raise ProviderUnavailable()
                    uri = discovery.get("jwks_uri")
                    if not isinstance(uri, str):
                        raise ProviderUnavailable()
                    self.transport_url(uri)  # No discovery-controlled cross-origin SSRF.
                    supported = discovery.get("id_token_signing_alg_values_supported", [])
                    if not isinstance(supported, list) or not set(self.settings.oidc_algorithms) <= set(
                        supported
                    ):
                        raise ProviderUnavailable()
                    self.jwks_uri = uri
                document = await self.document(self.jwks_uri)
                values = document.get("keys")
                if not isinstance(values, list) or not 1 <= len(values) <= 32:
                    raise ProviderUnavailable()
                keys: dict[str, jwt.PyJWK] = {}
                for value in values:
                    if not isinstance(value, dict):
                        raise ProviderUnavailable()
                    if value.get("use", "sig") != "sig":
                        continue
                    if value.get("alg") not in self.settings.oidc_algorithms:
                        continue
                    kid = value.get("kid")
                    if not isinstance(kid, str) or not 1 <= len(kid) <= 128 or kid in keys:
                        raise ProviderUnavailable()
                    if any(field in value for field in ("d", "p", "q", "dp", "dq", "qi", "k")):
                        raise ProviderUnavailable()
                    if value.get("key_ops", ["verify"]) != ["verify"]:
                        raise ProviderUnavailable()
                    key = jwt.PyJWK.from_dict(value)
                    if value.get("kty") == "RSA" and not 2048 <= key.key.key_size <= 8192:
                        raise ProviderUnavailable()
                    if (
                        value.get("alg") == "ES256"
                        and getattr(getattr(key.key, "curve", None), "name", "") != "secp256r1"
                    ):
                        raise ProviderUnavailable()
                    keys[kid] = key
                if not keys:
                    raise ProviderUnavailable()
                self.keys = keys
                self.expires = now + self.settings.oidc_cache_seconds
            except (jwt.PyJWTError, ValueError, TypeError, KeyError) as error:
                raise ProviderUnavailable() from error

    async def ready(self) -> bool:
        try:
            await self.refresh()
            return bool(self.keys) and self.clock() < self.expires
        except ProviderUnavailable:
            return False

    async def verify(self, token: str) -> dict[str, Any]:
        if not 1 <= len(token) <= 16384:
            raise InvalidToken()
        try:
            header = jwt.get_unverified_header(token)
            algorithm, kid = header.get("alg"), header.get("kid")
            if (
                algorithm not in self.settings.oidc_algorithms
                or not isinstance(kid, str)
                or not 1 <= len(kid) <= 128
            ):
                raise InvalidToken()
            if any(key in header for key in ("jku", "jwk", "x5u", "crit")):
                raise InvalidToken()
            await self.refresh(unknown_kid=kid)
            key = self.keys.get(kid)
            if key is None or key.algorithm_name != algorithm:
                raise InvalidToken()
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=self.settings.oidc_algorithms,
                issuer=self.settings.oidc_issuer,
                audience=self.settings.oidc_audience,
                leeway=self.settings.oidc_leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
            if any(
                type(claims[name]) not in (int, float) or not math.isfinite(claims[name])
                for name in ("exp", "iat", "nbf")
                if name in claims
            ):
                raise InvalidToken()
            if (
                claims.get("typ") != "Bearer"
                or not isinstance(claims["sub"], str)
                or not 1 <= len(claims["sub"]) <= 255
            ):
                raise InvalidToken()
            return claims
        except (jwt.PyJWTError, ProviderUnavailable, ValueError, TypeError, KeyError, OverflowError) as error:
            raise InvalidToken() from error
