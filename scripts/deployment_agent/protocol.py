"""Outbound HTTPS protocol. Deployment credentials are never business-module credentials."""

import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.config import validate_url


class Config(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="XARIONIX_DEPLOYMENT_", extra="ignore", hide_input_in_errors=True
    )
    core_url: str
    issuer: str
    client_id: str = Field(min_length=1, max_length=120)
    client_secret: SecretStr = Field(min_length=24, repr=False)
    host_id: UUID
    engine_socket: Path
    engine_id: str = Field(pattern=r"^[A-Za-z0-9:-]{8,120}$")
    storage_root: Path
    isolated_http: bool = False
    test_oidc_transport: str | None = None

    @model_validator(mode="after")
    def transport(self) -> "Config":
        for url in (self.core_url, self.issuer):
            parts = urlsplit(url)
            if self.isolated_http and parts.scheme == "http":
                if parts.hostname not in {"localhost", "127.0.0.1", "core", "keycloak"}:
                    raise ValueError("deployment_test_transport_denied")
                validate_url(url.replace("http://core", "http://localhost"), development=True)
            else:
                validate_url(url)
        if self.test_oidc_transport and (
            not self.isolated_http or self.test_oidc_transport != "http://keycloak:8080/realms/xarionix"
        ):
            raise ValueError("deployment_oidc_transport_denied")
        if not self.storage_root.is_absolute() or not self.engine_socket.is_absolute():
            raise ValueError("deployment_absolute_paths_required")
        return self


class ProtocolFailure(Exception):
    pass


class Rejected(ProtocolFailure):
    pass


class Protocol:
    def __init__(self, config: Config, client: httpx.Client):
        self.config, self.client = config, client
        self.access: str | None = None
        self.expires = 0.0

    def json(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        try:
            with self.client.stream(method, url, **kwargs) as response:
                data = bytearray()
                for chunk in response.iter_bytes(16384):
                    if len(data) + len(chunk) > 524288:
                        raise ProtocolFailure("deployment_response_limit")
                    data.extend(chunk)
                if response.status_code in {401, 403}:
                    self.access = None
                    raise Rejected("deployment_credentials_or_host_rejected")
                if not 200 <= response.status_code < 300:
                    raise ProtocolFailure("deployment_request_failed")
                value = json.loads(data)
                if not isinstance(value, dict):
                    raise ProtocolFailure("deployment_response_invalid")
                return value
        except (httpx.HTTPError, ValueError):
            raise ProtocolFailure("deployment_transport_failed") from None

    def token(self) -> str:
        if self.access and time.monotonic() < self.expires:
            return self.access
        base = self.config.test_oidc_transport or self.config.issuer
        discovery = self.json("GET", base + "/.well-known/openid-configuration")
        if (
            discovery.get("issuer") != self.config.issuer
            or discovery.get("token_endpoint") != self.config.issuer + "/protocol/openid-connect/token"
        ):
            raise ProtocolFailure("deployment_discovery_untrusted")
        value = self.json(
            "POST",
            base + "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret.get_secret_value(),
            },
        )
        token, expires = value.get("access_token"), value.get("expires_in")
        if (
            not isinstance(token, str)
            or not 1 <= len(token) <= 16384
            or type(expires) is not int
            or not 1 <= expires <= 3600
            or value.get("token_type", "").lower() != "bearer"
        ):
            raise ProtocolFailure("deployment_token_invalid")
        self.access, self.expires = token, time.monotonic() + max(0, expires - 10)
        return token

    def endpoint(self, path: str) -> str:
        return self.config.core_url + "/api/v1/deployment-agent/hosts/" + str(self.config.host_id) + path

    def request(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.json(
            "POST", self.endpoint(path), json=payload, headers={"Authorization": "Bearer " + self.token()}
        )
