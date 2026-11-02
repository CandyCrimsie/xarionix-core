"""Minimal outbound-only demonstration agent. No DB, incoming listener or shell execution."""

import json
import secrets
import signal
import ssl
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.api.v1.module_schemas import CommandDelivery
from app.core.config import validate_url


class AgentConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="XARIONIX_AGENT_", extra="ignore", hide_input_in_errors=True)
    core_url: str = Field(max_length=512)
    issuer: str = Field(max_length=512)
    client_id: str = Field(min_length=1, max_length=120)
    client_secret: SecretStr = Field(repr=False, min_length=24)
    instance_id: UUID
    isolated_http: bool = False
    test_oidc_transport: str | None = None
    max_failures: int = Field(default=8, ge=1, le=20)

    @model_validator(mode="after")
    def transport(self) -> "AgentConfig":
        from urllib.parse import urlsplit

        for url in (self.core_url, self.issuer):
            if self.isolated_http and urlsplit(url).scheme == "http":
                # Explicit disposable topology, never arbitrary host / URL input.
                if urlsplit(url).hostname not in {"localhost", "127.0.0.1", "core", "keycloak"}:
                    raise ValueError("Isolated HTTP endpoint not allowed")
                validate_url(url.replace("http://core", "http://localhost"), development=True)
            else:
                validate_url(url)
        if self.test_oidc_transport and (
            not self.isolated_http or self.test_oidc_transport != "http://keycloak:8080/realms/xarionix"
        ):
            raise ValueError("Token transport override is disposable-only")
        return self


class AgentFailure(Exception):
    """Only stable non-secret error codes may escape the protocol client."""


class Revoked(AgentFailure):
    pass


def jitter() -> float:
    return secrets.randbelow(1001) / 1000


def backoff(failures: int, jitter: Callable[[], float] = jitter) -> float:
    return min(60.0, 2.0 ** min(failures, 6)) * (0.8 + 0.2 * jitter())


class Agent:
    def __init__(
        self, config: AgentConfig, client: httpx.Client, clock: Callable[[], float] = time.monotonic
    ):
        self.config, self.client, self.clock = config, client, clock
        self._access: str | None = None
        self._expires = 0.0
        self._endpoint: str | None = None
        self.results: OrderedDict[UUID, tuple[dict[str, Any], datetime]] = OrderedDict()
        self.pending: dict[UUID, tuple[dict[str, Any], datetime]] = {}

    def json_request(self, method: str, url: str, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        try:
            with self.client.stream(method, url, **kwargs) as response:
                data = bytearray()
                for chunk in response.iter_bytes(8192):
                    data.extend(chunk)
                    if len(data) > 65536:
                        raise AgentFailure("response_too_large")
                value = json.loads(data) if data else {}
                if not isinstance(value, dict):
                    raise AgentFailure("invalid_response")
                return response.status_code, value
        except (httpx.HTTPError, ValueError, TypeError):
            raise AgentFailure("transport_or_protocol_error") from None

    def token(self) -> str:
        if self._access is not None and self.clock() < self._expires:
            return self._access
        base = self.config.test_oidc_transport or self.config.issuer
        if self._endpoint is None:
            status, discovery = self.json_request("GET", base + "/.well-known/openid-configuration")
            expected = self.config.issuer + "/protocol/openid-connect/token"
            if (
                status != 200
                or discovery.get("issuer") != self.config.issuer
                or discovery.get("token_endpoint") != expected
            ):
                raise AgentFailure("untrusted_discovery")
            self._endpoint = base + "/protocol/openid-connect/token"
        status, value = self.json_request(
            "POST",
            self._endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret.get_secret_value(),
            },
        )
        if status in {400, 401, 403}:
            raise Revoked("credentials_rejected")
        expires, token = value.get("expires_in"), value.get("access_token")
        if (
            status != 200
            or not isinstance(value.get("token_type"), str)
            or value["token_type"].casefold() != "bearer"
            or type(expires) is not int
            or not 1 <= expires <= 3600
            or not isinstance(token, str)
            or not 1 <= len(token) <= 16384
        ):
            raise AgentFailure("invalid_token_response")
        self._access, self._expires = token, self.clock() + max(0.1, expires - min(30, expires / 5))
        return token

    def request(self, path: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        for attempt in range(2):
            status, value = self.json_request(
                "POST",
                self.config.core_url + "/api/v1/module-agent" + path,
                headers={"Authorization": "Bearer " + self.token()},
                json=payload,
            )
            if status == 401 and attempt == 0:
                self._access, self._expires = None, 0
                continue
            if status in {401, 403, 404}:
                raise Revoked("module_access_denied")
            if status == 429:
                raise AgentFailure("rate_limited")
            if status >= 400:
                raise AgentFailure("core_request_rejected")
            return status, value
        raise AgentFailure("authentication_failed")

    def result(self, command: CommandDelivery) -> dict[str, Any]:
        now = datetime.now(UTC)
        for identifier in list(self.results):
            if self.results[identifier][1] <= now:
                del self.results[identifier]
        if command.id not in self.results:
            value = (
                {"kind": "pong"}
                if command.operation == "ping"
                else {"kind": "status", "health": "healthy", "agent_version": "0.1.0"}
            )
            self.results[command.id] = (value, command.expires_at)
            while len(self.results) > 256:
                self.results.popitem(last=False)
        return self.results[command.id][0]

    def flush_acknowledgements(self) -> None:
        for identifier, (result, expiry) in list(self.pending.items()):
            if expiry <= datetime.now(UTC):
                del self.pending[identifier]
                continue
            status, _ = self.request(
                f"/commands/{identifier}/ack", {"instance_id": str(self.config.instance_id), "result": result}
            )
            if status == 200:
                del self.pending[identifier]

    def step(self) -> int:
        self.flush_acknowledgements()
        _, value = self.request(
            "/check-in",
            {
                "instance_id": str(self.config.instance_id),
                "protocol_version": 1,
                "health": "healthy",
                "agent_version": "0.1.0",
            },
        )
        interval = value.get("check_in_seconds")
        commands = value.get("commands", [])
        if (
            type(interval) is not int
            or not 1 <= interval <= 120
            or not isinstance(commands, list)
            or len(commands) > 10
        ):
            raise AgentFailure("invalid_check_in_response")
        try:
            for item in commands:
                command = CommandDelivery.model_validate(item)
                if command.expires_at > datetime.now(UTC):
                    self.pending[command.id] = (self.result(command), command.expires_at)
        except ValueError:
            raise AgentFailure("unsupported_command_contract") from None
        self.flush_acknowledgements()
        return interval


def main() -> int:
    try:
        config = AgentConfig()
    except ValueError:
        print('{"event":"agent_invalid_configuration"}', flush=True)
        return 2
    stop = threading.Event()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, lambda *_: stop.set())
    failures = 0
    with httpx.Client(
        verify=ssl.create_default_context(), follow_redirects=False, trust_env=False, timeout=10
    ) as client:
        agent = Agent(config, client)
        while not stop.is_set():
            try:
                interval = agent.step()
                failures = 0
                print('{"event":"agent_check_in_ok"}', flush=True)
                stop.wait(interval * (1 + jitter() * 0.1))
            except Revoked:
                print('{"event":"agent_access_denied"}', flush=True)
                return 3
            except AgentFailure:
                failures += 1
                print('{"event":"agent_retry"}', flush=True)
                if failures >= config.max_failures:
                    return 2
                stop.wait(backoff(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
