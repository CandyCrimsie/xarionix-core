"""Outbound business data plane. Separate credentials/process, no deployment job consumption."""

import json
import os
import signal
import sqlite3
import ssl
import stat
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any
from uuid import UUID

import httpx
from pydantic_settings import SettingsConfigDict

from app.domains.deployments.contracts import Delivery
from app.domains.module_gateway.contracts import Dispatch, Result
from scripts.deployment_agent.engine import Engine, EngineFailure
from scripts.deployment_agent.protocol import Config as DeploymentConfig
from scripts.deployment_agent.protocol import Protocol, ProtocolFailure
from scripts.module_agent import backoff


class Config(DeploymentConfig):
    model_config = SettingsConfigDict(
        env_prefix="XARIONIX_GATEWAY_", extra="ignore", hide_input_in_errors=True
    )


class GatewayProtocol(Protocol):
    def __init__(self, config: DeploymentConfig, client: httpx.Client):
        super().__init__(config, client)
        self.token_lock = threading.Lock()

    def token(self) -> str:
        with self.token_lock:
            return super().token()

    def endpoint(self, path: str) -> str:
        return self.config.core_url + "/api/v1/module-gateway/hosts/" + str(self.config.host_id) + path


def acknowledged(config: DeploymentConfig, frame: Dispatch) -> Delivery:
    root = config.storage_root
    if (
        root.is_symlink()
        or root.resolve() != root
        or root.stat().st_uid != os.geteuid()
        or stat.S_IMODE(root.stat().st_mode) & 0o077
    ):
        raise ValueError("gateway_journal_denied")
    path = root / "state.sqlite3"
    if path.is_symlink() or path.stat().st_uid != os.geteuid() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("gateway_journal_denied")
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1) as database:
        row = database.execute(
            "SELECT delivery,receipt FROM runtime WHERE installation=? AND generation=?",
            (str(frame.context.installation_id), frame.context.deployment_generation),
        ).fetchone()
    if not row or not row[1]:
        raise ValueError("gateway_runtime_not_acknowledged")
    receipt = json.loads(row[1])
    if receipt.get("success") is not True or receipt.get("report", {}).get("state") != "running":
        raise ValueError("gateway_runtime_not_ready")
    job = Delivery.model_validate_json(row[0])
    if job.host_id != config.host_id or job.engine_id != config.engine_id:
        raise ValueError("gateway_host_binding_changed")
    return job


class GatewayAgent:
    def __init__(self, protocol: GatewayProtocol, engine: Engine):
        self.protocol, self.engine = protocol, engine
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="module-operation")
        self.work: set[Future[None]] = set()
        self.session: UUID | None = None
        self.session_until = 0.0
        self.sequence = 0

    def execute(self, frame: Dispatch, session: UUID) -> None:
        context = frame.context
        base = {"session_id": str(session), "request_id": str(context.request_id)}
        # Recheck current company authorization immediately before fixed local execution.
        try:
            self.protocol.request("/claim", base)
        except ProtocolFailure:
            return
        outcome: dict[str, Any]
        try:
            job = acknowledged(self.protocol.config, frame)
            outcome = self.engine.business(job, frame)
        except EngineFailure as error:
            outcome = {
                "error": str(error)
                if str(error) in {"module_timeout", "runtime_binding_changed", "module_response_invalid"}
                else "module_unavailable"
            }
        except (OSError, ValueError, sqlite3.Error):
            outcome = {"error": "runtime_binding_changed"}
        result = Result(
            **base,
            installation_id=context.installation_id,
            installation_generation=context.installation_generation,
            deployment_generation=context.deployment_generation,
            **outcome,
        )
        # No retry: a failed response delivery must never run the business operation twice.
        try:
            self.protocol.request("/result", result.model_dump(mode="json"))
        except ProtocolFailure:
            pass

    def cycle(self) -> None:
        self.work = {future for future in self.work if not future.done()}
        if self.session is None or time.monotonic() >= self.session_until:
            value = self.protocol.request(
                "/sessions", {"schema_version": 1, "protocol": "module-gateway-poll-v1"}
            )
            if value.get("protocol") != "module-gateway-poll-v1" or type(value.get("expires_in")) is not int:
                raise ProtocolFailure("gateway_protocol_mismatch")
            self.session = UUID(value["session_id"])
            self.session_until = time.monotonic() + max(0, min(300, value["expires_in"]) - 5)
            self.sequence = 0
        self.sequence += 1
        value = self.protocol.request(
            "/poll",
            {"session_id": str(self.session), "sequence": self.sequence, "capacity": 4 - len(self.work)},
        )
        frames = value.get("requests")
        if not isinstance(frames, list) or len(frames) > 4 or value.get("schema_version") != 1:
            raise ProtocolFailure("gateway_frame_limit")
        for item in frames:
            frame = Dispatch.model_validate(item)
            if len(self.work) >= 4:
                # Offered but unclaimed => no operation ran. Core deadline bounds its queue.
                continue
            self.work.add(self.pool.submit(self.execute, frame, self.session))

    def close(self) -> None:
        self.pool.shutdown(wait=True, cancel_futures=True)


def main() -> None:
    stop = threading.Event()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, lambda *args: stop.set())
    try:
        config = Config()
        engine = Engine(config.engine_socket, config.engine_id)
        try:
            with httpx.Client(
                verify=ssl.create_default_context(), timeout=20, follow_redirects=False, trust_env=False
            ) as client:
                agent = GatewayAgent(GatewayProtocol(config, client), engine)
                failures = 0
                try:
                    while not stop.is_set():
                        try:
                            agent.cycle()
                            failures = 0
                        except (ProtocolFailure, EngineFailure, OSError, ValueError):
                            agent.session = None
                            failures += 1
                        if failures:
                            stop.wait(backoff(failures))
                finally:
                    agent.close()
        finally:
            engine.close()
    except (OSError, ValueError, EngineFailure):
        raise SystemExit("Gateway Agent configuration or local state unavailable") from None


if __name__ == "__main__":
    main()
