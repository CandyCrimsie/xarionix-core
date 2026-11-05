"""Single-worker, bounded ephemeral relay. No bodies in PostgreSQL or deployment jobs."""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException

from app.core.access import fail
from app.core.config import Settings
from app.domains.module_gateway.authorization import Verdict, authorize
from app.domains.module_gateway.contracts import Dispatch, ExecutionContext, Result, json_bytes


@dataclass
class Session:
    id: UUID
    revision: int
    expires: float
    last_seen: float = field(default_factory=time.monotonic)
    sequence: int = 0
    polling: bool = False


@dataclass
class Pending:
    verdict: Verdict
    dispatch: Dispatch
    future: asyncio.Future[dict[str, Any]]
    offered: bool = False
    claimed: bool = False


class Relay:
    def __init__(self, config: Settings, sessions: Any):
        self.config, self.database = config, sessions
        self.sessions: dict[UUID, Session] = {}
        self.pending: dict[UUID, Pending] = {}
        self.wakeup = asyncio.Event()

    def session(self, host: UUID, identifier: UUID, revision: int) -> Session:
        value = self.sessions.get(host)
        if (
            value is None
            or value.id != identifier
            or value.revision != revision
            or value.expires <= time.time()
        ):
            fail(409, "gateway_session_expired")
        return value

    def open(self, host: UUID, revision: int, expires: float) -> UUID:
        # Explicit authenticated replacement invalidates old correlations; never redeliver a write.
        for p in self.pending.values():
            if p.verdict.host_id == host and not p.future.done():
                p.future.set_exception(HTTPException(503, detail={"code": "gateway_session_lost"}))
        for key, value in list(self.sessions.items()):
            if value.expires <= time.time():
                del self.sessions[key]
        if host not in self.sessions and len(self.sessions) >= 128:
            fail(503, "gateway_session_capacity")
        value = Session(uuid4(), revision, min(expires, time.time() + 300))
        self.sessions[host] = value
        return value.id

    async def invoke(
        self, verdict: Verdict, body: dict[str, Any], *, request_id: UUID | None = None
    ) -> dict[str, Any]:
        config = self.config
        session = self.sessions.get(verdict.host_id)
        if session is None or session.expires <= time.time() or time.monotonic() - session.last_seen > 8:
            fail(503, "gateway_agent_disconnected")
        active = list(self.pending.values())
        if (
            len(active) >= config.gateway_pending
            or sum(p.verdict.host_id == verdict.host_id for p in active) >= config.gateway_per_host
            or sum(p.verdict.installation_id == verdict.installation_id for p in active)
            >= config.gateway_per_installation
            or sum(p.verdict.actor_id == verdict.actor_id for p in active) >= config.gateway_per_user
        ):
            fail(429, "gateway_capacity_exceeded")
        try:
            json_bytes(
                body,
                limit=min(config.gateway_request_bytes, verdict.operation.request.max_bytes),
                depth=config.gateway_json_depth,
            )
        except ValueError:
            fail(413, "gateway_request_limit")
        identifier = request_id or uuid4()
        frame = Dispatch(
            context=ExecutionContext(
                request_id=identifier,
                company_id=verdict.company_id,
                actor_id=verdict.actor_id,
                operation_id=verdict.operation.id,
                permission=verdict.operation.permission,
                installation_id=verdict.installation_id,
                installation_generation=verdict.installation_generation,
                deployment_generation=verdict.deployment_generation,
                deadline=datetime.now(UTC) + timedelta(seconds=config.gateway_deadline_seconds),
            ),
            package_sha256=verdict.package_sha256,
            contract_sha256=verdict.contract_sha256,
            image_digest=verdict.image_digest,
            body=body,
            response_max_bytes=min(config.gateway_response_bytes, verdict.operation.response.max_bytes),
            json_depth=config.gateway_json_depth,
        )
        pending = Pending(verdict, frame, asyncio.get_running_loop().create_future())
        self.pending[identifier] = pending
        self.wakeup.set()
        try:
            async with asyncio.timeout(config.gateway_deadline_seconds):
                return await pending.future
        except TimeoutError:
            fail(504, "gateway_timeout_outcome_unknown")
        finally:
            self.pending.pop(identifier, None)
            if not pending.future.done():
                pending.future.cancel()

    async def poll(
        self, host: UUID, identifier: UUID, revision: int, sequence: int, capacity: int = 4
    ) -> list[Dispatch]:
        session = self.session(host, identifier, revision)
        if session.polling or sequence <= session.sequence:
            fail(409, "gateway_replay_rejected")
        session.sequence, session.polling, session.last_seen = sequence, True, time.monotonic()
        try:
            if capacity == 0 or not any(
                p.verdict.host_id == host and not p.offered for p in self.pending.values()
            ):
                self.wakeup.clear()
                try:
                    async with asyncio.timeout(2):
                        await self.wakeup.wait()
                except TimeoutError:
                    pass
            self.session(host, identifier, revision)
            frames: list[Dispatch] = []
            if capacity == 0:
                return frames
            for p in self.pending.values():
                if p.verdict.host_id == host and not p.offered and not p.future.done():
                    p.offered = True
                    frames.append(p.dispatch)
                    if len(frames) == capacity:
                        break
            return frames
        finally:
            session.polling = False
            session.last_seen = time.monotonic()

    def correlation(self, host: UUID, identifier: UUID, request_id: UUID, revision: int) -> Pending:
        self.session(host, identifier, revision)
        pending = self.pending.get(request_id)
        if (
            pending is None
            or pending.verdict.host_id != host
            or not pending.offered
            or pending.future.done()
            or pending.dispatch.context.deadline <= datetime.now(UTC)
        ):
            fail(409, "gateway_correlation_rejected")
        return pending

    async def revalidate(self, pending: Pending) -> None:
        v = pending.verdict
        try:
            current = await authorize(
                self.database, self.config, v.claims, v.company_id, v.module_id, v.operation.id
            )
            if current != v:
                fail(409, "gateway_authorization_changed")
        except HTTPException as error:
            if not pending.future.done():
                pending.future.set_exception(error)
            raise

    async def claim(self, host: UUID, identifier: UUID, request_id: UUID, revision: int) -> None:
        p = self.correlation(host, identifier, request_id, revision)
        if p.claimed:
            fail(409, "gateway_duplicate_dispatch")
        # Set before awaiting SQL so two concurrent claims cannot both succeed.
        p.claimed = True
        await self.revalidate(p)
        self.correlation(host, identifier, request_id, revision)

    async def complete(self, host: UUID, result: Result, revision: int) -> None:
        p = self.correlation(host, result.session_id, result.request_id, revision)
        c = p.dispatch.context
        if not p.claimed or (
            result.installation_id,
            result.installation_generation,
            result.deployment_generation,
        ) != (c.installation_id, c.installation_generation, c.deployment_generation):
            fail(409, "gateway_response_binding_rejected")
        if result.error:
            p.future.set_exception(HTTPException(502, detail={"code": result.error}))
            return
        try:
            json_bytes(result.body, limit=p.dispatch.response_max_bytes, depth=p.dispatch.json_depth)
        except ValueError:
            p.future.set_exception(HTTPException(502, detail={"code": "gateway_response_limit"}))
            fail(422, "gateway_response_limit")
        await self.revalidate(p)
        self.correlation(host, result.session_id, result.request_id, revision)
        p.future.set_result({"request_id": str(result.request_id), "body": result.body})

    def close(self) -> None:
        for p in self.pending.values():
            if not p.future.done():
                p.future.set_exception(HTTPException(503, detail={"code": "gateway_shutdown"}))
        self.sessions.clear()
