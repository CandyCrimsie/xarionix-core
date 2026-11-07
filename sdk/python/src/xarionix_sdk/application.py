"""Finite operations, typed server-created context and closed build-time declarations."""

import asyncio
import copy
import inspect
import json
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from .configuration import Configuration
from .storage import StorageSchema
from .validation import check_schema, json_bytes, validate

EMPTY = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}


class ModuleError(Exception):
    """No arbitrary exception text is sent to callers or default logs."""


@dataclass(frozen=True)
class ModuleContext:
    request_id: UUID
    company_id: UUID
    actor_id: UUID
    operation_id: str
    permission: str
    installation_id: UUID
    installation_generation: int
    deployment_generation: int
    deadline: datetime

    @classmethod
    def parse(cls, raw: Any) -> "ModuleContext":
        keys = set(cls.__dataclass_fields__)
        if (
            not isinstance(raw, dict)
            or set(raw) != keys | {"schema_version"}
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
        ):
            raise ModuleError("context_invalid")
        values = {key: raw[key] for key in keys}
        try:
            for key in ("request_id", "company_id", "actor_id", "installation_id"):
                if not isinstance(values[key], str):
                    raise ValueError()
                values[key] = UUID(values[key])
            for key in ("installation_generation", "deployment_generation"):
                if type(values[key]) is not int or not 1 <= values[key] <= 2**63 - 1:
                    raise ValueError()
            values["deadline"] = datetime.fromisoformat(values["deadline"].replace("Z", "+00:00"))
            if (
                values["deadline"].tzinfo is None
                or not 0 < (values["deadline"] - datetime.now(UTC)).total_seconds() <= 15
            ):
                raise ValueError()
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", values["operation_id"]):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ModuleError("context_invalid") from None
        return cls(**values)


Handler = Callable[[ModuleContext, dict[str, Any]], Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class Operation:
    id: str
    permission: str
    handler: Handler
    request: dict[str, Any]
    response: dict[str, Any]
    request_max_bytes: int
    response_max_bytes: int


class Module:
    def __init__(self, *, id: str, namespace: str, version: str, storage: StorageSchema | None = None):
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", id)
            or not re.fullmatch(r"[a-z][a-z0-9_]{1,39}", namespace)
            or namespace == "core"
            or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version)
        ):
            raise ValueError("module_identity_invalid")
        self.id, self.namespace, self.version = id, namespace, version
        self.storage_schema = storage
        self._operations: dict[str, Operation] = {}
        self._frozen = False
        self._configuration: Configuration | None = None
        self.readiness: Callable[[], bool] = lambda: True
        self.shutdown: Callable[[], None] = lambda: None
        self.storage_version: Callable[[], int] | None = None

    def configure(self, configuration: Configuration) -> None:
        if (
            self._configuration is not None
            or configuration.module_id != self.id
            or configuration.package_version != self.version
        ):
            raise ValueError("module_configuration_binding_invalid")
        self._configuration = configuration

    def storage_status(self) -> dict[str, Any]:
        if self._configuration is None or self.storage_version is None or self.storage_schema is None:
            raise ModuleError("storage_not_ready")
        version = self.storage_version()
        if (
            type(version) is not int
            or not self.storage_schema.compatible_minimum <= version <= self.storage_schema.compatible_maximum
        ):
            raise ModuleError("storage_schema_incompatible")
        return {
            "schema_version": 1,
            "installation_id": str(self._configuration.installation_id),
            "installation_generation": self._configuration.installation_generation,
            "data_schema_version": version,
        }

    def operation(
        self,
        id: str,
        *,
        permission: str,
        request: dict[str, Any] | None = None,
        response: dict[str, Any] | None = None,
        request_max_bytes: int = 65536,
        response_max_bytes: int = 65536,
    ) -> Callable[[Handler], Handler]:
        if (
            self._frozen
            or id in self._operations
            or len(self._operations) >= 64
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", id)
            or not re.fullmatch(
                re.escape(self.namespace) + r"\.[a-z][a-z0-9_.]*\.[a-z][a-z0-9_]*", permission
            )
            or len(permission) > 120
            or any(type(n) is not int or not 2 <= n <= 65536 for n in (request_max_bytes, response_max_bytes))
        ):
            raise ValueError("operation_invalid")
        incoming, outgoing = copy.deepcopy(request or EMPTY), copy.deepcopy(response or EMPTY)
        for schema in (incoming, outgoing):
            check_schema(schema)
            if schema["type"] != "object":
                raise ValueError("operation_object_schema_required")

        def decorate(handler: Handler) -> Handler:
            if self._frozen or id in self._operations or not inspect.iscoroutinefunction(handler):
                raise ValueError("operation_handler_invalid")
            self._operations[id] = Operation(
                id, permission, handler, incoming, outgoing, request_max_bytes, response_max_bytes
            )
            return handler

        return decorate

    def contract(self) -> dict[str, Any]:
        if not self._operations:
            raise ValueError("operations_required")
        self._frozen = True
        return {
            "schema_version": 1,
            "operations": [
                {
                    "id": op.id,
                    "method": "POST",
                    "permission": op.permission,
                    "request": {"kind": "json", "max_bytes": op.request_max_bytes},
                    "response": {"kind": "json", "max_bytes": op.response_max_bytes},
                }
                for op in sorted(self._operations.values(), key=lambda item: item.id)
            ],
        }

    def metadata(self) -> dict[str, Any]:
        return {
            **({"storage": self.storage_schema.document()} if self.storage_schema else {}),
            "schema_version": 1,
            "module_id": self.id,
            "namespace": self.namespace,
            "package_version": self.version,
            "gateway_protocol": "module-gateway-poll-v1",
            "api_contract": self.contract(),
            "schemas": {
                op.id: {"request": copy.deepcopy(op.request), "response": copy.deepcopy(op.response)}
                for op in sorted(self._operations.values(), key=lambda item: item.id)
            },
        }

    def check(
        self,
        manifest: dict[str, Any],
        api: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        document = manifest["module"]
        declared = {p["key"] for p in manifest["permissions"]["definitions"]}
        if (
            document["id"] != self.id
            or document["version"] != self.version
            or document["type"] != "standard"
            or manifest["permissions"]["namespace"] != self.namespace
            or type(manifest["compatibility"]["module_protocol"]) is not int
            or manifest["compatibility"]["module_protocol"] != 1
            or any(not key.startswith(self.namespace + ".") for key in declared)
            or not {op.permission for op in self._operations.values()} <= declared
            or (api is not None and api != self.contract())
            or (metadata is not None and metadata != self.metadata())
        ):
            raise ValueError("module_contract_mismatch")
        self.contract()

    async def dispatch(self, operation: str, frame: dict[str, Any]) -> dict[str, Any]:
        self.contract()
        op = self._operations.get(operation)
        if op is None or not isinstance(frame, dict) or set(frame) != {"context", "body"}:
            raise ModuleError("operation_invalid")
        ctx = ModuleContext.parse(frame["context"])
        if self._configuration is not None and (
            ctx.installation_id != self._configuration.installation_id
            or ctx.installation_generation != self._configuration.installation_generation
        ):
            raise ModuleError("runtime_configuration_binding_changed")
        if ctx.operation_id != operation or ctx.permission != op.permission:
            raise ModuleError("operation_invalid")
        try:
            json_bytes(frame["body"], op.request_max_bytes)
            validate(frame["body"], op.request)
            async with asyncio.timeout((ctx.deadline - datetime.now(UTC)).total_seconds()):
                result = await op.handler(ctx, frame["body"])
            json_bytes(result, op.response_max_bytes)
            validate(result, op.response)
        except TimeoutError:
            raise ModuleError("deadline_exceeded") from None
        except Exception:
            raise ModuleError("operation_failed") from None
        if ctx.deadline <= datetime.now(UTC):
            raise ModuleError("deadline_exceeded")
        logging.getLogger("xarionix.module").info(
            json.dumps(
                {
                    "event": "module_operation_completed",
                    "module": self.id,
                    "request_id": str(ctx.request_id),
                }
            )
        )
        return result

    def serve(self) -> None:
        from .server import serve

        serve(self)
