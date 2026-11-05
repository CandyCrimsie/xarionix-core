"""Closed signed operations and transient frames. Never URLs, headers or executable commands."""

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from app.domains.packages.codec import PackageError, canonical, load_json
from app.domains.packages.schema import Manifest, Strict

API_RESOURCE = "payload/resources/module-api-v1.json"
OperationID = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")]


class JSONLimit(Strict):
    kind: Literal["json"]
    max_bytes: int = Field(ge=2, le=1048576)


class Operation(Strict):
    id: OperationID
    method: Literal["POST"]
    permission: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_.]*\.[a-z][a-z0-9_]*$", max_length=120)
    request: JSONLimit
    response: JSONLimit


class APIContract(Strict):
    schema_version: Literal[1]
    operations: list[Operation] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def unique(self) -> "APIContract":
        if len({o.id for o in self.operations}) != len(self.operations):
            raise ValueError("duplicate_operation")
        return self

    def bound(self, manifest: Manifest) -> None:
        declared = {p.key for p in manifest.permissions.definitions}
        if manifest.module.type != "standard" or any(
            o.permission not in declared
            or not o.permission.startswith(manifest.permissions.namespace + ".")
            or o.permission.startswith("core.")
            for o in self.operations
        ):
            raise PackageError("module_api_permission_invalid")

    def digest(self) -> str:
        return hashlib.sha256(canonical(self.model_dump())).hexdigest()


def read_contract(path: Path, manifest: Manifest) -> APIContract | None:
    if API_RESOURCE not in {a.path for a in manifest.artifacts}:
        return None
    from app.domains.packages.archive import read_member

    try:
        with zipfile.ZipFile(path) as archive:
            raw = read_member(archive, API_RESOURCE, 65536)
        artifact = next(a for a in manifest.artifacts if a.path == API_RESOURCE)
        if len(raw) != artifact.size or hashlib.sha256(raw).hexdigest() != artifact.sha256:
            raise PackageError("module_api_inventory_mismatch")
        value = APIContract.model_validate(load_json(raw, 65536))
        value.bound(manifest)
        return value
    except (ValueError, KeyError):
        raise PackageError("module_api_invalid") from None


def json_bytes(value: Any, *, limit: int, depth: int = 16) -> bytes:
    """Bound CPU/collections/nesting and reject NaN, duplicate keys handled at decoding."""
    budget = 10000

    def visit(node: Any, level: int) -> None:
        nonlocal budget
        budget -= 1
        if level > depth or budget < 0:
            raise ValueError("gateway_json_limit")
        if isinstance(node, dict):
            for key, child in node.items():
                if not isinstance(key, str):
                    raise ValueError("gateway_json_invalid")
                visit(child, level + 1)
        elif isinstance(node, list):
            for child in node:
                visit(child, level + 1)
        elif node is not None and not isinstance(node, (str, bool, int, float)):
            raise ValueError("gateway_json_invalid")

    visit(value, 0)
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > limit:
        raise ValueError("gateway_json_limit")
    return encoded


class Frame(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    schema_version: Literal[1] = 1

    @model_validator(mode="before")
    @classmethod
    def integer_version(cls, value: Any) -> Any:
        if isinstance(value, dict) and isinstance(value.get("schema_version"), bool):
            raise ValueError("integer_version_required")
        return value


class ExecutionContext(Frame):
    request_id: UUID
    company_id: UUID
    actor_id: UUID
    operation_id: OperationID
    permission: str = Field(max_length=120)
    installation_id: UUID
    installation_generation: int = Field(ge=1, strict=True)
    deployment_generation: int = Field(ge=1, strict=True)
    deadline: AwareDatetime


class Dispatch(Frame):
    context: ExecutionContext
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    body: dict[str, Any]
    response_max_bytes: int = Field(ge=2, le=1048576, strict=True)
    json_depth: int = Field(default=16, ge=1, le=16, strict=True)


class SessionOpen(Frame):
    protocol: Literal["module-gateway-poll-v1"]


class Poll(Frame):
    session_id: UUID
    sequence: int = Field(ge=1, strict=True)
    capacity: int = Field(default=4, ge=0, le=4, strict=True)


class Correlation(Frame):
    session_id: UUID
    request_id: UUID


class Result(Correlation):
    installation_id: UUID
    installation_generation: int = Field(ge=1, strict=True)
    deployment_generation: int = Field(ge=1, strict=True)
    body: dict[str, Any] | None = None
    error: (
        Literal["module_unavailable", "module_timeout", "module_response_invalid", "runtime_binding_changed"]
        | None
    ) = None

    @model_validator(mode="after")
    def one_outcome(self) -> "Result":
        if (self.body is None) == (self.error is None):
            raise ValueError("one_outcome_required")
        return self
