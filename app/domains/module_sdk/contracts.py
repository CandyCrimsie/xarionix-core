"""Signed SDK declarations, parsed as data. Core never imports module Python."""

import hashlib
import zipfile
from typing import Any, Literal

from pydantic import Field, model_validator

from app.domains.module_gateway.contracts import APIContract
from app.domains.packages.codec import PackageError, canonical, load_json
from app.domains.packages.schema import Digest, Identifier, Manifest, Namespace, Strict

SDK_RESOURCE = "payload/resources/module-sdk-v1.json"


class MigrationDeclaration(Strict):
    version: int = Field(ge=1, le=128)
    sha256: Digest


class StorageDeclaration(Strict):
    engine: Literal["sqlite"]
    data_schema_version: int = Field(ge=1, le=128)
    compatible_minimum: int = Field(ge=1, le=128)
    compatible_maximum: int = Field(ge=1, le=128)
    migrations: list[MigrationDeclaration] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def consistent(self) -> "StorageDeclaration":
        if not self.compatible_minimum <= self.data_schema_version <= self.compatible_maximum or [
            step.version for step in self.migrations
        ] != list(range(1, self.data_schema_version + 1)):
            raise ValueError("storage_schema_inconsistent")
        return self


def validate_schema(value: Any, depth: int = 0) -> None:
    if not isinstance(value, dict) or depth > 8:
        raise ValueError("sdk_schema_invalid")
    allowed = {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "minimum",
        "maximum",
        "enum",
    }
    kind = value.get("type")
    if set(value) - allowed or kind not in {
        "object",
        "array",
        "string",
        "integer",
        "number",
        "boolean",
        "null",
    }:
        raise ValueError("sdk_schema_unsupported")
    if kind == "object":
        props, required = value.get("properties", {}), value.get("required", [])
        if (
            value.get("additionalProperties") is not False
            or not isinstance(props, dict)
            or len(props) > 64
            or not isinstance(required, list)
            or any(not isinstance(k, str) for k in required)
            or len(set(required)) != len(required)
            or not set(required) <= set(props)
        ):
            raise ValueError("sdk_schema_object_invalid")
        for child in props.values():
            validate_schema(child, depth + 1)
    if kind == "array":
        if type(value.get("maxItems")) is not int or not 0 <= value["maxItems"] <= 1000:
            raise ValueError("sdk_schema_array_bound_required")
        validate_schema(value.get("items"), depth + 1)
    if kind == "string" and (type(value.get("maxLength")) is not int or not 0 <= value["maxLength"] <= 65536):
        raise ValueError("sdk_schema_string_bound_required")
    for key in {"minLength", "maxLength", "minItems", "maxItems", "minimum", "maximum"} & set(value):
        if type(value[key]) is not int:
            raise ValueError("sdk_schema_integer_bound_required")
    if "enum" in value and (not isinstance(value["enum"], list) or not 1 <= len(value["enum"]) <= 64):
        raise ValueError("sdk_schema_enum_invalid")
    if len(canonical(value)) > 16384:
        raise ValueError("sdk_schema_too_large")


class SDKContract(Strict):
    schema_version: Literal[1]
    module_id: Identifier
    namespace: Namespace
    package_version: str = Field(max_length=120)
    gateway_protocol: Literal["module-gateway-poll-v1"]
    api_contract: APIContract
    schemas: dict[str, dict[str, Any]]
    storage: StorageDeclaration | None = None

    def bound(self, manifest: Manifest, api: APIContract | None) -> None:
        if (
            self.module_id != manifest.module.id
            or self.namespace != manifest.permissions.namespace
            or self.package_version != manifest.module.version
            or api != self.api_contract
            or set(self.schemas) != {op.id for op in self.api_contract.operations}
        ):
            raise PackageError("module_sdk_binding_invalid")
        self.api_contract.bound(manifest)
        for schemas in self.schemas.values():
            if set(schemas) != {"request", "response"}:
                raise PackageError("module_sdk_schema_invalid")
            for schema in schemas.values():
                validate_schema(schema)
                if schema["type"] != "object":
                    raise PackageError("module_sdk_object_schema_required")

    def document(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)

    def digest(self) -> str:
        return hashlib.sha256(canonical(self.document())).hexdigest()


def read_sdk_contract(path: Any, manifest: Manifest, api: APIContract | None) -> SDKContract | None:
    artifact = next((a for a in manifest.artifacts if a.path == SDK_RESOURCE), None)
    if artifact is None:
        return None
    from app.domains.packages.archive import read_member

    try:
        with zipfile.ZipFile(path) as archive:
            raw = read_member(archive, SDK_RESOURCE, 65536)
        if len(raw) != artifact.size or hashlib.sha256(raw).hexdigest() != artifact.sha256:
            raise PackageError("module_sdk_inventory_mismatch")
        value = SDKContract.model_validate(load_json(raw, 65536))
        value.bound(manifest, api)
        return value
    except (ValueError, KeyError, TypeError):
        raise PackageError("module_sdk_invalid") from None
