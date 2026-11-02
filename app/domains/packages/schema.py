import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from app.domains.packages.semver import Range, Version

Identifier = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,62}$")]
Namespace = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,39}$")]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)

    @model_validator(mode="before")
    @classmethod
    def no_boolean_versions(cls, value: Any) -> Any:
        if isinstance(value, dict) and any(
            isinstance(value.get(k), bool) for k in ("schema_version", "module_protocol")
        ):
            raise ValueError("Integer versions must not be Boolean")
        return value


def safe_path(value: str) -> str:
    # V1 paths are ASCII POSIX file names, not locale/filesystem dependent names.
    if (
        len(value) > 240
        or not re.fullmatch(r"[A-Za-z0-9_./-]+", value)
        or len(value.split("/")) > 12
        or any(not part or part.startswith(".") or part.endswith(".") for part in value.split("/"))
    ):
        raise ValueError("invalid_archive_path")
    if any(
        part.split(".")[0].upper()
        in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }
        for part in value.split("/")
    ):
        raise ValueError("reserved_archive_path")
    return value


class Module(Strict):
    id: Identifier
    name: str = Field(min_length=1, max_length=160)
    version: str = Field(max_length=120)
    description: str = Field(default="", max_length=1000)
    type: Literal["standard", "autonomous"]
    homepage: str | None = Field(default=None, max_length=512)

    @field_validator("version")
    @classmethod
    def version_valid(cls, value: str) -> str:
        Version.parse(value)
        return value

    @field_validator("id")
    @classmethod
    def not_core(cls, value: str) -> str:
        if value in {"core", "xarionix-core"}:
            raise ValueError("core_module_protected")
        return value


class Publisher(Strict):
    id: Identifier


class Compatibility(Strict):
    core: str = Field(max_length=256)
    module_protocol: Literal[1]

    @field_validator("core")
    @classmethod
    def range_valid(cls, value: str) -> str:
        Range.parse(value)
        return value


class Permission(Strict):
    key: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_.]*\.[a-z][a-z0-9_]*$", max_length=120)
    description: str = Field(min_length=1, max_length=320)
    scope: Literal["company"]


class Permissions(Strict):
    namespace: Namespace
    definitions: list[Permission] = Field(max_length=100)

    @model_validator(mode="after")
    def own_namespace(self) -> "Permissions":
        keys = [item.key for item in self.definitions]
        if self.namespace == "core" or len(set(keys)) != len(keys):
            raise ValueError("namespace_protected_or_duplicate")
        if any(not key.startswith(self.namespace + ".") for key in keys):
            raise ValueError("foreign_permission_namespace")
        return self


class Dependency(Strict):
    module_id: Identifier
    version: str = Field(max_length=256)
    publisher_id: Identifier

    @field_validator("version")
    @classmethod
    def range_valid(cls, value: str) -> str:
        Range.parse(value)
        return value


class Artifact(Strict):
    path: str
    size: int = Field(ge=0, le=32 * 1024 * 1024)
    sha256: Digest

    @field_validator("path")
    @classmethod
    def artifact_path(cls, value: str) -> str:
        safe_path(value)
        if not value.startswith(("payload/backend/", "payload/frontend/", "payload/resources/")):
            raise ValueError("unsupported_artifact_role")
        filename = value.rsplit("/", 1)[-1].lower()
        if (
            filename.startswith(".env")
            or filename.endswith((".pem", ".key", ".p12", ".pfx"))
            or filename in {"id_rsa", "id_ed25519", "credentials", "secrets.json"}
        ):
            raise ValueError("possible_secret_artifact")
        return value


class Manifest(Strict):
    schema_version: Literal[1]
    module: Module
    publisher: Publisher
    compatibility: Compatibility
    permissions: Permissions
    dependencies: list[Dependency] = Field(max_length=64)
    artifacts: list[Artifact] = Field(min_length=1, max_length=1022)

    @model_validator(mode="after")
    def unique_inventory(self) -> "Manifest":
        paths = [item.path.casefold() for item in self.artifacts]
        dependencies = [item.module_id for item in self.dependencies]
        if len(set(paths)) != len(paths) or len(set(dependencies)) != len(dependencies):
            raise ValueError("duplicate_inventory_or_dependency")
        if self.module.id in dependencies:
            raise ValueError("self_dependency")
        return self


class Envelope(Strict):
    schema_version: Literal[1]
    algorithm: Literal["Ed25519"]
    publisher_id: Identifier
    key_id: Identifier
    signature: str = Field(min_length=88, max_length=88)


class TrustKey(Strict):
    publisher_id: Identifier
    key_id: Identifier
    public_key: str = Field(min_length=44, max_length=44)
    publisher_status: Literal["active", "revoked"] = "active"
    status: Literal["active", "revoked"] = "active"
    namespaces: list[Namespace] = Field(max_length=64)


class TrustStore(Strict):
    schema_version: Literal[1]
    keys: list[TrustKey] = Field(max_length=1024)

    @model_validator(mode="after")
    def unique_keys(self) -> "TrustStore":
        identifiers = [(item.publisher_id, item.key_id) for item in self.keys]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("ambiguous_trust_key")
        return self
