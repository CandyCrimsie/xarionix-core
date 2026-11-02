"""Trusted deployment contract, NOT a module installer or public registration API."""

import re
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.access import fail
from app.domains.rbac.model import PermissionNamespace


class PermissionDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    key: str = Field(min_length=5, max_length=120)
    description: str = Field(min_length=1, max_length=320)
    scope: str = "company"
    protected: bool = False
    owner_grantable: bool = False


class NamespaceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    namespace: str = Field(pattern=r"^[a-z][a-z0-9_]{1,39}$")
    version: int = Field(ge=1, strict=True)
    permissions: tuple[PermissionDefinition, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def bounded_company_permissions(self) -> "NamespaceManifest":
        keys = [item.key for item in self.permissions]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate permission key")
        for item in self.permissions:
            if (
                not re.fullmatch(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_.]*\.[a-z][a-z0-9_]*", item.key)
                or not item.key.startswith(self.namespace + ".")
                or item.scope != "company"
                or item.key == "core.platform.admin"
                or (item.protected and item.owner_grantable)
            ):
                raise ValueError("Invalid namespace or protected authority")
        return self


@dataclass(frozen=True)
class DeploymentAuthority:
    # Constructed by reviewed deployment code, never deserialized from a JWT or
    # an HTTP/module payload. Future package signature verification is separate.
    component: str


async def validate_registration(
    session: AsyncSession, authority: DeploymentAuthority, manifest: NamespaceManifest
) -> NamespaceManifest:
    namespace = await session.get(PermissionNamespace, manifest.namespace)
    if namespace is None or namespace.owner != authority.component or namespace.state != "active":
        fail(403, "namespace_registration_denied")
    if manifest.namespace == "core" and authority.component != "xarionix-core":
        fail(403, "core_namespace_protected")
    # Applying a validated manifest is a trusted Alembic deployment operation:
    # ordinary runtime DML is intentionally blocked by core_catalog_guard.
    return manifest
