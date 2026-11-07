"""Short authorization snapshots. No connection/transaction survives remote execution."""

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select

from app.core.access import Context, fail
from app.core.config import Settings
from app.domains.deployments.model import DeploymentHost, RuntimeDeployment
from app.domains.deployments.service import trusted
from app.domains.identity.model import Identity
from app.domains.installations.model import ModuleInstallation
from app.domains.module_gateway.contracts import APIContract, Operation
from app.domains.module_gateway.model import GatewayIdentity, ModuleAPIContract
from app.domains.packages.model import ModulePackage
from app.domains.rbac.authorization import require
from app.domains.users.model import User


@dataclass(frozen=True)
class Verdict:
    host_id: UUID
    installation_id: UUID
    installation_generation: int
    deployment_generation: int
    package_sha256: str
    contract_sha256: str
    image_digest: str
    actor_id: UUID
    company_id: UUID
    module_id: str
    operation: Operation
    claims: dict[str, Any] = field(repr=False, compare=False)


async def authorize(
    sessions: Any,
    config: Settings,
    claims: dict[str, Any],
    company_id: UUID,
    module_id: str,
    operation_id: str,
) -> Verdict:
    if not 1 <= len(operation_id) <= config.gateway_operation_id_length:
        fail(404, "gateway_operation_not_found")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= time.time():
        fail(401, "gateway_human_token_expired")
    async with sessions() as session, session.begin():
        identity = await session.scalar(
            select(Identity).where(Identity.issuer == claims["iss"], Identity.subject == claims["sub"])
        )
        user = await session.get(User, identity.user_id) if identity else None
        if identity is None or user is None:
            fail(403, "gateway_human_identity_required")
        ctx = Context(session, identity, user, config, claims)
        installation = await session.scalar(
            select(ModuleInstallation).where(ModuleInstallation.module_id == module_id)
        )
        if (
            installation is None
            or installation.status != "installed_enabled"
            or installation.module_type != "standard"
        ):
            fail(404, "gateway_module_unavailable")
        package = await session.get(ModulePackage, installation.package_id)
        contract = await session.get(ModuleAPIContract, installation.package_id)
        if not package or not contract or not await trusted(session, package):
            fail(409, "gateway_package_unavailable")
        api = APIContract.model_validate(contract.document)
        if api.digest() != contract.sha256:
            fail(409, "gateway_contract_binding_changed")
        op = next((o for o in api.operations if o.id == operation_id), None)
        if not op or not op.permission.startswith(installation.namespace + "."):
            fail(404, "gateway_operation_not_found")
        await require(ctx, company_id, op.permission)
        if not await session.scalar(
            select(func.core_module_available(installation.namespace, config.modules_stale_seconds))
        ):
            fail(409, "gateway_module_unavailable")
        runtime = await session.get(RuntimeDeployment, installation.id)
        if (
            runtime is None
            or runtime.profile not in {"module-api-private-v1", "module-api-stateful-v1"}
            or runtime.package_id != package.id
            or runtime.desired != "running"
            or runtime.generation != runtime.observed_generation
            or runtime.image_digest != runtime.observed_image_digest
        ):
            fail(409, "gateway_runtime_binding_changed")
        return Verdict(
            runtime.host_id,
            installation.id,
            installation.generation,
            runtime.generation,
            package.package_sha256,
            contract.sha256,
            runtime.image_digest,
            user.id,
            company_id,
            module_id,
            op,
            {k: claims[k] for k in ("iss", "sub", "exp")},
        )


async def gateway_host(sessions: Any, claims: dict[str, Any], host_id: UUID) -> int:
    async with sessions() as session, session.begin():
        identity = await session.get(GatewayIdentity, host_id)
        host = await session.get(DeploymentHost, host_id)
        if (
            identity is None
            or host is None
            or host.status != "active"
            or identity.status != "active"
            or (identity.issuer, identity.subject, identity.client_id)
            != (claims.get("iss"), claims.get("sub"), claims.get("azp"))
            or claims.get("xarionix_principal") != "gateway"
            or float(claims.get("exp", 0)) <= datetime.now(UTC).timestamp()
        ):
            fail(403, "gateway_host_unavailable")
        return int(identity.revision)
