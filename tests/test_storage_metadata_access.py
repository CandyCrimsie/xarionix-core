import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1 import deployments, installations, module_gateway, packages
from app.core.access import Context
from app.domains.platform.model import PlatformAdmin


@pytest.mark.parametrize("endpoint", ["storage", "sdk", "gateway", "plans"])
@pytest.mark.parametrize(
    "admin,fresh,code",
    [(False, True, "platform_admin_required"), (True, False, "configured_recent_mfa_required")],
)
async def test_storage_and_admin_metadata_never_bypass_platform_membership_or_fresh_mfa(
    settings, monkeypatch, endpoint, admin, fresh, code
):
    session = MagicMock()
    session.refresh = AsyncMock()
    session.get = AsyncMock(return_value=SimpleNamespace(active=True) if admin else None)
    monkeypatch.setattr("app.core.locking.administration", AsyncMock())
    config = settings.model_copy(update={"admin_acr_values": ["test-step-up"]})
    ctx = Context(
        session,
        SimpleNamespace(principal_type="human"),
        SimpleNamespace(id=uuid4(), status="active"),
        config,
        {"acr": "test-step-up", "auth_time": time.time() if fresh else 0},
    )
    with pytest.raises(HTTPException) as error:
        match endpoint:
            case "storage":
                await deployments.storage_detail(uuid4(), ctx)
            case "sdk":
                await packages.sdk_detail(uuid4(), ctx)
            case "gateway":
                await module_gateway.identity_detail(uuid4(), ctx)
            case "plans":
                await installations.plans(ctx)
    assert error.value.status_code == 403 and error.value.detail["code"] == code
    assert session.get.await_count == 1 and session.get.await_args.args[0] == PlatformAdmin
    session.scalars.assert_not_called()


async def test_gateway_identity_status_rejects_a_stale_displayed_revision_before_mutation(
    settings, monkeypatch
):
    identity = SimpleNamespace(status="active", revision=8)
    session = MagicMock(get=AsyncMock(return_value=identity))
    ctx = SimpleNamespace(session=session)
    monkeypatch.setattr(module_gateway, "require_platform", AsyncMock())
    with pytest.raises(HTTPException) as error:
        await module_gateway.identity_status(
            uuid4(), module_gateway.IdentityStatus(status="revoked", expected_revision=7), ctx
        )
    assert error.value.status_code == 409
    assert identity.status == "active" and identity.revision == 8
