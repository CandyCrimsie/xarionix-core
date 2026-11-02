import math
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core.access import require_mfa


@pytest.mark.parametrize(
    "claims,allowed",
    [
        ({"acr": "step-up", "auth_time": 1000}, True),
        ({"acr": "step-up", "auth_time": 700}, True),
        ({"acr": "step-up", "auth_time": 699.99}, False),
        ({"acr": "step-up", "auth_time": 1015}, True),
        ({"acr": "step-up", "auth_time": 1015.01}, False),
        ({"auth_time": 1000}, False),
        ({"acr": "1", "auth_time": 1000}, False),
        ({"acr": "step-up", "iat": 1000}, False),
        ({"acr": "step-up", "auth_time": "1000"}, False),
        ({"acr": "step-up", "auth_time": True}, False),
        ({"acr": "step-up", "auth_time": None}, False),
        ({"acr": "step-up", "auth_time": math.nan}, False),
        ({"acr": "step-up", "auth_time": math.inf}, False),
        ({"acr": "step-up", "auth_time": -math.inf}, False),
        ({"acr": ["step-up"], "auth_time": 1000}, False),
    ],
)
def test_assurance_has_deterministic_clock_and_exact_boundaries(claims, allowed):
    ctx = SimpleNamespace(
        claims=claims,
        clock=lambda: 1000,
        config=SimpleNamespace(
            admin_acr_values=["step-up"], oidc_leeway_seconds=15, admin_auth_max_age_seconds=300
        ),
    )
    if allowed:
        require_mfa(ctx)
    else:
        with pytest.raises(HTTPException) as denied:
            require_mfa(ctx)
        assert denied.value.status_code == 403
        assert denied.value.detail == {"code": "configured_recent_mfa_required"}
    ctx.config.admin_acr_values = []
    with pytest.raises(HTTPException):
        require_mfa(ctx)
