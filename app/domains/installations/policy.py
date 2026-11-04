"""Pure, bounded decisions shared by plans and the trusted executor."""

import hashlib
from typing import Any

from app.core.config import Settings
from app.domains.packages.codec import canonical
from app.domains.packages.schema import Manifest
from app.version import VERSION

ACTIONS = frozenset({"install", "enable", "disable", "update", "uninstall", "rollback"})
PLAN_SECONDS = 600
MAX_PINS = 32


def digest(body: dict[str, Any]) -> str:
    return hashlib.sha256(b"XARIONIX-INSTALL-PLAN-V1\x00" + canonical(body)).hexdigest()


def policy(config: Settings) -> dict[str, Any]:
    return {
        "version": 1,
        "core": VERSION,
        "protocol": 1,
        "admin_acr_values": sorted(config.admin_acr_values),
        "admin_auth_max_age_seconds": config.admin_auth_max_age_seconds,
        "oidc_leeway_seconds": config.oidc_leeway_seconds,
        "oidc_issuer": config.oidc_issuer,
        "permission_flags": {"protected": False, "owner_grantable": True},
    }


def runtime_mode(manifest: Manifest) -> str:
    if manifest.module.type == "autonomous":
        return "external_agent"
    if any(a.path == "payload/resources/runtime-v1.json" for a in manifest.artifacts):
        return "oci_v1"
    return (
        "metadata_only"
        if all(a.path.startswith("payload/resources/") for a in manifest.artifacts)
        else "not_supported_in_4c"
    )


def transition(action: str, state: str | None) -> str:
    allowed: dict[str, set[str | None]] = {
        "install": {None, "removed"},
        "enable": {"installed_disabled"},
        "disable": {"installed_enabled"},
        "update": {"installed_disabled", "installed_enabled"},
        "uninstall": {"installed_disabled"},
        "rollback": {"installed_disabled", "installed_enabled"},
    }
    if action not in allowed or state not in allowed[action]:
        raise ValueError("installation_transition_invalid")
    return (
        "removed"
        if action == "uninstall"
        else "installed_enabled"
        if action == "enable"
        else "installed_disabled"
    )
