import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def validate_url(value: str, *, development: bool = False) -> str:
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise ValueError("URL must have a hostname and no credentials, query or fragment")
    if (
        not re.fullmatch(r"[A-Za-z0-9.:-]+", parsed.hostname)
        or "%" in value
        or any(part in {".", ".."} for part in parsed.path.split("/"))
    ):
        raise ValueError("Invalid URL hostname or path")
    _ = parsed.port
    if parsed.scheme != "https":
        if not (
            development
            and parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1", "keycloak"}
        ):
            raise ValueError("HTTPS is required")
    if value.endswith("/"):
        raise ValueError("URL must not end with a slash")
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="XARIONIX_", env_file=None, extra="ignore", hide_input_in_errors=True
    )
    environment: Literal["production", "development"] = "production"
    install_language: Literal["ru", "en"] = "ru"
    keycloak_mode: Literal["managed", "external"]
    public_url: str
    oidc_issuer: str = Field(max_length=512)
    oidc_audience: str = Field(default="xarionix-core", min_length=1, max_length=120)
    modules_audience: str = Field(
        default="xarionix-core-modules", min_length=1, max_length=120, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    modules_check_in_seconds: int = Field(default=15, ge=1, le=120)
    modules_stale_seconds: int = Field(default=90, ge=10, le=900)
    modules_lease_seconds: int = Field(default=30, ge=5, le=120)
    packages_storage_root: Path = Path("/var/lib/xarionix/packages")
    packages_max_bytes: int = Field(default=128 * 1024 * 1024, ge=1024, le=128 * 1024 * 1024)
    packages_max_files: int = Field(default=1024, ge=3, le=1024)
    packages_max_file_bytes: int = Field(default=32 * 1024 * 1024, ge=1, le=32 * 1024 * 1024)
    packages_max_total_bytes: int = Field(default=256 * 1024 * 1024, ge=1, le=256 * 1024 * 1024)
    packages_max_path_depth: int = Field(default=12, ge=1, le=12)
    packages_max_path_bytes: int = Field(default=240, ge=1, le=240)
    packages_max_ratio: int = Field(default=100, ge=1, le=100)
    packages_max_manifest_bytes: int = Field(default=256 * 1024, ge=1, le=256 * 1024)
    packages_max_signature_bytes: int = Field(default=4096, ge=1, le=4096)
    packages_upload_seconds: int = Field(default=120, ge=5, le=300)
    oidc_algorithms: list[str] = ["RS256"]
    oidc_backchannel: str | None = None
    oidc_cache_seconds: int = Field(default=300, ge=10, le=3600)
    oidc_refresh_cooldown: int = Field(default=10, ge=1, le=60)
    oidc_timeout_seconds: float = Field(default=5, ge=0.1, le=30)
    oidc_leeway_seconds: int = Field(default=15, ge=0, le=60)
    cors_origins: list[str] = []
    docs_enabled: bool = False
    admin_acr_values: list[str] = []
    admin_auth_max_age_seconds: int = Field(default=300, ge=30, le=900)
    db_host: str = Field(default="postgres", min_length=1, max_length=253)
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = Field(default="xarionix_core", min_length=1, max_length=63)
    db_user: str = Field(default="core_app", min_length=1, max_length=63)
    db_password: SecretStr = Field(repr=False)

    @model_validator(mode="after")
    def secure_configuration(self) -> "Settings":
        development = self.environment == "development"
        if not self.packages_storage_root.is_absolute() or ".." in self.packages_storage_root.parts:
            raise ValueError("Package storage must be an absolute operator-configured path")
        if self.modules_audience == self.oidc_audience:
            raise ValueError("Machine and human audiences must differ")
        if self.modules_stale_seconds < self.modules_check_in_seconds * 2:
            raise ValueError("Stale threshold must allow at least two check-ins")
        validate_url(self.public_url, development=development)
        validate_url(self.oidc_issuer, development=development)
        if not self.oidc_algorithms or not set(self.oidc_algorithms) <= {"RS256", "RS384", "RS512", "ES256"}:
            raise ValueError("Only explicitly allowed asymmetric JWT algorithms may be used")
        if self.keycloak_mode == "managed" and not self.oidc_issuer.endswith("/realms/xarionix"):
            raise ValueError("Managed issuer must use the xarionix realm")
        if self.oidc_backchannel:
            expected = "http://keycloak:8080/realms/xarionix"
            if self.keycloak_mode != "managed" or self.oidc_backchannel != expected:
                raise ValueError("Backchannel is restricted to the managed private Keycloak service")
        if len(self.db_password.get_secret_value()) < 24:
            raise ValueError("Database password must contain at least 24 characters")
        if len(self.admin_acr_values) > 16 or any(
            not 1 <= len(value) <= 120 for value in self.admin_acr_values
        ):
            raise ValueError("Administrative ACR allowlist must contain at most 16 bounded exact values")
        for origin in self.cors_origins:
            validate_url(origin, development=development)
            if urlsplit(origin).path:
                raise ValueError("CORS entries must be exact origins, not paths or wildcards")
        return self
