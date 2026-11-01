import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.main import create_app


def test_production_defaults(settings):
    assert settings.environment == "production"
    assert settings.docs_enabled is False
    assert settings.cors_origins == []
    assert "test-password" not in repr(settings)
    assert create_app(settings).openapi_url is None


@pytest.mark.parametrize(
    "override",
    [
        {"keycloak_mode": "other"},
        {"install_language": "fr"},
        {"public_url": "http://core.example.test"},
        {"oidc_issuer": "http://auth.example.test/realm"},
        {"oidc_issuer": "https://user:secret@auth.example.test/r"},
        {"oidc_issuer": "https://auth.example.test/r?x=1"},
        {"oidc_issuer": "https://auth.example.test/r/"},
        {"oidc_issuer": "https://auth.example.test/r/../private"},
        {"oidc_algorithms": ["HS256"]},
        {"oidc_algorithms": ["none"]},
        {"oidc_algorithms": []},
        {"db_password": "short"},
        {"cors_origins": ["*"]},
        {"cors_origins": ["https://*.example.test"]},
        {"cors_origins": ["https://web.example.test/callback"]},
        {"oidc_cache_seconds": 0},
        {"oidc_backchannel": "http://evil.test"},
        {"db_port": 0},
    ],
)
def test_rejects_unsafe_configuration(settings, override):
    with pytest.raises(ValidationError):
        Settings(**(settings.model_dump() | override))


def test_managed_transport_must_be_explicit_private_service(settings):
    config = Settings(
        **(
            settings.model_dump()
            | {"keycloak_mode": "managed", "oidc_backchannel": "http://keycloak:8080/realms/xarionix"}
        )
    )
    assert config.oidc_issuer.startswith("https://")


def test_development_is_explicit(settings):
    Settings(
        **(
            settings.model_dump()
            | {
                "environment": "development",
                "public_url": "http://localhost:8000",
                "oidc_issuer": "http://localhost:8090/realms/xarionix",
            }
        )
    )
    with pytest.raises(ValidationError):
        Settings(
            **(
                settings.model_dump()
                | {"environment": "development", "oidc_issuer": "http://public.example.test/realm"}
            )
        )


def test_startup_configuration_error_does_not_expose_environment(monkeypatch):
    for key in list(__import__("os").environ):
        if key.startswith("XARIONIX_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("XARIONIX_DB_PASSWORD", "highly-sensitive")
    with pytest.raises(RuntimeError) as error:
        create_app()
    assert "highly-sensitive" not in str(error.value)
