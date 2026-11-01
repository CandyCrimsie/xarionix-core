import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts import setup

ROOT = Path(__file__).resolve().parents[1]


def test_compose_production_never_exposes_core_or_database_ports():
    base = yaml.safe_load((ROOT / "compose.yaml").read_text())
    managed = yaml.safe_load((ROOT / "compose.keycloak.yaml").read_text())
    for name, service in (base["services"] | managed["services"]).items():
        if name != "nginx":
            assert "ports" not in service
        assert "container_name" not in service
    assert base["services"]["core"]["read_only"] is True
    assert base["services"]["core"]["cap_drop"] == ["ALL"]
    assert base["networks"]["core_db"]["internal"] is True
    assert "-h 127.0.0.1" in base["services"]["postgres"]["healthcheck"]["test"][1]
    assert "-h 127.0.0.1" in managed["services"]["keycloak-postgres"]["healthcheck"]["test"][1]
    assert managed["networks"]["keycloak_db"]["internal"] is True
    assert (
        base["services"]["postgres"]["environment"]["APP_USER"]
        != managed["services"]["keycloak-postgres"]["environment"]["APP_USER"]
    )
    assert "--import-realm" in managed["services"]["keycloak"]["command"]
    assert "docker.sock" not in (ROOT / "compose.yaml").read_text()
    assert "USER 10001:10001" in (ROOT / "Dockerfile").read_text()


def test_alembic_revision_can_render_offline_without_credentials():
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head", "--sql"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "CREATE TABLE identities" in result.stdout
    assert "uq_identity_issuer_subject" in result.stdout
    assert "password" not in result.stdout.lower()


def test_compose_cli_validates_both_modes_without_daemon(tmp_path):
    if not shutil.which("docker"):
        pytest.skip("Docker CLI is not installed")
    # config --format json is kept in memory, never printed (it contains test-only credentials).
    config = setup.DEFAULTS | {
        "PUBLIC_URL": "https://core.example.test",
        "KEYCLOAK_PUBLIC_URL": "https://auth.example.test",
        "OIDC_ISSUER": "https://auth.example.test/realms/xarionix",
        "OIDC_BACKCHANNEL": "http://keycloak:8080/realms/xarionix",
        **{key: "test-only-not-a-real-secret-0123456789" for key in setup.SECRETS},
    }
    path = tmp_path / ".env"
    setup.atomic_write(path, setup.env_text(config))
    command = setup.compose(config, path)
    managed = json.loads(setup.run(command + ["config", "--format", "json"]).stdout)
    assert "keycloak" in managed["services"]
    assert set(managed["services"]["core"]["depends_on"]) == {"keycloak", "migrate"}
    external_config = config | {"KEYCLOAK_MODE": "external", "OIDC_BACKCHANNEL": ""}
    setup.atomic_write(path, setup.env_text(external_config))
    external = json.loads(
        setup.run(setup.compose(external_config, path) + ["config", "--format", "json"]).stdout
    )
    assert "keycloak" not in external["services"]
    assert external["services"]["core"]["environment"]["XARIONIX_KEYCLOAK_MODE"] == "external"
    assert external["services"]["core"]["environment"]["XARIONIX_OIDC_BACKCHANNEL"] == ""
    assert "KC_BOOTSTRAP_ADMIN_PASSWORD" not in external["services"]["core"]["environment"]
