import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import setup


@pytest.fixture
def config():
    return setup.DEFAULTS | {
        "PUBLIC_URL": "https://core.example.test",
        "KEYCLOAK_PUBLIC_URL": "https://auth.example.test",
        "OIDC_ISSUER": "https://auth.example.test/realms/xarionix",
        "OIDC_BACKCHANNEL": "http://keycloak:8080/realms/xarionix",
        "BROWSER_REDIRECT_URI": "https://console.example.test/callback",
        "BROWSER_ORIGIN": "https://console.example.test",
        **{key: "test-secret-not-for-deployment-" + key + "-12345" for key in setup.SECRETS},
    }


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(setup, "ROOT", tmp_path)
    monkeypatch.setattr(setup, "GENERATED", tmp_path / "deploy/generated")
    return tmp_path


def test_dotenv_roundtrip_never_executes_shell(isolated, config):
    path = isolated / "config.env"
    setup.atomic_write(path, setup.env_text(config))
    assert setup.read_env(path) == config
    assert path.stat().st_mode & 0o777 == 0o600
    for payload in (
        "export XARIONIX_DB_PASSWORD=secret",
        "XARIONIX_DB_PASSWORD=$(touch /tmp/not-executed)",
        "XARIONIX_DB_PASSWORD=`id`",
        "XARIONIX_DB_PASSWORD=x\nXARIONIX_DB_PASSWORD=y",
    ):
        setup.atomic_write(path, payload)
        with pytest.raises(setup.SetupError):
            setup.read_env(path)
    path.chmod(0o644)
    with pytest.raises(setup.SetupError):
        setup.read_env(path)


@pytest.mark.parametrize(
    "override",
    [
        {"ENVIRONMENT": "development"},
        {"KEYCLOAK_MODE": "other"},
        {"INSTALL_LANGUAGE": "other"},
        {"PUBLIC_URL": "http://core.example.test"},
        {"PUBLIC_URL": "https://core.example.test/path"},
        {"PUBLIC_URL": "https://core.example.test:bad"},
        {"PUBLIC_URL": "https://*.example.test"},
        {"OIDC_ISSUER": "https://auth.example.test/wrong"},
        {"OIDC_BACKCHANNEL": "http://untrusted"},
        {"BROWSER_REDIRECT_URI": "https://console.example.test/*"},
        {"BROWSER_ORIGIN": "*"},
        {"DB_PASSWORD": "short"},
        {"DOCS_ENABLED": "maybe"},
        {"CORS_ORIGINS": '["*"]'},
        {"CORS_ORIGINS": "{}"},
        {"POSTGRES_IMAGE": "postgres:latest"},
        {"NGINX_UID": "0"},
        {
            "KEYCLOAK_PUBLIC_URL": "https://core.example.test:443",
            "OIDC_ISSUER": "https://core.example.test:443/realms/xarionix",
        },
        {"CORE_TLS_KEY": "unsafe'path"},
    ],
)
def test_configuration_rejected_before_install(config, override):
    with pytest.raises(setup.SetupError):
        setup.validate(config | override)


def test_external_configuration_has_no_admin_access(config):
    external = {
        key: value for key, value in config.items() if not key.startswith(("KC_", "KEYCLOAK_", "BROWSER_"))
    }
    external |= {
        "KEYCLOAK_MODE": "external",
        "OIDC_BACKCHANNEL": "",
        "OIDC_ISSUER": "https://organization.example.test/realms/corporate",
    }
    setup.validate(external)
    command = setup.compose(external, Path("/private/config.env"))
    assert "compose.keycloak.yaml" not in command
    assert "keycloak:8080" not in setup.nginx(external)
    assert "keycloak.key" not in setup.nginx(external)


def test_realm_is_secure_and_has_no_user_passwords_or_client_secret(config):
    realm = setup.realm(config)
    assert realm["registrationAllowed"] is False
    assert realm["bruteForceProtected"] is True
    assert "users" not in realm
    browser = realm["clients"][1]
    assert browser["directAccessGrantsEnabled"] is False
    assert browser["implicitFlowEnabled"] is False
    assert browser["attributes"]["pkce.code.challenge.method"] == "S256"
    assert browser["redirectUris"] == [config["BROWSER_REDIRECT_URI"]]
    assert browser["webOrigins"] == [config["BROWSER_ORIGIN"]]
    assert all(secret not in json.dumps(realm) for secret in (config[key] for key in setup.SECRETS))


def test_nginx_has_overwritten_proxy_headers_and_safe_defaults(config):
    value = setup.nginx(config)
    assert "ssl_protocols TLSv1.2 TLSv1.3" in value
    assert "proxy_set_header X-Forwarded-For $remote_addr" in value
    assert "$proxy_add_x_forwarded_for" not in value
    assert "ssl_reject_handshake on" in value
    assert "client_max_body_size 2m" in value
    assert "access_log off" in value
    assert "keycloak:9000" not in value


@pytest.mark.parametrize("language", ["ru", "en"])
def test_installer_rerun_preserves_secrets_and_avoids_backup_when_identical(
    isolated, config, monkeypatch, capsys, language
):
    config["INSTALL_LANGUAGE"] = language
    source = isolated / "input.env"
    setup.atomic_write(source, setup.env_text(config))
    commands = []
    monkeypatch.setattr(setup, "check_system", lambda: None)
    monkeypatch.setattr(setup, "check_certificate", lambda *args: None)
    monkeypatch.setattr(setup, "check_ports", lambda command: None)
    monkeypatch.setattr(setup, "prepare", lambda config: None)
    monkeypatch.setattr(setup, "verify_health", lambda config: None)

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(setup, "run", run)
    args = argparse.Namespace(env_file=str(source), non_interactive=True, replace_config=False)
    setup.install(args, language)
    first = (isolated / ".env").read_bytes()
    setup.install(args, language)
    assert (isolated / ".env").read_bytes() == first
    assert not (isolated / "backups").exists()
    assert any("--no-deps" in command and command[-1] == "-t" for command in commands)
    assert all("down" not in command for command in commands)
    output = capsys.readouterr()
    assert all(config[key] not in output.out + output.err for key in setup.SECRETS)
    assert setup.message("complete", language) in output.out


def test_replacement_requires_opt_in_and_makes_private_backup(isolated, config, monkeypatch):
    target, source = isolated / ".env", isolated / "input.env"
    setup.atomic_write(target, setup.env_text(config))
    revised = config | {"DOCS_ENABLED": "true"}
    setup.atomic_write(source, setup.env_text(revised))
    monkeypatch.setattr(setup, "check_system", lambda: None)
    args = argparse.Namespace(env_file=str(source), non_interactive=True, replace_config=False)
    with pytest.raises(setup.SetupError) as error:
        setup.install(args, "ru")
    assert error.value.key == "needs_replace"
    assert setup.read_env(target) == config
    monkeypatch.setattr(setup, "check_certificate", lambda *args: None)
    monkeypatch.setattr(setup, "prepare", lambda config: None)
    monkeypatch.setattr(setup, "check_ports", lambda command: None)
    monkeypatch.setattr(setup, "verify_health", lambda config: None)
    monkeypatch.setattr(setup, "run", lambda command, **kw: subprocess.CompletedProcess(command, 0, b"", b""))
    args.replace_config = True
    setup.install(args, "ru")
    (backup,) = (isolated / "backups").iterdir()
    assert backup.stat().st_mode & 0o777 == 0o600
    assert setup.read_env(backup) == config
    assert setup.read_env(target) == revised


def test_dev_config_is_explicit_repeatable_and_secrets_not_printed(isolated, capsys):
    setup.dev_config("en")
    first = (isolated / ".env.dev").read_bytes()
    setup.dev_config("en")
    assert first == (isolated / ".env.dev").read_bytes()
    config = setup.read_env(isolated / ".env.dev")
    assert config["ENVIRONMENT"] == "development"
    assert config["INSTALL_LANGUAGE"] == "en"
    output = capsys.readouterr().out
    assert all(config[key] not in output for key in setup.SECRETS)
    assert json.loads((isolated / "deploy/generated/dev-realm.json").read_text())["sslRequired"] == "none"


@pytest.mark.parametrize(
    "choice,expected,unexpected",
    [("1", "Нужны Linux", "are required"), ("2", "are required", "Нужны Linux")],
)
def test_bash_first_screen_language_then_localized_error(choice, expected, unexpected, tmp_path):
    # Linux validation is made to fail deterministically without contacting Docker or a real deployment.
    (tmp_path / "python3").symlink_to(sys.executable)
    (tmp_path / "dirname").symlink_to(shutil.which("dirname"))
    process = subprocess.run(
        ["/bin/bash", str(Path(__file__).resolve().parents[1] / "install.sh")],
        input=choice + "\n",
        text=True,
        capture_output=True,
        env=os.environ | {"PATH": str(tmp_path)},
    )
    assert process.stdout.startswith("========================================\n         Xarionix Core Setup")
    assert "Выберите язык установки" in process.stdout
    assert "Select installation language" in process.stdout
    assert process.returncode == 1
    assert expected in process.stderr
    assert unexpected not in process.stderr


def test_subprocess_errors_never_reproduce_raw_stderr(monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "docker", stderr=b"private-password JWT cookie")

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(setup.SetupError) as error:
        setup.run(["docker", "info"])
    assert error.value.key == "command"
    assert "private-password" not in str(error.value)


def test_certificate_hostname_key_match_and_permissions(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "3",
            "-subj",
            "/CN=core.example.test",
            "-addext",
            "subjectAltName=DNS:core.example.test",
        ],
        check=True,
        capture_output=True,
    )
    key.chmod(0o600)
    setup.check_certificate(cert, key, "core.example.test")
    with pytest.raises(setup.SetupError):
        setup.check_certificate(cert, key, "wrong.example.test")
    key.chmod(0o644)
    with pytest.raises(setup.SetupError):
        setup.check_certificate(cert, key, "core.example.test")


def test_all_localization_messages_exist_in_both_languages():
    assert all(len(values) == 2 and all(values) for values in setup.MESSAGES.values())


def test_new_template_is_private_and_never_overwrites(isolated, monkeypatch, capsys):
    path = isolated / "config.env"
    monkeypatch.setattr(sys, "argv", ["setup", "init-config", "--env-file", str(path)])
    assert setup.main() == 0
    config = setup.read_env(path)
    assert all(len(config[key]) == 64 for key in setup.SECRETS)
    assert len({config[key] for key in setup.SECRETS}) == len(setup.SECRETS)
    assert all(config[key] not in capsys.readouterr().out for key in setup.SECRETS)
    original = path.read_bytes()
    assert setup.main() == 1
    assert path.read_bytes() == original


def test_healthy_check_never_accepts_http_in_production(config):
    with pytest.raises(setup.SetupError):
        setup.verify_health(config | {"PUBLIC_URL": "http://localhost:8000"}, attempts=1)


def test_busy_port_check_is_read_only_and_allows_own_running_nginx(monkeypatch):
    def busy(command, **kwargs):
        output = b"LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n" if command[0] == "ss" else b""
        return subprocess.CompletedProcess(command, 0, output, b"")

    monkeypatch.setattr(setup, "run", busy)
    with pytest.raises(setup.SetupError) as error:
        setup.check_ports(["docker", "compose"])
    assert error.value.key == "ports"
    monkeypatch.setattr(setup, "run", lambda cmd: subprocess.CompletedProcess(cmd, 0, b"nginx\n", b""))
    setup.check_ports(["docker", "compose"])


def test_private_key_stays_private_but_mount_directory_is_traversable(isolated, config, monkeypatch):
    cert, key = isolated / "source.crt", isolated / "source.key"
    setup.atomic_write(cert, "test-certificate", 0o644)
    setup.atomic_write(key, "test-private-key")
    config |= {
        "CORE_TLS_CERT": str(cert),
        "CORE_TLS_KEY": str(key),
        "KEYCLOAK_TLS_CERT": str(cert),
        "KEYCLOAK_TLS_KEY": str(key),
    }
    monkeypatch.setattr(setup, "check_certificate", lambda *args: None)
    previous = os.umask(0o077)
    try:
        setup.prepare(config)
    finally:
        os.umask(previous)
    assert (setup.GENERATED / "tls").stat().st_mode & 0o777 == 0o755
    assert (setup.GENERATED / "tls/core.key").stat().st_mode & 0o777 == 0o600
    assert (setup.GENERATED / "nginx.conf").stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("language", ["ru", "en"])
def test_unattended_installer_reads_language_without_stdin(tmp_path, language):
    (tmp_path / "python3").symlink_to(sys.executable)
    (tmp_path / "dirname").symlink_to(shutil.which("dirname"))
    env_path = tmp_path / "config.env"
    setup.atomic_write(env_path, f"XARIONIX_INSTALL_LANGUAGE='{language}'\n")
    result = subprocess.run(
        [
            "/bin/bash",
            str(Path(__file__).resolve().parents[1] / "install.sh"),
            "--non-interactive",
            "--env-file",
            str(env_path),
        ],
        input="",
        text=True,
        capture_output=True,
        env=os.environ | {"PATH": str(tmp_path)},
    )
    assert result.returncode == 1
    assert setup.message("requirements", language) in result.stderr
    assert "Choice / Выбор" not in result.stdout
