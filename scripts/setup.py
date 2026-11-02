"""Standard-library-only installer. Never sources dotenv files or prints subprocess output."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import secrets
import shutil
import ssl

# Deployment needs fixed executable argv; no shell or eval is used.
import subprocess  # nosec B404
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Never
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "deploy/generated"
SECRETS = (
    "DB_PASSWORD",
    "DB_BOOTSTRAP_PASSWORD",
    "KC_DB_PASSWORD",
    "KC_DB_BOOTSTRAP_PASSWORD",
    "KC_ADMIN_PASSWORD",
)
DEFAULTS = {
    "ENVIRONMENT": "production",
    "INSTALL_LANGUAGE": "ru",
    "KEYCLOAK_MODE": "managed",
    "OIDC_AUDIENCE": "xarionix-core",
    "MODULES_AUDIENCE": "xarionix-core-modules",
    "MODULES_CHECK_IN_SECONDS": "15",
    "MODULES_STALE_SECONDS": "90",
    "MODULES_LEASE_SECONDS": "30",
    "DOCS_ENABLED": "false",
    "CORS_ORIGINS": "[]",
    "ADMIN_ACR_VALUES": "[]",
    "ADMIN_AUTH_MAX_AGE_SECONDS": "300",
    "POSTGRES_IMAGE": "postgres:18.6-alpine@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5",
    "KEYCLOAK_IMAGE": "quay.io/keycloak/keycloak:26.8.1@sha256:3f3c5f8e03c614774b4bd9173b88391fefa4153bfc010d8012d59ad825377332",
    "NGINX_IMAGE": "nginxinc/nginx-unprivileged:1.30.6-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03",
    "NGINX_UID": str(os.getuid() or 101),
}
MESSAGES = {
    "system": ("Проверка системы", "Checking the system"),
    "requirements": (
        "Нужны Linux, Python 3.12+, Docker с Compose v2+, OpenSSL, ss и доступ к Docker daemon.",
        "Linux, Python 3.12+, Docker with Compose v2+, OpenSSL, ss and Docker daemon access are required.",
    ),
    "invalid": (
        "Некорректная или неполная конфигурация. Проверьте переменную: ",
        "Invalid or incomplete configuration. Check variable: ",
    ),
    "bad_env": (
        "Небезопасный формат env-файла. Используйте KEY='value', без shell-команд и подстановок.",
        "Unsafe env format. Use KEY='value', without shell commands or substitutions.",
    ),
    "missing_env": (
        "Файл конфигурации не найден или доступен посторонним. Нужны права 600 и текущий владелец.",
        "Configuration is missing or accessible to others. Mode 600 and current ownership are required.",
    ),
    "mode": ("Режим Keycloak: 1 — встроенный, 2 — внешний", "Keycloak mode: 1 — managed, 2 — external"),
    "core_url": (
        "Публичный HTTPS URL Core (например https://core.example.org)",
        "Public HTTPS Core URL (e.g. https://core.example.org)",
    ),
    "kc_url": (
        "Публичный HTTPS URL Keycloak (отдельный домен)",
        "Public HTTPS Keycloak URL (separate hostname)",
    ),
    "issuer": ("Issuer существующего realm (точный HTTPS URL)", "Existing realm issuer (exact HTTPS URL)"),
    "browser_redirect": (
        "Точный HTTPS callback будущего браузерного клиента",
        "Exact HTTPS callback of the future browser client",
    ),
    "core_cert": ("Путь к PEM-сертификату Core с цепочкой", "Path to Core PEM certificate with chain"),
    "core_key": ("Путь к приватному PEM-ключу Core (без пароля)", "Path to unencrypted Core PEM private key"),
    "kc_cert": ("Путь к PEM-сертификату Keycloak с цепочкой", "Path to Keycloak PEM certificate with chain"),
    "kc_key": (
        "Путь к приватному PEM-ключу Keycloak (без пароля)",
        "Path to unencrypted Keycloak PEM private key",
    ),
    "database": (
        "PostgreSQL: отдельные базы и роли; пароли будут безопасно сгенерированы.",
        "PostgreSQL: separate databases and roles; passwords will be securely generated.",
    ),
    "replace": (
        "Заменить существующий .env? Будет создана резервная копия",
        "Replace existing .env? A backup will be created",
    ),
    "confirm": (
        "Конфигурация проверена. Установить / обновить контейнеры?",
        "Configuration validated. Install / update containers?",
    ),
    "yes": ("да", "yes"),
    "no": ("нет", "no"),
    "cancel": ("Установка отменена. Данные не удалены.", "Installation cancelled. No data was deleted."),
    "needs_replace": (
        ".env отличается. Для замены укажите --replace-config; резервная копия сохранится.",
        ".env differs. Use --replace-config to replace it; a backup will be saved.",
    ),
    "locked": ("Другой установщик уже работает.", "Another installer is running."),
    "ports": (
        "Порты 80/443 заняты не текущим Nginx проекта.",
        "Ports 80/443 are occupied by something other than this project's Nginx.",
    ),
    "tls": (
        "Сертификат или ключ не прошёл проверку имени, срока действия, соответствия или прав доступа.",
        "Certificate or key failed hostname, expiry, key match or permissions validation.",
    ),
    "prepare": (
        "Подготовка конфигурации, TLS и первоначального realm",
        "Preparing configuration, TLS and initial realm",
    ),
    "start": (
        "Проверка Compose и Nginx, запуск контейнеров (это может занять несколько минут)",
        "Validating Compose and Nginx, starting containers (this may take several minutes)",
    ),
    "command": (
        "Операция Docker завершилась ошибкой. Проверьте состояние контейнеров; не публикуйте их конфигурацию и секреты.",
        "Docker operation failed. Inspect container status; do not publish configuration or secrets.",
    ),
    "health": ("Проверка HTTPS, Core readiness и OIDC", "Checking HTTPS, Core readiness and OIDC"),
    "unhealthy": (
        "Проверка работоспособности не пройдена. Конфигурация и данные сохранены; проверьте DNS, TLS и состояние контейнеров.",
        "Health verification failed. Configuration and data were preserved; check DNS, TLS and container status.",
    ),
    "complete": ("Установка завершена. Core: ", "Installation complete. Core: "),
    "admin": (
        "Keycloak: создайте постоянного администратора с MFA и удалите временного bootstrap-admin. Секрет хранится только в .env (600).",
        "Keycloak: create a permanent administrator with MFA and remove temporary bootstrap-admin. Its secret is stored only in .env (600).",
    ),
    "external": (
        "Внешний realm не изменялся. Настройте audience xarionix-core и PKCE-клиент по документации.",
        "External realm was not modified. Configure the xarionix-core audience and PKCE client as documented.",
    ),
    "failure": (
        "Установка остановлена безопасно. Проверьте конфигурацию и права; секреты не выводятся.",
        "Installation stopped safely. Check configuration and permissions; secrets are not displayed.",
    ),
    "dev": (
        "Dev-конфигурация создана. Запуск описан в README. Это НЕ production.",
        "Dev configuration created. See README for launch commands. This is NOT production.",
    ),
    "validated": ("Конфигурация проверена.", "Configuration validated."),
    "template": (
        "Закрытый шаблон с новыми секретами создан. Заполните домены и пути TLS перед установкой.",
        "A private template with new secrets was created. Fill in domains and TLS paths before installation.",
    ),
    "existing_realm": (
        "При существующем realm импорт пропускается: изменения redirect URI, origins и политик применяйте через Keycloak Console, не перезаписывая realm.",
        "An existing realm is not reimported: apply redirect URI, origins and policy changes through Keycloak Console without overwriting the realm.",
    ),
    "reuse": (
        "Использовать текущий .env без изменения секретов?",
        "Reuse current .env without changing secrets?",
    ),
}


class SetupError(Exception):
    def __init__(self, key: str, field: str = ""):
        self.key, self.field = key, field


def message(key: str, language: str, field: str = "") -> str:
    return MESSAGES[key][0 if language == "ru" else 1] + field


def read_env(path: Path) -> dict[str, str]:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_mode & 0o077
        or path.stat().st_uid != os.getuid()
    ):
        raise SetupError("missing_env")
    result: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"(XARIONIX_[A-Z0-9_]+)=(.*)", line)
        if not match or match[1].removeprefix("XARIONIX_") in result:
            raise SetupError("bad_env")
        value = match[2]
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        elif any(char in value for char in "'\"`$\\"):
            # JSON arrays must be single-quoted in dotenv to avoid interpolation ambiguity.
            raise SetupError("bad_env")
        if "'" in value or any(ord(char) < 32 for char in value):
            raise SetupError("bad_env")
        result[match[1].removeprefix("XARIONIX_")] = value
    return result


def atomic_write(path: Path, content: str | bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".setup-", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(content.encode() if isinstance(content, str) else content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def env_text(config: dict[str, str]) -> str:
    if any("'" in value or any(ord(char) < 32 for char in value) for value in config.values()):
        raise SetupError("bad_env")
    return "".join(f"XARIONIX_{key}='{value}'\n" for key, value in sorted(config.items()))


def url(value: str, field: str, *, root: bool = False, development: bool = False) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise SetupError("invalid", field) from None
    if (
        parsed.scheme != "https"
        and not (development and parsed.scheme == "http" and parsed.hostname == "localhost")
    ) or not parsed.hostname:
        raise SetupError("invalid", field)
    if (
        not re.fullmatch(r"[a-zA-Z0-9.-]+", parsed.hostname)
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or value.endswith("/")
    ):
        raise SetupError("invalid", field)
    if root and (parsed.path or port not in (None, 443)):
        raise SetupError("invalid", field)
    if any(part in (".", "..") for part in parsed.path.split("/")) or "%" in value:
        raise SetupError("invalid", field)
    return value


def validate(config: dict[str, str], *, development: bool = False) -> None:
    env_text(config)
    for key in ("DB_USER", "MIGRATION_DB_USER"):
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", config.get(key, "core_app")):
            raise SetupError("invalid", "XARIONIX_" + key)
    if (
        config.get("MIGRATION_DB_USER", "core_app") != "core_app"
        and len(config.get("MIGRATION_DB_PASSWORD", "")) < 24
    ):
        raise SetupError("invalid", "XARIONIX_MIGRATION_DB_PASSWORD")
    try:
        if not 1024 <= int(config.get("PACKAGES_MAX_BYTES", "134217728")) <= 134217728:
            raise ValueError()
        if not 5 <= int(config.get("PACKAGES_UPLOAD_SECONDS", "120")) <= 300:
            raise ValueError()
        for field, cap in {
            "FILES": 1024,
            "FILE_BYTES": 33554432,
            "TOTAL_BYTES": 268435456,
            "PATH_DEPTH": 12,
            "PATH_BYTES": 240,
            "RATIO": 100,
            "MANIFEST_BYTES": 262144,
            "SIGNATURE_BYTES": 4096,
        }.items():
            value = int(config.get("PACKAGES_MAX_" + field, str(cap)))
            if not (3 if field == "FILES" else 1) <= value <= cap:
                raise ValueError()
    except ValueError:
        raise SetupError("invalid", "XARIONIX_PACKAGES_MAX_BYTES/PACKAGES_UPLOAD_SECONDS") from None
    expected = "development" if development else "production"
    if config.get("ENVIRONMENT") != expected:
        raise SetupError("invalid", "XARIONIX_ENVIRONMENT")
    if config.get("INSTALL_LANGUAGE") not in {"ru", "en"}:
        raise SetupError("invalid", "XARIONIX_INSTALL_LANGUAGE")
    mode = config.get("KEYCLOAK_MODE")
    if mode not in {"managed", "external"}:
        raise SetupError("invalid", "XARIONIX_KEYCLOAK_MODE")
    for key in ("PUBLIC_URL", "OIDC_ISSUER"):
        url(
            config.get(key, ""),
            f"XARIONIX_{key}",
            root=key == "PUBLIC_URL" and not development,
            development=development,
        )
    if config.get("OIDC_AUDIENCE") != "xarionix-core":
        raise SetupError("invalid", "XARIONIX_OIDC_AUDIENCE")
    if not re.fullmatch(
        r"[A-Za-z0-9._:-]{1,120}", config.get("MODULES_AUDIENCE", "xarionix-core-modules")
    ) or config.get("MODULES_AUDIENCE") == config.get("OIDC_AUDIENCE"):
        raise SetupError("invalid", "XARIONIX_MODULES_AUDIENCE")
    try:
        interval = int(config.get("MODULES_CHECK_IN_SECONDS", "15"))
        stale = int(config.get("MODULES_STALE_SECONDS", "90"))
        lease = int(config.get("MODULES_LEASE_SECONDS", "30"))
        if not (1 <= interval <= 120 and max(10, 2 * interval) <= stale <= 900 and 5 <= lease <= 120):
            raise ValueError()
    except ValueError:
        raise SetupError(
            "invalid", "XARIONIX_MODULES_CHECK_IN_SECONDS/MODULES_STALE_SECONDS/MODULES_LEASE_SECONDS"
        ) from None
    if config.get("DOCS_ENABLED") not in {"true", "false"}:
        raise SetupError("invalid", "XARIONIX_DOCS_ENABLED")
    try:
        origins = json.loads(config.get("CORS_ORIGINS", "[]"))
        if not isinstance(origins, list):
            raise ValueError()
        for origin in origins:
            if (
                not isinstance(origin, str)
                or urlsplit(url(origin, "XARIONIX_CORS_ORIGINS", development=development)).path
            ):
                raise ValueError()
    except (ValueError, TypeError):
        raise SetupError("invalid", "XARIONIX_CORS_ORIGINS") from None
    try:
        acr = json.loads(config.get("ADMIN_ACR_VALUES", "[]"))
        if (
            not isinstance(acr, list)
            or len(acr) > 16
            or any(not isinstance(item, str) or not 1 <= len(item) <= 120 for item in acr)
        ):
            raise ValueError()
        if not 30 <= int(config.get("ADMIN_AUTH_MAX_AGE_SECONDS", "300")) <= 900:
            raise ValueError()
    except (ValueError, TypeError):
        raise SetupError("invalid", "XARIONIX_ADMIN_ACR_VALUES") from None
    for key in SECRETS if mode == "managed" else SECRETS[:2]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", config.get(key, "")):
            raise SetupError("invalid", f"XARIONIX_{key}")
    if mode == "external" and config.get("OIDC_BACKCHANNEL"):
        raise SetupError("invalid", "XARIONIX_OIDC_BACKCHANNEL")
    if mode == "managed":
        kc_url = url(
            config.get("KEYCLOAK_PUBLIC_URL", ""),
            "XARIONIX_KEYCLOAK_PUBLIC_URL",
            root=not development,
            development=development,
        )
        if (
            kc_url == config["PUBLIC_URL"]
            or (not development and urlsplit(kc_url).hostname == urlsplit(config["PUBLIC_URL"]).hostname)
            or config["OIDC_ISSUER"] != kc_url + "/realms/xarionix"
        ):
            raise SetupError("invalid", "XARIONIX_OIDC_ISSUER")
        if config.get("OIDC_BACKCHANNEL") != "http://keycloak:8080/realms/xarionix":
            raise SetupError("invalid", "XARIONIX_OIDC_BACKCHANNEL")
        callback = url(
            config.get("BROWSER_REDIRECT_URI", ""), "XARIONIX_BROWSER_REDIRECT_URI", development=development
        )
        if (
            "*" in callback
            or config.get("BROWSER_ORIGIN") != f"{urlsplit(callback).scheme}://{urlsplit(callback).netloc}"
        ):
            raise SetupError("invalid", "XARIONIX_BROWSER_ORIGIN")
    for key in ("POSTGRES_IMAGE", "NGINX_IMAGE", *(("KEYCLOAK_IMAGE",) if mode == "managed" else ())):
        image = config.get(key, "")
        if (
            not re.fullmatch(r"[a-zA-Z0-9_./:@-]+", image)
            or (":" not in image.rsplit("/", 1)[-1])
            or image.endswith(":latest")
        ):
            raise SetupError("invalid", f"XARIONIX_{key}")
    if not re.fullmatch(r"[1-9][0-9]{0,9}", config.get("NGINX_UID", "")):
        raise SetupError("invalid", "XARIONIX_NGINX_UID")
    if os.getuid() != 0 and int(config["NGINX_UID"]) != os.getuid():
        raise SetupError("invalid", "XARIONIX_NGINX_UID")


def realm(config: dict[str, str], *, development: bool = False) -> dict[str, object]:
    return {
        "realm": "xarionix",
        "enabled": True,
        "sslRequired": "none" if development else "external",
        "registrationAllowed": False,
        "resetPasswordAllowed": True,
        "rememberMe": False,
        "loginWithEmailAllowed": False,
        "duplicateEmailsAllowed": False,
        "bruteForceProtected": True,
        "permanentLockout": False,
        "failureFactor": 5,
        "waitIncrementSeconds": 60,
        "maxFailureWaitSeconds": 900,
        "accessTokenLifespan": 300,
        "ssoSessionIdleTimeout": 1800,
        "clients": [
            {
                "clientId": "xarionix-core",
                "enabled": True,
                "protocol": "openid-connect",
                "bearerOnly": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": False,
            },
            {
                "clientId": "xarionix-browser",
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": True,
                "standardFlowEnabled": True,
                "implicitFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": False,
                "redirectUris": [config["BROWSER_REDIRECT_URI"]],
                "webOrigins": [config["BROWSER_ORIGIN"]],
                "defaultClientScopes": ["profile", "email"],
                "attributes": {
                    "pkce.code.challenge.method": "S256",
                    "oauth2.device.authorization.grant.enabled": "false",
                },
                "protocolMappers": [
                    {
                        "name": "core-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "consentRequired": False,
                        "config": {
                            "included.client.audience": "xarionix-core",
                            "access.token.claim": "true",
                            "id.token.claim": "false",
                        },
                    }
                ],
            },
        ],
    }


def nginx(config: dict[str, str]) -> str:
    hosts = [(urlsplit(config["PUBLIC_URL"]).hostname, "core", "core:8000")]
    if config["KEYCLOAK_MODE"] == "managed":
        hosts.append((urlsplit(config["KEYCLOAK_PUBLIC_URL"]).hostname, "keycloak", "keycloak:8080"))
    servers = []
    for host, name, upstream in hosts:
        # Only the Core vhost accepts large streamed archives. Keycloak retains the 2 MiB default.
        package_location = (
            ""
            if name != "core"
            else f"""
        location = /api/v1/platform/packages {{
            client_max_body_size 128m;
            client_body_timeout 120s;
            set $upstream http://{upstream};
            proxy_pass $upstream;
            proxy_http_version 1.1;
            proxy_request_buffering off;
            proxy_set_header Host {host};
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header Connection "";
            proxy_connect_timeout 5s;
            proxy_read_timeout 180s;
            proxy_send_timeout 120s;
        }}"""
        )
        servers.append(f"""
    server {{
        listen 8080;
        server_name {host};
        return 308 https://{host}$request_uri;
    }}
    server {{
        listen 8443 ssl;
        server_name {host};
        ssl_certificate /etc/xarionix/tls/{name}.crt;
        ssl_certificate_key /etc/xarionix/tls/{name}.key;
        add_header Strict-Transport-Security "max-age=31536000" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy no-referrer always;
        {package_location}
        location / {{
            set $upstream http://{upstream};
            proxy_pass $upstream;
            proxy_http_version 1.1;
            proxy_set_header Host {host};
            proxy_set_header X-Forwarded-Host {host};
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Port 443;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header Connection "";
            proxy_connect_timeout 5s;
            proxy_read_timeout 60s;
            proxy_send_timeout 60s;
        }}
    }}""")
    return (
        """pid /tmp/nginx.pid;
error_log /dev/stderr crit;
events { worker_connections 1024; }
http {
    access_log off;
    server_tokens off;
    client_max_body_size 2m;
    client_body_timeout 15s;
    client_header_timeout 15s;
    send_timeout 30s;
    keepalive_timeout 30s;
    client_body_temp_path /tmp/client_temp;
    proxy_temp_path /tmp/proxy_temp;
    fastcgi_temp_path /tmp/fastcgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    scgi_temp_path /tmp/scgi_temp;
    resolver 127.0.0.11 valid=10s ipv6=off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:TLS:10m;
    ssl_session_tickets off;
    server { listen 8080 default_server; return 444; }
    server { listen 8443 ssl default_server; ssl_reject_handshake on; }
"""
        + "".join(servers)
        + "\n}\n"
    )


def run(command: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    if not command or command[0] not in {"docker", "openssl", "ss"}:
        raise SetupError("command")
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith(("XARIONIX_", "COMPOSE_"))
    }
    try:
        # Executables are allowlisted; every parameter is a separate argv item, never shell text.
        return subprocess.run(  # nosec B603
            command, cwd=ROOT, env=environment, capture_output=True, timeout=timeout, check=True
        )
    except (OSError, subprocess.SubprocessError):
        raise SetupError("command") from None


def check_certificate(cert: Path, key: Path, hostname: str) -> None:
    try:
        if key.is_symlink() or key.stat().st_mode & 0o077 or key.stat().st_uid != os.getuid():
            raise SetupError("tls")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # A callback prevents OpenSSL from prompting for an encrypted key password.
        context.load_cert_chain(cert, key, password=lambda: "")
        match = run(["openssl", "x509", "-in", str(cert), "-noout", "-checkhost", hostname])
        if b"does match certificate" not in match.stdout:
            raise SetupError("tls")
        run(["openssl", "x509", "-in", str(cert), "-noout", "-checkend", "86400"])
    except (OSError, ValueError, ssl.SSLError, SetupError):
        raise SetupError("tls") from None


def prepare(config: dict[str, str]) -> None:
    certificates = [("CORE", "core", config["PUBLIC_URL"])]
    if config["KEYCLOAK_MODE"] == "managed":
        certificates.append(("KEYCLOAK", "keycloak", config["KEYCLOAK_PUBLIC_URL"]))
    for prefix, _, public in certificates:
        check_certificate(
            Path(config.get(f"{prefix}_TLS_CERT", "")),
            Path(config.get(f"{prefix}_TLS_KEY", "")),
            urlsplit(public).hostname or "",
        )
    GENERATED.mkdir(parents=True, exist_ok=True, mode=0o755)
    (GENERATED / "tls").mkdir(exist_ok=True, mode=0o755)
    # install.sh uses umask 077; mounted directories must still be traversable by Nginx's UID.
    GENERATED.chmod(0o755)
    (GENERATED / "tls").chmod(0o755)
    for prefix, name, _ in certificates:
        for suffix, key in (("crt", "CERT"), ("key", "KEY")):
            destination = GENERATED / f"tls/{name}.{suffix}"
            atomic_write(
                destination,
                Path(config[f"{prefix}_TLS_{key}"]).read_bytes(),
                0o644 if suffix == "crt" else 0o600,
            )
            if os.getuid() == 0:
                os.chown(destination, int(config["NGINX_UID"]), int(config["NGINX_UID"]))
    atomic_write(GENERATED / "nginx.conf", nginx(config), 0o644)
    if config["KEYCLOAK_MODE"] == "managed":
        atomic_write(GENERATED / "xarionix-realm.json", json.dumps(realm(config), indent=2) + "\n", 0o644)


def compose(config: dict[str, str], env_file: Path) -> list[str]:
    command = [
        "docker",
        "compose",
        "--project-name",
        "xarionix-core",
        "--env-file",
        str(env_file),
        "-f",
        "compose.yaml",
    ]
    if config["KEYCLOAK_MODE"] == "managed":
        command += ["-f", "compose.keycloak.yaml"]
    return command


def check_system() -> None:
    if (
        not sys.platform.startswith("linux")
        or sys.version_info < (3, 12)
        or not all(shutil.which(tool) for tool in ("docker", "openssl", "ss"))
    ):
        raise SetupError("requirements")
    try:
        run(["docker", "compose", "version"])
        run(["docker", "info"], timeout=20)
    except SetupError:
        raise SetupError("requirements") from None


def check_ports(command: list[str]) -> None:
    # Existing project Nginx may own the ports on an idempotent rerun.
    running = run(command + ["ps", "--status", "running", "--services"]).stdout.decode().splitlines()
    if "nginx" in running:
        return
    for line in run(["ss", "-H", "-ltn"]).stdout.decode().splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].rsplit(":", 1)[-1] in {"80", "443"}:
            raise SetupError("ports")


def verify_health(config: dict[str, str], *, attempts: int = 60) -> None:
    # HTTPS URLs are validated again at this public function boundary. No redirects/downgrade.
    url(config["PUBLIC_URL"], "XARIONIX_PUBLIC_URL", root=True)
    url(config["OIDC_ISSUER"], "XARIONIX_OIDC_ISSUER")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str
        ) -> None:
            return None

    opener = urllib.request.build_opener(NoRedirect())
    for attempt in range(attempts):
        try:
            with opener.open(config["PUBLIC_URL"] + "/health/ready", timeout=10) as response:
                if json.load(response) != {"status": "ready"}:
                    raise ValueError()
            with opener.open(
                config["OIDC_ISSUER"] + "/.well-known/openid-configuration", timeout=10
            ) as response:
                discovery = json.load(response)
            if discovery.get("issuer") != config["OIDC_ISSUER"]:
                raise ValueError()
            return
        except (OSError, ValueError, urllib.error.URLError):
            if attempt + 1 < attempts:
                time.sleep(2)
    raise SetupError("unhealthy")


def ask(key: str, language: str, default: str = "") -> str:
    return input(message(key, language) + (f" [{default}]" if default else "") + ": ").strip() or default


def confirm(key: str, language: str) -> bool:
    return ask(key, language, message("no", language)).lower() == message("yes", language)


def interactive_config(language: str) -> dict[str, str]:
    config = DEFAULTS | {"INSTALL_LANGUAGE": language}
    config["KEYCLOAK_MODE"] = {"1": "managed", "2": "external"}.get(ask("mode", language, "1"), "")
    config["PUBLIC_URL"] = ask("core_url", language)
    if config["KEYCLOAK_MODE"] == "managed":
        config["KEYCLOAK_PUBLIC_URL"] = ask("kc_url", language)
        config["OIDC_ISSUER"] = config["KEYCLOAK_PUBLIC_URL"] + "/realms/xarionix"
        config["OIDC_BACKCHANNEL"] = "http://keycloak:8080/realms/xarionix"
        config["BROWSER_REDIRECT_URI"] = ask("browser_redirect", language)
        callback = urlsplit(config["BROWSER_REDIRECT_URI"])
        config["BROWSER_ORIGIN"] = f"{callback.scheme}://{callback.netloc}"
    else:
        config["OIDC_ISSUER"] = ask("issuer", language)
        config["OIDC_BACKCHANNEL"] = ""
    for prefix in ("core", "kc") if config["KEYCLOAK_MODE"] == "managed" else ("core",):
        env_prefix = "CORE" if prefix == "core" else "KEYCLOAK"
        for item in ("cert", "key"):
            config[f"{env_prefix}_TLS_{item.upper()}"] = str(
                Path(ask(f"{prefix}_{item}", language)).expanduser().resolve()
            )
    print(message("database", language))
    for key in SECRETS if config["KEYCLOAK_MODE"] == "managed" else SECRETS[:2]:
        config[key] = secrets.token_hex(32)
    return config


def install(args: argparse.Namespace, language: str) -> None:
    print(message("system", language))
    check_system()
    target = ROOT / ".env"
    if args.env_file:
        config = read_env(Path(args.env_file).resolve())
    elif args.non_interactive:
        raise SetupError("invalid", "--env-file")
    elif target.exists() and confirm("reuse", language):
        config = read_env(target)
    else:
        config = interactive_config(language)
    config["INSTALL_LANGUAGE"] = language
    validate(config)
    changed = not target.exists() or read_env(target) != config
    if target.exists() and changed and not args.replace_config:
        if args.non_interactive:
            raise SetupError("needs_replace")
        if not confirm("replace", language):
            raise SetupError("cancel")
    # Validate TLS before modifying the existing dotenv or generated configuration.
    for prefix, public in (
        ("CORE", config["PUBLIC_URL"]),
        *([("KEYCLOAK", config["KEYCLOAK_PUBLIC_URL"])] if config["KEYCLOAK_MODE"] == "managed" else []),
    ):
        check_certificate(
            Path(config.get(f"{prefix}_TLS_CERT", "")),
            Path(config.get(f"{prefix}_TLS_KEY", "")),
            urlsplit(public).hostname or "",
        )
    if not args.non_interactive and not confirm("confirm", language):
        raise SetupError("cancel")
    if changed:
        if target.exists():
            backup = ROOT / "backups" / ("env-" + time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3))
            atomic_write(backup, target.read_bytes())
        atomic_write(target, env_text(config))
    print(message("prepare", language))
    prepare(config)
    command = compose(config, target)
    run(command + ["config", "--quiet"])
    check_ports(command)
    print(message("start", language))
    infrastructure = ["postgres", "nginx"]
    if config["KEYCLOAK_MODE"] == "managed":
        infrastructure += ["keycloak-postgres", "keycloak"]
    # Core and migrate share the locally built image; never pull it from a public registry.
    run(command + ["pull", *infrastructure], timeout=1800)
    run(command + ["build"], timeout=1800)
    # Dynamic upstream resolution allows syntax validation before Core/Keycloak start.
    run(command + ["run", "--rm", "--no-deps", "nginx", "-t"], timeout=60)
    run(command + ["up", "-d", "--remove-orphans"], timeout=600)
    run(command + ["exec", "-T", "nginx", "nginx", "-t"])
    run(command + ["exec", "-T", "nginx", "nginx", "-s", "reload"])
    print(message("health", language))
    verify_health(config)
    print(message("complete", language) + config["PUBLIC_URL"])
    print(message("admin" if config["KEYCLOAK_MODE"] == "managed" else "external", language))
    if config["KEYCLOAK_MODE"] == "managed":
        print(message("existing_realm", language))


def dev_config(language: str) -> None:
    path = ROOT / ".env.dev"
    if path.exists():
        config = read_env(path)
    else:
        config = DEFAULTS | {
            "ENVIRONMENT": "development",
            "INSTALL_LANGUAGE": language,
            "PUBLIC_URL": "http://localhost:8000",
            "KEYCLOAK_PUBLIC_URL": "http://localhost:8090",
            "OIDC_ISSUER": "http://localhost:8090/realms/xarionix",
            "OIDC_BACKCHANNEL": "http://keycloak:8080/realms/xarionix",
            "BROWSER_REDIRECT_URI": "http://localhost:4200/auth/callback",
            "BROWSER_ORIGIN": "http://localhost:4200",
            "DOCS_ENABLED": "true",
        }
        for key in SECRETS:
            config[key] = secrets.token_hex(32)
    validate(config, development=True)
    if not path.exists():
        atomic_write(path, env_text(config))
    atomic_write(GENERATED / "dev-realm.json", json.dumps(realm(config, development=True), indent=2), 0o644)
    print(message("dev", language))


def main() -> int:
    class Parser(argparse.ArgumentParser):
        def error(self, message: str) -> Never:
            raise SetupError("invalid", "CLI")

    parser = Parser(description="Xarionix Core setup", add_help=False)
    parser.add_argument("command", choices=("install", "validate", "prepare", "dev", "reload", "init-config"))
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--env-file")
    parser.add_argument("--replace-config", action="store_true")
    parser.add_argument("--language", choices=("ru", "en"))
    language = "ru"
    # Preserve a selected language even if parsing a later invalid CLI argument fails.
    for index, value in enumerate(sys.argv[:-1]):
        if value == "--language" and sys.argv[index + 1] in {"ru", "en"}:
            language = sys.argv[index + 1]
    try:
        args = parser.parse_args()
        if args.language:
            language = args.language
        elif args.env_file and args.command != "init-config":
            language = read_env(Path(args.env_file)).get("INSTALL_LANGUAGE", "ru")
            if language not in {"ru", "en"}:
                raise SetupError("invalid", "XARIONIX_INSTALL_LANGUAGE")
        ROOT.mkdir(exist_ok=True)
        with (ROOT / ".install.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SetupError("locked") from None
            if args.command == "install":
                install(args, language)
            elif args.command == "init-config":
                path = Path(args.env_file).resolve() if args.env_file else ROOT / "deployment.env"
                if path.exists():
                    raise SetupError("needs_replace")
                config = (
                    DEFAULTS
                    | {
                        "INSTALL_LANGUAGE": language,
                        "PUBLIC_URL": "https://core.example.com",
                        "KEYCLOAK_PUBLIC_URL": "https://auth.example.com",
                        "OIDC_ISSUER": "https://auth.example.com/realms/xarionix",
                        "OIDC_BACKCHANNEL": "http://keycloak:8080/realms/xarionix",
                        "BROWSER_REDIRECT_URI": "https://console.example.com/auth/callback",
                        "BROWSER_ORIGIN": "https://console.example.com",
                        "CORE_TLS_CERT": "/absolute/path/core-fullchain.pem",
                        "CORE_TLS_KEY": "/absolute/path/core-key.pem",
                        "KEYCLOAK_TLS_CERT": "/absolute/path/auth-fullchain.pem",
                        "KEYCLOAK_TLS_KEY": "/absolute/path/auth-key.pem",
                    }
                    | {key: secrets.token_hex(32) for key in SECRETS}
                )
                atomic_write(path, env_text(config))
                print(message("template", language))
            elif args.command == "dev":
                dev_config(language)
            else:
                path = Path(args.env_file).resolve() if args.env_file else ROOT / ".env"
                config = read_env(path)
                validate(config)
                if args.command == "prepare":
                    prepare(config)
                elif args.command == "reload":
                    command = compose(config, path)
                    run(command + ["exec", "-T", "nginx", "nginx", "-t"])
                    run(command + ["exec", "-T", "nginx", "nginx", "-s", "reload"])
                print(message("validated", language))
        return 0
    except SetupError as error:
        print(message(error.key, language, error.field), file=sys.stderr)
    except (OSError, ValueError, EOFError, KeyboardInterrupt):
        print(message("failure", language), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
