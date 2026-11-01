"""Validate all deployment modes using disposable config, never the installed dotenv/TLS."""

from __future__ import annotations

import argparse
import json
import os
import secrets

# Only Docker argv is executed; no shell or production input is evaluated.
import subprocess  # nosec B404
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scripts import setup

ROOT = Path(__file__).resolve().parents[1]


def clean_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if not key.startswith(("XARIONIX_", "COMPOSE_"))}


def docker(
    arguments: list[str], *, timeout: int = 60, input_data: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(  # nosec B603 B607
            ["docker", *arguments],
            cwd=ROOT,
            env=clean_environment(),
            input=input_data,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError(
            "Docker CLI/daemon unavailable or operation timed out; see docs/ci-cd.md runner requirements"
        ) from None
    if result.returncode:
        # docker compose diagnostics can expand environment values. Never echo raw output.
        raise RuntimeError(
            "Docker operation failed; inspect the isolated project locally without publishing credentials"
        )
    return result


@dataclass
class Configuration:
    name: str
    project: str
    arguments: list[str]

    def normalized(self) -> dict[str, Any]:
        docker([*self.arguments, "config", "-q"])
        return json.loads(docker([*self.arguments, "config", "--format", "json"]).stdout)  # type: ignore[no-any-return]


def certificates(directory: Path, uid: int) -> None:
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    for name, host in (("core", "core.example.test"), ("keycloak", "auth.example.test")):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(key, hashes.SHA256())
        )
        setup.atomic_write(directory / f"{name}.crt", cert.public_bytes(serialization.Encoding.PEM), 0o644)
        key_path = directory / f"{name}.key"
        setup.atomic_write(
            key_path,
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
        )
        if os.getuid() == 0:
            os.chown(key_path, uid, uid)


@contextmanager
def configurations() -> Iterator[list[Configuration]]:
    scratch = ROOT / ".ci-tmp"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="compose-", dir=scratch) as temporary:
        folder = Path(temporary)
        generated = folder / "generated"
        generated.mkdir(mode=0o755)
        generated.chmod(0o755)
        config = setup.DEFAULTS | {
            "PUBLIC_URL": "https://core.example.test",
            "KEYCLOAK_PUBLIC_URL": "https://auth.example.test",
            "OIDC_ISSUER": "https://auth.example.test/realms/xarionix",
            "OIDC_BACKCHANNEL": "http://keycloak:8080/realms/xarionix",
            "BROWSER_REDIRECT_URI": "https://console.example.test/callback",
            "BROWSER_ORIGIN": "https://console.example.test",
            **{key: secrets.token_hex(32) for key in setup.SECRETS},
        }
        certificates(generated / "tls", int(config["NGINX_UID"]))
        for name in ("xarionix-realm.json", "dev-realm.json"):
            setup.atomic_write(
                generated / name, json.dumps(setup.realm(config, development=name.startswith("dev"))), 0o644
            )
        files = {}
        for filename in ("compose.yaml", "compose.keycloak.yaml", "compose.dev.yaml"):
            definition = yaml.safe_load((ROOT / filename).read_text())
            for service in definition["services"].values():
                if "build" in service:
                    service["build"] = str(ROOT)
                for mount in service.get("volumes", []):
                    if mount["type"] == "bind":
                        source = Path(mount["source"])
                        if source.is_relative_to("deploy/generated"):
                            mount["source"] = str(generated / source.relative_to("deploy/generated"))
                        else:
                            mount["source"] = str(ROOT / source)
            files[filename] = folder / filename
            setup.atomic_write(files[filename], yaml.safe_dump(definition))
        results = []
        prefix = "xarionix-config-" + uuid.uuid4().hex[:12]
        for mode in ("dev", "external", "managed"):
            values = config | {"KEYCLOAK_MODE": "external" if mode == "external" else "managed"}
            if mode == "external":
                values["OIDC_BACKCHANNEL"] = ""
            setup.atomic_write(generated / "nginx.conf", setup.nginx(values), 0o644)
            # Each mode has its own config file so Nginx syntax tests do not share a mutable mount.
            nginx_path = generated / f"nginx-{mode}.conf"
            setup.atomic_write(nginx_path, setup.nginx(values), 0o644)
            env_path = folder / f"{mode}.env"
            setup.atomic_write(env_path, setup.env_text(values))
            selected = ["compose.dev.yaml"] if mode == "dev" else ["compose.yaml"]
            if mode == "managed":
                selected.append("compose.keycloak.yaml")
            # Isolate the base file per mode; never modify real deploy/generated.
            if mode != "dev":
                base = yaml.safe_load(files["compose.yaml"].read_text())
                base["services"]["nginx"]["volumes"][0]["source"] = str(nginx_path)
                base_path = folder / f"compose-{mode}.yaml"
                setup.atomic_write(base_path, yaml.safe_dump(base))
                selected[0] = base_path.name
            arguments = ["compose", "--project-name", prefix + "-" + mode, "--env-file", str(env_path)]
            for filename in selected:
                arguments += ["-f", str(folder / filename)]
            results.append(Configuration(mode, prefix + "-" + mode, arguments))
        yield results


def audit(definition: dict[str, Any], mode: str) -> None:
    services = definition["services"]
    container_tmp = "/tmp"  # nosec B108
    for name, service in services.items():
        if service.get("privileged") or service.get("network_mode") == "host" or service.get("cap_add"):
            raise ValueError(f"Unsafe container privileges: {name}")
        if "container_name" in service:
            raise ValueError(f"Fixed container name: {name}")
        for mount in service.get("volumes", []):
            if not mount["target"].startswith("/") or "docker.sock" in mount.get("source", ""):
                raise ValueError(f"Unsafe mount: {name}")
            if mount["type"] == "bind" and (
                not mount.get("read_only") or mount.get("bind", {}).get("create_host_path", True)
            ):
                raise ValueError(f"Unsafe bind mount: {name}")
        tmpfs = service.get("tmpfs", [])
        for entry in tmpfs:
            target, _, options = entry.partition(":")
            # This is a container mount target, not an insecure host temporary file.
            if target != container_tmp or not {"rw", "nosuid", "nodev"} <= set(options.split(",")):
                raise ValueError(f"Malformed tmpfs: {name}")
        if name in {"core", "migrate"}:
            if (
                not service.get("read_only")
                or service.get("cap_drop") != ["ALL"]
                or not any("noexec" in entry for entry in tmpfs)
            ):
                raise ValueError(f"Core hardening missing: {name}")
        if mode != "dev" and name != "nginx" and service.get("ports"):
            raise ValueError(f"Internal production port published: {name}")
        if name in {"postgres", "keycloak-postgres"}:
            if service.get("ports") or service["volumes"][0]["target"] != "/var/lib/postgresql":
                raise ValueError(f"PostgreSQL18 mount/port error: {name}")
            if mode != "dev" and not all(
                definition["networks"][network].get("internal") for network in service["networks"]
            ):
                raise ValueError(f"Database must use only internal networks: {name}")
        if name != "migrate" and not service.get("healthcheck", {}).get("test"):
            raise ValueError(f"Healthcheck missing: {name}")
    if services["core"]["depends_on"]["migrate"]["condition"] != "service_completed_successfully":
        raise ValueError("Core must wait for migrations")
    if mode == "external":
        if "keycloak" in services or services["core"]["environment"]["XARIONIX_OIDC_BACKCHANNEL"]:
            raise ValueError("External mode must not start managed Keycloak or remap issuer transport")
    elif services["core"]["depends_on"]["keycloak"]["condition"] != "service_healthy":
        raise ValueError("Core must wait for Keycloak")


def check(*, nginx: bool = False) -> None:
    with configurations() as variants:
        for variant in variants:
            audit(variant.normalized(), variant.name)
            if nginx and variant.name != "dev":
                try:
                    docker([*variant.arguments, "run", "--rm", "--no-deps", "nginx", "-t"], timeout=180)
                finally:
                    # Unique throw-away project, no existing project or volumes are removed.
                    docker([*variant.arguments, "down", "--remove-orphans"])
            print(f"Compose {variant.name}: interpolation, mounts, privileges and dependencies OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--nginx",
        action="store_true",
        help="Also execute nginx -t in disposable containers (requires daemon)",
    )
    args = parser.parse_args()
    check(nginx=args.nginx)


if __name__ == "__main__":
    main()
