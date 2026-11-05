"""Local/CI Docker commands. No registry credential is accepted as a command argument."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil

# Fixed argv; registry credentials are passed only over stdin and a private Docker config.
import subprocess  # nosec B404
import tempfile
import tomllib
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from scripts.compose_check import ROOT, docker

TRIVY_IMAGE = "aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
GITLEAKS_IMAGE = "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"


def compose_failure_kind(output: bytes) -> str:
    """Classify captured Docker output without returning URLs, commands or secret values."""
    message = output.decode(errors="replace").lower()
    patterns = (
        (
            "tls_verification",
            (
                "certificate verify failed",
                "certificate signed by unknown authority",
                "certificate has expired",
            ),
        ),
        ("disk_full", ("no space left on device",)),
        ("out_of_memory", ("cannot allocate memory", "out of memory", "exit code: 137")),
        (
            "network_timeout",
            (
                "read timed out",
                "readtimeout",
                "i/o timeout",
                "tls handshake timeout",
                "context deadline exceeded",
            ),
        ),
        (
            "network_unavailable",
            (
                "temporary failure in name resolution",
                "no such host",
                "connection reset by peer",
                "network is unreachable",
            ),
        ),
        (
            "upstream_unavailable",
            ("429 too many requests", "toomanyrequests", "502 bad gateway", "503 service unavailable"),
        ),
        (
            "dependency_resolution",
            (
                "no matching distribution found",
                "resolutionimpossible",
                "could not find a version that satisfies",
            ),
        ),
    )
    return next(
        (kind for kind, markers in patterns if any(marker in message for marker in markers)), "unclassified"
    )


def retry_compose_build(arguments: list[str], kind: str, attempt: int) -> bool:
    """One retry for an idempotent image build's explicit transient transport failure only."""
    return (
        arguments == ["build", "core"]
        and attempt == 1
        and kind in {"network_timeout", "network_unavailable", "upstream_unavailable"}
    )


def preflight() -> None:
    try:
        docker(["version", "--format", "{{.Server.Version}}"], timeout=20)
        docker(["compose", "version"], timeout=20)
    except RuntimeError:
        raise RuntimeError(
            "Docker CLI/daemon or Compose unavailable: use a working local daemon or the rootless Docker-executor setup (docs/ci-cd.md)"
        ) from None
    print("Docker daemon and Compose available (local or isolated rootless CI)")


def metadata() -> dict[str, str]:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    revision = os.environ.get("CI_COMMIT_SHA")
    if not revision:
        executable = shutil.which("git")
        if not executable:
            raise ValueError("Git is required for local OCI revision metadata")
        # Verified executable, fixed arguments, no shell or repository-supplied command.
        output = subprocess.check_output([executable, "rev-parse", "HEAD"], cwd=ROOT, text=True)  # nosec B603
        revision = output.strip()
    source = os.environ.get("CI_PROJECT_URL", "unknown")
    if source != "unknown":
        parsed = urlsplit(source)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            # This is an OCI metadata label, not a network request. HTTP self-hosted GitLab is valid.
            raise ValueError("CI_PROJECT_URL must be a credential-free HTTP(S) URL")
    if not re.fullmatch(r"[0-9a-f]{40,64}", revision):
        raise ValueError("Invalid commit SHA")
    created = os.environ.get("CI_COMMIT_TIMESTAMP")
    if not created:
        executable = shutil.which("git")
        if not executable:
            raise ValueError("Git is required for local OCI timestamp metadata")
        # Commit date is stable across local build/check calls and is valid RFC3339.
        output = subprocess.check_output(  # nosec B603
            [executable, "show", "-s", "--format=%cI", "HEAD"], cwd=ROOT, text=True
        )
        created = output.strip()
    return {
        "version": version,
        "revision": revision,
        "source": source,
        "created": created,
    }


def build(image: str) -> None:
    values = metadata()
    arguments = ["build", "--progress", "plain", "--tag", image]
    for key, value in {
        "VERSION": values["version"],
        "VCS_REF": values["revision"],
        "SOURCE_URL": values["source"],
        "BUILD_DATE": values["created"],
    }.items():
        arguments += ["--build-arg", f"{key}={value}"]
    docker([*arguments, "."], timeout=1800)
    print("Production multi-stage image built with OCI metadata (no registry push)")


def image_check(image: str) -> None:
    configuration = json.loads(docker(["image", "inspect", image]).stdout)[0]["Config"]
    if configuration["User"] != "10001:10001":
        raise ValueError("Image must run as non-root UID 10001")
    labels = configuration.get("Labels", {})
    for key, value in metadata().items():
        if labels.get("org.opencontainers.image." + key) != value:
            raise ValueError(f"OCI label mismatch: {key}")
    # No DB/IdP fallback: start the actual image and test HTTP entirely inside it, no host ports.
    name = "xarionix-image-check-" + uuid.uuid4().hex[:12]
    # Mount option string refers to a container filesystem, not a host temp directory.
    tmpfs_options = "/tmp:rw,noexec,nosuid,nodev,size=64m"  # nosec B108
    try:
        docker(
            [
                "run",
                "--detach",
                "--name",
                name,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                tmpfs_options,
                "--env",
                "XARIONIX_ENVIRONMENT=development",
                "--env",
                "XARIONIX_KEYCLOAK_MODE=external",
                "--env",
                "XARIONIX_PUBLIC_URL=http://localhost:8000",
                "--env",
                "XARIONIX_OIDC_ISSUER=http://localhost:9/realms/xarionix",
                "--env",
                "XARIONIX_DB_HOST=127.0.0.1",
                "--env",
                "XARIONIX_DB_PORT=9",
                "--env",
                "XARIONIX_DB_PASSWORD=image-smoke-dummy-not-a-deployment-secret",
                "--env",
                "XARIONIX_OIDC_TIMEOUT_SECONDS=0.1",
                image,
            ]
        )
        script = """import importlib.util, pathlib, time, urllib.request, urllib.error
assert importlib.util.find_spec('pip') is None, 'pip is not needed in runtime'
assert not any(pathlib.Path('/srv/core').rglob('*.pyc')), 'host bytecode must not enter runtime'
deadline = time.monotonic() + 30
while True:
    try:
        assert urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2).status == 200
        break
    except OSError:
        if time.monotonic() >= deadline: raise RuntimeError('image did not become live') from None
        time.sleep(0.2)
for path, expected in [('/health/ready',503),('/api/v1/me',401)]:
    try:
        response = urllib.request.urlopen('http://127.0.0.1:8000'+path, timeout=12)
        status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
    assert status == expected
"""
        docker(["exec", name, "python", "-c", script], timeout=60)
    finally:
        docker(["rm", "--force", name])
    print("Built image: non-root, OCI labels, read-only startup, live=200, unready=503, missing token=401 OK")


def trivy(image: str, report: str = "trivy-image.json") -> None:
    if report not in {
        "trivy-image.json",
        "trivy-agent.json",
        "trivy-runtime.json",
        "trivy-gateway-agent.json",
        "trivy-business-runtime.json",
    }:
        raise ValueError("Unsupported image security report")
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    report_path = reports / report
    # A scanner/network failure must not leave a previous successful result as this run's report.
    report_path.unlink(missing_ok=True)
    # Cache is inside the disposable scanner container, not on the host.
    cache = "/tmp/trivy-cache"  # nosec B108
    with tempfile.TemporaryDirectory(prefix="image-scan-", dir=ROOT / ".ci-tmp") as temporary:
        archive = Path(temporary) / "image.tar"
        docker(["save", "--output", str(archive), image], timeout=180)
        # Scanner sees only the exported candidate, not Docker socket, workspace or production env.
        try:
            docker(
                [
                    "run",
                    "--rm",
                    "--user",
                    f"{os.getuid()}:{os.getgid()}",
                    "--env",
                    "HOME=/tmp",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--mount",
                    f"type=bind,source={temporary},target=/scan,readonly",
                    "--mount",
                    f"type=bind,source={reports},target=/reports",
                    TRIVY_IMAGE,
                    "image",
                    # Trivy's default 5m also covers downloading its 131+ MiB DB.
                    # Keep this below the enclosing Docker operation/job deadline.
                    "--timeout",
                    "12m",
                    "--no-progress",
                    "--cache-dir",
                    cache,
                    "--input",
                    "/scan/image.tar",
                    "--scanners",
                    "vuln",
                    "--severity",
                    "HIGH,CRITICAL",
                    "--exit-code",
                    "1",
                    "--format",
                    "json",
                    "--output",
                    "/reports/" + report,
                ],
                timeout=900,
            )
        except RuntimeError:
            raise RuntimeError(
                "Trivy failed: HIGH/CRITICAL findings or scanner/database unavailable; "
                "inspect reports/trivy-image.json if created. The security gate remains blocking."
            ) from None
    print("Trivy HIGH/CRITICAL image vulnerability scan passed")


def secrets_check() -> None:
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)

    # Full Git history plus current tracked/untracked source are scanned separately. Never scan ignored .env.
    def scan(source: Path, mode: str, report: str) -> None:
        docker(
            [
                "run",
                "--rm",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--env",
                "HOME=/tmp",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--network",
                "none",
                "--mount",
                f"type=bind,source={source},target=/repo,readonly",
                "--mount",
                f"type=bind,source={reports},target=/reports",
                GITLEAKS_IMAGE,
                mode,
                "/repo",
                *(["--log-opts=--all"] if mode == "git" else []),
                "--config=/repo/.gitleaks.toml",
                "--redact=100",
                "--report-format=json",
                f"--report-path=/reports/{report}",
                "--no-banner",
            ],
            timeout=180,
        )

    scan(ROOT, "git", "gitleaks.json")
    listing = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
    )  # nosec B603 B607
    with tempfile.TemporaryDirectory(prefix="source-scan-", dir=ROOT / ".ci-tmp") as temporary:
        for filename in listing.decode().strip("\0").split("\0"):
            source = ROOT / filename
            if source.is_symlink() or not source.resolve().is_relative_to(ROOT):
                raise ValueError("Refusing to scan symlinks/paths outside this repository")
            destination = Path(temporary) / filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        scan(Path(temporary), "dir", "gitleaks-working-tree.json")
    print("Full Git history and non-ignored working tree secret scans passed (redacted reports)")


def export_image(image: str) -> None:
    destination = ROOT / "dist"
    destination.mkdir(exist_ok=True)
    archive = destination / "core-image.tar"
    docker(["save", "--output", str(archive), image], timeout=180)
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    descriptor = metadata() | {"sha256": digest, "image": image}
    (destination / "image.json").write_text(json.dumps(descriptor))


def publish() -> None:
    tag = os.environ.get("CI_COMMIT_TAG", "")
    values = metadata()
    if (
        os.environ.get("CI_COMMIT_REF_PROTECTED") != "true"
        or not re.fullmatch(r"v?\d+\.\d+\.\d+", tag)
        or tag.removeprefix("v") != values["version"]
    ):
        raise ValueError("Publishing requires a protected release tag matching pyproject version")
    names = ("CI_REGISTRY", "CI_REGISTRY_IMAGE", "CI_REGISTRY_USER", "CI_REGISTRY_PASSWORD")
    if not all(os.environ.get(name) for name in names):
        raise ValueError("GitLab Container Registry is unavailable or CI registry credentials are missing")
    archive = ROOT / "dist/core-image.tar"
    descriptor = json.loads((ROOT / "dist/image.json").read_text())
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != descriptor["sha256"]:
            raise ValueError("Image artifact checksum mismatch")
    if any(descriptor[key] != values[key] for key in values):
        raise ValueError("Image artifact does not belong to this release")
    docker(["load", "--input", str(archive)], timeout=180)
    image = descriptor["image"]
    image_check(image)
    # Docker auth is confined to an automatically removed private directory, never an artifact/cache.
    with tempfile.TemporaryDirectory(prefix="registry-auth-") as auth:
        docker(
            [
                "--config",
                auth,
                "login",
                os.environ["CI_REGISTRY"],
                "--username",
                os.environ["CI_REGISTRY_USER"],
                "--password-stdin",
            ],
            input_data=os.environ["CI_REGISTRY_PASSWORD"].encode(),
        )
        for suffix in (values["version"], "sha-" + values["revision"]):
            target = os.environ["CI_REGISTRY_IMAGE"] + ":" + suffix
            docker(["tag", image, target])
            docker(["--config", auth, "push", target], timeout=600)
    print("Protected release published to GitLab Container Registry; no deployment performed")


def dev_check() -> None:
    with httpx.Client(timeout=15, trust_env=False) as client:
        for path, status in (("/health/live", 200), ("/health/ready", 200), ("/api/v1/me", 401)):
            if client.get("http://localhost:8000" + path).status_code != status:
                raise RuntimeError(f"Dev endpoint check failed: {path}")
        discovery = client.get(
            "http://localhost:8090/realms/xarionix/.well-known/openid-configuration"
        ).json()
        if discovery["issuer"] != "http://localhost:8090/realms/xarionix":
            raise RuntimeError("Dev issuer mismatch")
        if not client.get(discovery["jwks_uri"]).json()["keys"]:
            raise RuntimeError("Dev JWKS has no keys")
    print("Dev health, authentication denial, discovery and JWKS: OK")


def cleanup_tests() -> None:
    job = os.environ.get("CI_JOB_ID", "")
    if not job.isdecimal():
        raise ValueError(
            "Cleanup requires this CI job's numeric CI_JOB_ID; local tests clean their own random project"
        )
    for resource, listing in (
        ("container", ["ps", "--all", "--quiet"]),
        ("network", ["network", "ls", "--quiet"]),
        ("volume", ["volume", "ls", "--quiet"]),
    ):
        identifiers = (
            docker([*listing, "--filter", f"label=io.xarionix.test.job-id={job}"]).stdout.decode().split()
        )
        for identifier in identifiers:
            template = "{{json .Config.Labels}}" if resource == "container" else "{{json .Labels}}"
            labels = json.loads(docker([resource, "inspect", "--format", template, identifier]).stdout)
            if labels.get("io.xarionix.test.job-id") != job or not labels.get(
                "com.docker.compose.project", ""
            ).startswith("xarionix-test-"):
                raise ValueError("Refusing cleanup: resource does not belong to this isolated test job")
            docker([resource, "rm", *(["--force"] if resource == "container" else []), identifier])
    print("Only resources labeled for this isolated CI job were cleaned")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=(
            "preflight",
            "build",
            "image-check",
            "export",
            "trivy",
            "secrets",
            "publish",
            "dev-check",
            "cleanup-tests",
        ),
    )
    parser.add_argument("--image", default="xarionix-core:local")
    args = parser.parse_args()
    (ROOT / ".ci-tmp").mkdir(exist_ok=True)
    try:
        match args.command:
            case "preflight":
                preflight()
            case "build":
                build(args.image)
            case "image-check":
                image_check(args.image)
            case "export":
                export_image(args.image)
            case "trivy":
                trivy(args.image)
            case "secrets":
                secrets_check()
            case "publish":
                publish()
            case "dev-check":
                dev_check()
            case "cleanup-tests":
                cleanup_tests()
    except (RuntimeError, ValueError, OSError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
