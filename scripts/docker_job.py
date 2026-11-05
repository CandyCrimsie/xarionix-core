"""Docker-executor bridge. Outer half needs only Python's standard library and Docker CLI.

All check code runs INSIDE the job's rootless DinD daemon. Its workspace is a named
volume mounted at its daemon-side absolute path, so Compose bind mounts and file
ownership keep working. No VM Docker socket, shared host paths or TCP port 2375.
"""

from __future__ import annotations

import argparse
import io
import json
import os

# Fixed argv, never shell input.
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
ROOTLESS_IMAGE = (
    "docker:29.9.2-dind-rootless@sha256:ae083cc7de51e7a8e5a597f8fb774ca7914c408a95fc0f1477826a913479518a"
)
ROOTLESS_SOCKET = "/run/user/1000/docker.sock"  # DinD service's socket, NOT the VM socket.
JOBS = ("compose", "integration", "secrets", "scan", "runtime-images", "build", "publish")
PUBLIC_ENV = (
    "CI",
    "CI_JOB_ID",
    "CI_PIPELINE_ID",
    "CI_PROJECT_ID",
    "CI_COMMIT_SHA",
    "CI_COMMIT_TIMESTAMP",
    "CI_PROJECT_URL",
    "CI_COMMIT_TAG",
    "CI_COMMIT_REF_SLUG",
    "CI_COMMIT_REF_PROTECTED",
)
REGISTRY_ENV = ("CI_REGISTRY", "CI_REGISTRY_IMAGE", "CI_REGISTRY_USER", "CI_REGISTRY_PASSWORD")
REPORTS = {
    "integration.xml",
    "integration-diagnostics.json",
    "gitleaks.json",
    "gitleaks-working-tree.json",
    "trivy-image.json",
    "trivy-agent.json",
    "trivy-runtime.json",
    "trivy-gateway-agent.json",
    "trivy-business-runtime.json",
    "docker-job.json",
}
DIST = {"core-image.tar", "image.json"}


def log(message: str) -> None:
    print("[docker-job] " + message, flush=True)


def command(
    arguments: list[str],
    *,
    capture: bool = True,
    timeout: float = 120,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Never echo argv/env: publish receives registry credentials by inherited env only."""
    try:
        # Structured argv, no shell.
        result = subprocess.run(  # nosec B603
            arguments,
            cwd=ROOT,
            stdin=stdin,
            stdout=stdout if stdout else (subprocess.PIPE if capture else None),
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("Command unavailable or timed out; inspect the preceding job phase") from None
    if check and result.returncode:
        # No raw Docker JSON/config/stderr: these can contain expanded credentials.
        raise RuntimeError(
            f"Command failed with exit code {result.returncode}; inspect the preceding job phase"
        )
    return result


def preflight(*, timeout: float = 120) -> None:
    endpoint = urlsplit(os.environ.get("DOCKER_HOST", ""))
    if endpoint.scheme != "tcp" or not endpoint.hostname or endpoint.port != 2376:
        raise ValueError("Docker-executor jobs require the rootless DinD TLS endpoint on port 2376")
    if os.environ.get("DOCKER_TLS_VERIFY") != "1":
        raise ValueError("Docker-executor jobs require DOCKER_TLS_VERIFY=1")
    certs = Path(os.environ.get("DOCKER_CERT_PATH", "/certs/client"))
    log("Waiting for rootless DinD over verified TLS (deadline 120s)")
    deadline = time.monotonic() + timeout
    while True:
        if all((certs / filename).is_file() for filename in ("ca.pem", "cert.pem", "key.pem")):
            try:
                result = command(["docker", "info", "--format", "{{json .SecurityOptions}}"], timeout=10)
                options = json.loads(result.stdout)
                if "name=rootless" not in options:
                    raise ValueError("Refusing a non-rootless Docker daemon")
                command(["docker", "compose", "version"], timeout=10)
                log("Rootless Docker daemon, TLS and Compose available")
                return
            except (RuntimeError, json.JSONDecodeError):
                pass
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "Rootless DinD did not become ready. Runner needs services_privileged=true, "
                "only the pinned rootless image in allowed_privileged_services, and /certs/client shared. "
                "Check the Runner service log; never expose the VM docker.sock or disable TLS."
            )
        time.sleep(0.5)


def source_files() -> list[Path]:
    result = command(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"])
    return sorted({ROOT / name for name in result.stdout.decode().strip("\0").split("\0") if name})


def archive_source(destination: BinaryIO, *, publish: bool = False) -> None:
    """Copy source + history, not ignored env/venv/artifacts or GitLab's clone credentials."""
    files = source_files()
    git = ROOT / ".git"
    if not git.is_dir() or git.is_symlink():
        raise ValueError("CI source transfer requires a regular .git directory")
    directories = {git}
    for name in ("HEAD", "index", "shallow", "packed-refs", "objects", "refs"):
        source = git / name
        if source.is_dir():
            # A detached GitLab checkout may keep every ref packed. Git still
            # requires the empty refs/objects directories to recognize the repo.
            directories.add(source)
            for path in source.rglob("*"):
                if path.is_symlink():
                    raise ValueError("Refusing a symlink in CI Git metadata")
                if path.is_dir():
                    directories.add(path)
                else:
                    files.append(path)
        elif source.exists():
            files.append(source)
    if publish:
        files.extend(ROOT / "dist" / name for name in sorted(DIST))
    with tarfile.open(fileobj=destination, mode="w") as archive:
        for source in [*sorted(directories), *files]:
            if (
                source.is_symlink()
                or not source.resolve().is_relative_to(ROOT)
                or not (source.is_file() or source in directories)
            ):
                raise ValueError("Refusing a missing file, symlink or path outside the CI checkout")
            name = source.relative_to(ROOT).as_posix()
            leaf = source.name
            if leaf != ".env.example" and (
                leaf == ".env"
                or leaf.startswith(".env.")
                or leaf.endswith((".env", ".pem", ".key", ".p12", ".pfx", ".dump", ".private", ".xpkg"))
            ):
                raise ValueError("Refusing a secret/config data file in the source archive")
            info = archive.gettarinfo(str(source), arcname=name)
            info.uid = info.gid = 0  # uid 0 INSIDE the rootless daemon's user namespace.
            info.uname = info.gname = ""
            if source in directories:
                archive.addfile(info)
            else:
                with source.open("rb") as content:
                    archive.addfile(info, content)
        # .git/config and reflogs can contain CI_JOB_TOKEN in the clone URL. Never transfer them.
        config = b"[core]\nrepositoryformatversion = 0\nbare = false\n"
        info = tarfile.TarInfo(".git/config")
        info.mode, info.size = 0o644, len(config)
        archive.addfile(info, io.BytesIO(config))
    destination.seek(0)


def restore_artifacts(archive: BinaryIO, destination: Path, allowed: set[str]) -> None:
    """An inner job cannot make artifact collection follow symlinks or escape reports/dist."""
    if destination.is_symlink():
        raise ValueError("Refusing artifact directory symlink")
    destination.mkdir(exist_ok=True)
    with tarfile.open(fileobj=archive, mode="r:*") as contents:
        for member in contents:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or member.issym() or member.islnk():
                raise ValueError("Unsafe artifact path or link")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("Non-regular artifact")
            if name.as_posix().removeprefix("./") not in allowed:
                continue
            target = destination / name.name
            if target.is_symlink():
                raise ValueError("Refusing artifact destination symlink")
            source = contents.extractfile(member)
            if source is not None:
                with target.open("wb") as output:
                    while block := source.read(1024 * 1024):
                        output.write(block)


def inner(job: str) -> None:
    # Only this isolated controller uses host networking: the host here is the job's
    # rootless DinD network namespace, never the physical Runner VM.
    from scripts import ci

    (ROOT / ".ci-tmp").mkdir(exist_ok=True)
    (ROOT / "reports").mkdir(exist_ok=True)
    venv = ROOT / ".venv"
    if not venv.exists():
        venv.symlink_to("/opt/ci/venv", target_is_directory=True)
    image = "xarionix-core:ci-" + os.environ.get("CI_JOB_ID", uuid.uuid4().hex)
    log(f"Executing {job} inside this job's rootless daemon")
    try:
        match job:
            case "compose":
                from scripts.compose_check import check

                check(nginx=True)
            case "integration":
                # The toolbox contains locked dependencies, not this checkout's distribution.
                # Install after source transfer so importlib.metadata sees the current project
                # (including app.version), just like make install-dev and the Python CI jobs.
                log("Installing current Core checkout into the CI test environment (without dependencies)")
                command(
                    [sys.executable, "-m", "pip", "install", "--no-deps", "--editable", "."],
                    capture=False,
                    timeout=120,
                )
                os.environ["XARIONIX_RUN_DOCKER_TESTS"] = "1"
                command(
                    [
                        sys.executable,
                        "-m",
                        "pytest",
                        "-vv",
                        "-m",
                        "integration",
                        # Pytest's default /tmp lives only in this controller. Daemon-side
                        # bind mounts must stay inside the shared workspace volume.
                        "--basetemp=.ci-tmp/pytest",
                        "--junitxml=reports/integration.xml",
                    ],
                    capture=False,
                    timeout=1800,
                )
            case "secrets":
                ci.secrets_check()
            case "runtime-images":
                from scripts.runtime_images import check as runtime_image_check

                runtime_image_check()
            case "scan" | "build":
                ci.build(image)
                if job == "build":
                    ci.image_check(image)
                ci.trivy(image)
                if job == "build":
                    ci.export_image(image)
            case "publish":
                ci.publish()
            case _:
                raise ValueError("Unknown Docker job")
    finally:
        if job == "integration" and os.environ.get("CI_JOB_ID", "").isdecimal():
            ci.cleanup_tests()


def wait_for_controller(name: str, job: str, *, timeout: float = 2400) -> None:
    """A log transport exit is not the controller exit; confirm completion with the daemon."""
    deadline = time.monotonic() + timeout
    streamed = command(["docker", "logs", "--follow", name], capture=False, timeout=timeout, check=False)
    log("Confirming controller completion with docker wait and inspect")
    waited = command(["docker", "wait", name], timeout=max(1, deadline - time.monotonic()))
    exit_text = waited.stdout.decode().strip()
    if not exit_text.isascii() or not exit_text.isdecimal() or not 0 <= int(exit_text) <= 255:
        raise RuntimeError(f"{job} returned an invalid container exit status")
    exit_code = int(exit_text)
    state = json.loads(command(["docker", "inspect", "--format", "{{json .State}}", name]).stdout)
    if not (
        isinstance(state, dict)
        and state.get("Status") == "exited"
        and state.get("Running") is False
        and state.get("Dead") is False
        and state.get("OOMKilled") is False
        and state.get("Error") == ""
        and type(state.get("ExitCode")) is int
        and state["ExitCode"] == exit_code
    ):
        # Never print raw State.Error or Docker stderr: either may contain private configuration.
        raise RuntimeError(f"{job} has no confirmed normal container completion")
    if exit_code:
        raise RuntimeError(f"{job} failed in the rootless job container (exit {exit_code})")
    if streamed.returncode:
        log(
            f"Log streaming ended with CLI exit {streamed.returncode}; "
            "docker wait and inspect confirmed controller exit 0"
        )


def run_job(job: str) -> None:
    if job not in JOBS:
        raise ValueError("Unknown Docker job")
    preflight()
    identifier = uuid.uuid4().hex
    name = "xarionix-ci-" + identifier
    toolbox = "xarionix-ci-toolbox:" + identifier
    labels = ["--label", "io.xarionix.ci.job-id=" + os.environ.get("CI_JOB_ID", "local")]
    log("Building pinned CI toolbox (not the production image)")
    command(
        ["docker", "build", "--progress", "plain", "-f", "deploy/ci/Dockerfile", "-t", toolbox, "."],
        capture=False,
        timeout=1200,
    )
    created = False
    try:
        command(["docker", "volume", "create", *labels, name])
        mountpoint = (
            command(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}", name])
            .stdout.decode()
            .strip()
        )
        if not mountpoint.startswith("/") or not mountpoint.endswith("/" + name + "/_data"):
            raise ValueError("Unexpected workspace volume path")
        env = list(PUBLIC_ENV) + (list(REGISTRY_ENV) if job == "publish" else [])
        arguments = [
            "docker",
            "create",
            "--name",
            name,
            *labels,
            "--network",
            "host",
            "--security-opt",
            "no-new-privileges:true",
            "--mount",
            f"type=volume,source={name},target={mountpoint}",
            "--mount",
            f"type=bind,source={ROOTLESS_SOCKET},target={ROOTLESS_SOCKET}",
            "--env",
            "DOCKER_HOST=unix://" + ROOTLESS_SOCKET,
            "--env",
            "DOCKER_TLS_VERIFY=",
            "--env",
            "DOCKER_CERT_PATH=",
            "--env",
            "DOCKER_BUILDKIT=1",
            "--workdir",
            mountpoint,
        ]
        for key in env:
            if key in os.environ:
                arguments += ["--env", key]  # value inherited by CLI, never part of argv/log.
        arguments += [toolbox, "python", "-m", "scripts.docker_job", "inner", job]
        command(arguments)
        created = True
        with tempfile.TemporaryFile() as archive:
            archive_source(archive, publish=job == "publish")
            command(["docker", "cp", "--archive", "-", name + ":" + mountpoint], stdin=archive)
        log("Source/history transferred; ignored configuration and clone credentials excluded")
        command(["docker", "start", name])
        try:
            wait_for_controller(name, job)
        finally:
            # Preserve reports even when wait/inspect fail, not only for failed tests.
            for folder, allowed in (("reports", REPORTS), ("dist", DIST if job == "build" else set())):
                if not allowed:
                    continue
                with tempfile.TemporaryFile() as archive:
                    copied = command(
                        ["docker", "cp", name + ":" + mountpoint + "/" + folder + "/.", "-"],
                        stdout=archive,
                        check=False,
                    )
                    if copied.returncode == 0:
                        archive.seek(0)
                        restore_artifacts(archive, ROOT / folder, allowed)
        if job == "build" and not all((ROOT / "dist" / file).is_file() for file in DIST):
            raise RuntimeError("Build succeeded but required image artifacts are missing")
        log(f"{job} finished successfully; safe artifacts copied back")
    finally:
        if created:
            command(["docker", "rm", "--force", name], check=False)
        command(["docker", "volume", "rm", name], check=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("run", "inner"))
    parser.add_argument("job", choices=JOBS)
    args = parser.parse_args()
    try:
        (run_job if args.command == "run" else inner)(args.job)
    except (RuntimeError, ValueError, OSError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
