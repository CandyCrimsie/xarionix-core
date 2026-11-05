import io
import json
import subprocess
import tarfile
import tomllib
from pathlib import Path

import pytest

from scripts import configure_docker_runner as runner
from scripts import docker_job as job


def test_pinned_service_matches_pipeline_and_restricted_runner_allowlist():
    import yaml

    root = Path(__file__).resolve().parents[1]
    config = yaml.safe_load((root / ".gitlab-ci.yml").read_text())
    assert config[".docker"]["services"][0]["name"] == job.ROOTLESS_IMAGE == runner.ROOTLESS_IMAGE
    assert runner.ALLOWED_IMAGES == [job.ROOTLESS_IMAGE, "docker.io/library/" + job.ROOTLESS_IMAGE]
    assert not any("*" in name for name in runner.ALLOWED_IMAGES)
    assert "privileged" not in config[".docker"]  # only the pinned service receives it server-side


@pytest.fixture
def tls(monkeypatch, tmp_path):
    for name in ("ca.pem", "cert.pem", "key.pem"):
        (tmp_path / name).touch()
    monkeypatch.setenv("DOCKER_HOST", "tcp://docker:2376")
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")
    monkeypatch.setenv("DOCKER_CERT_PATH", str(tmp_path))


def test_dind_preflight_requires_actual_rootless_daemon_and_compose(tls, monkeypatch):
    calls = []

    def command(arguments, **kwargs):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, b'["name=rootless"]')

    monkeypatch.setattr(job, "command", command)
    job.preflight(timeout=0)
    assert calls[0][:2] == ["docker", "info"]
    assert calls[1] == ["docker", "compose", "version"]
    monkeypatch.setattr(job, "command", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, b"[]"))
    with pytest.raises(ValueError, match="non-rootless"):
        job.preflight(timeout=0)


@pytest.mark.parametrize("endpoint", ["unix:///var/run/docker.sock", "tcp://docker:2375", ""])
def test_no_fallback_to_host_socket_or_plaintext_dind(tls, monkeypatch, endpoint):
    monkeypatch.setenv("DOCKER_HOST", endpoint)
    with pytest.raises(ValueError, match="TLS endpoint"):
        job.preflight(timeout=0)


def test_missing_dind_configuration_fails_with_actionable_message(tls, monkeypatch, tmp_path):
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "0")
    with pytest.raises(ValueError, match="VERIFY=1"):
        job.preflight(timeout=0)
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")
    (tmp_path / "key.pem").unlink()
    with pytest.raises(RuntimeError, match="allowed_privileged_services"):
        job.preflight(timeout=0)


def test_source_archive_excludes_credentials_and_preserves_history(tmp_path, monkeypatch):
    monkeypatch.setattr(job, "ROOT", tmp_path)
    (tmp_path / ".git/refs/heads").mkdir(parents=True)
    (tmp_path / ".git/HEAD").write_text("ref: refs/heads/main\n")
    (tmp_path / ".git/refs/heads/main").write_text("a" * 40)
    (tmp_path / ".git/config").write_text("private clone credential must not be transferred")
    (tmp_path / ".env").write_text("real private dotenv must not be transferred")
    (tmp_path / "source.py").write_text("print('source')")
    monkeypatch.setattr(job, "source_files", lambda: [tmp_path / "source.py"])
    output = io.BytesIO()
    job.archive_source(output)
    with tarfile.open(fileobj=output) as archive:
        assert ".env" not in archive.getnames()
        assert ".git/refs/heads/main" in archive.getnames()
        assert b"private" not in archive.extractfile(".git/config").read()
        assert archive.getmember("source.py").uid == 0


def test_source_archive_preserves_real_detached_packed_refs_checkout(tmp_path, monkeypatch):
    source, restored = tmp_path / "source", tmp_path / "restored"
    source.mkdir()
    subprocess.run(["git", "init", "--quiet", str(source)], check=True)
    (source / "tracked.py").write_text("print('source')\n")
    subprocess.run(["git", "add", "tracked.py"], cwd=source, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=CI Test",
            "-c",
            "user.email=ci@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
        cwd=source,
        check=True,
    )
    subprocess.run(["git", "pack-refs", "--all", "--prune"], cwd=source, check=True)
    subprocess.run(["git", "checkout", "--quiet", "--detach", "HEAD"], cwd=source, check=True)
    assert not any(p.is_file() for p in (source / ".git/refs").rglob("*"))
    monkeypatch.setattr(job, "ROOT", source)
    output = io.BytesIO()
    job.archive_source(output)
    with tarfile.open(fileobj=output) as archive:
        archive.extractall(restored, filter="data")
    result = subprocess.run(["git", "ls-files"], cwd=restored, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "tracked.py\n"
    expected = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source)
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=restored) == expected


def test_ci_venv_link_is_ignored_just_like_a_local_venv_directory(tmp_path):
    root = Path(__file__).resolve().parents[1]
    (tmp_path / ".gitignore").write_text((root / ".gitignore").read_text())
    (tmp_path / ".venv").symlink_to("/opt/ci/venv", target_is_directory=True)
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    result = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=tmp_path)
    assert b".venv" not in result


@pytest.mark.parametrize("bad", [".env", "secret.key", "settings.env"])
def test_even_tracked_secrets_are_refused_in_source_transfer(tmp_path, monkeypatch, bad):
    monkeypatch.setattr(job, "ROOT", tmp_path)
    (tmp_path / ".git").mkdir()
    path = tmp_path / bad
    path.touch()
    monkeypatch.setattr(job, "source_files", lambda: [path])
    with pytest.raises(ValueError, match="secret/config"):
        job.archive_source(io.BytesIO())


def test_source_symlinks_and_external_gitdirs_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(job, "ROOT", tmp_path)
    (tmp_path / ".git").write_text("gitdir: somewhere else")
    monkeypatch.setattr(job, "source_files", lambda: [])
    with pytest.raises(ValueError, match="regular .git"):
        job.archive_source(io.BytesIO())
    (tmp_path / ".git").unlink()
    (tmp_path / ".git").mkdir()
    path = tmp_path / "link"
    path.symlink_to("/etc/passwd")
    monkeypatch.setattr(job, "source_files", lambda: [path])
    with pytest.raises(ValueError, match="symlink"):
        job.archive_source(io.BytesIO())


def artifact(name="integration.xml", link=False):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        member = tarfile.TarInfo(name)
        if link:
            member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
        else:
            member.size = 3
        archive.addfile(member, None if link else io.BytesIO(b"xml"))
    result.seek(0)
    return result


def test_only_allowlisted_regular_artifacts_are_restored(tmp_path):
    job.restore_artifacts(artifact(), tmp_path / "reports", job.REPORTS)
    assert (tmp_path / "reports/integration.xml").read_text() == "xml"
    job.restore_artifacts(artifact("private.env"), tmp_path / "reports", job.REPORTS)
    assert not (tmp_path / "reports/private.env").exists()


@pytest.mark.parametrize(
    "name,link", [("../outside", False), ("/etc/file", False), ("integration.xml", True)]
)
def test_artifacts_cannot_escape_or_follow_links(tmp_path, name, link):
    with pytest.raises(ValueError, match="Unsafe"):
        job.restore_artifacts(artifact(name, link), tmp_path / "reports", job.REPORTS)


def test_artifact_destination_symlinks_are_refused(tmp_path):
    (tmp_path / "reports").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="directory symlink"):
        job.restore_artifacts(artifact(), tmp_path / "reports", job.REPORTS)


def exited_state(exit_code=0):
    return {
        "Status": "exited",
        "Running": False,
        "Dead": False,
        "OOMKilled": False,
        "Error": "",
        "ExitCode": exit_code,
    }


@pytest.mark.parametrize(
    "failure,stream_exit",
    [("", 0), ("", 1), ("controller", 0), ("controller", 1), ("wait", 1), ("start", 0)],
)
def test_rootless_job_cleans_only_its_workspace_and_passes_no_secret_values_in_argv(
    tmp_path, monkeypatch, capsys, failure, stream_exit
):
    monkeypatch.setattr(job, "ROOT", tmp_path)
    monkeypatch.setattr(job, "preflight", lambda: None)
    monkeypatch.setattr(job, "archive_source", lambda *args, **kwargs: None)
    monkeypatch.setenv("CI_JOB_ID", "123")
    monkeypatch.setenv("CI_REGISTRY_PASSWORD", "test-job-credential-only-environment")
    calls = []

    def command(arguments, **kwargs):
        calls.append(arguments)
        if "volume" in arguments and "inspect" in arguments:
            return subprocess.CompletedProcess(
                arguments, 0, ("/rootless/volumes/" + arguments[-1] + "/_data").encode()
            )
        if "inspect" in arguments:
            return subprocess.CompletedProcess(
                arguments, 0, json.dumps(exited_state(1 if failure == "controller" else 0)).encode()
            )
        if arguments[1] == "start":
            assert "--attach" not in arguments and kwargs.get("check", True)
            if failure == "start":
                raise RuntimeError("Controller start failed")
        if arguments[1] == "logs":
            return subprocess.CompletedProcess(arguments, stream_exit, b"")
        if arguments[1] == "wait":
            assert kwargs.get("check", True)
            if failure == "wait":
                raise RuntimeError("Docker wait failed")
            return subprocess.CompletedProcess(arguments, 0, b"1\n" if failure == "controller" else b"0\n")
        if "cp" in arguments and arguments[-1] == "-":
            kwargs["stdout"].write(artifact().read())
        return subprocess.CompletedProcess(arguments, 0, b"")

    monkeypatch.setattr(job, "command", command)
    if failure:
        with pytest.raises(RuntimeError, match="failed"):
            job.run_job("publish")
    else:
        job.run_job("publish")
    assert (tmp_path / "reports/integration.xml").exists() == (failure != "start")
    if failure != "start":
        assert (tmp_path / "reports/integration.xml").read_text() == "xml"
        assert (
            next(i for i, call in enumerate(calls) if call[1] == "start")
            < next(i for i, call in enumerate(calls) if call[1] == "logs")
            < next(i for i, call in enumerate(calls) if call[1] == "wait")
        )
    create = next(call for call in calls if call[1] == "create")
    assert "CI_REGISTRY_PASSWORD" in create
    assert all("test-job-credential-only-environment" not in str(call) for call in calls)
    assert not any("/var/run/docker.sock" in str(call) for call in calls)
    assert "--privileged" not in create
    assert any(call[1:3] == ["rm", "--force"] for call in calls)
    assert calls[-1][:3] == ["docker", "volume", "rm"]
    output = capsys.readouterr()
    assert "test-job-credential-only-environment" not in output.out + output.err
    assert ("confirmed controller exit 0" in output.out) == (not failure and stream_exit != 0)


@pytest.mark.parametrize("exit_code", [0, 1, 137])
@pytest.mark.parametrize("stream_exit", [0, 1, 125])
def test_controller_result_uses_wait_and_inspect_not_the_log_transport(
    monkeypatch, capsys, exit_code, stream_exit
):
    calls = []
    times = iter([100.0, 104.0])
    monkeypatch.setattr(job.time, "monotonic", lambda: next(times))

    def command(arguments, **kwargs):
        calls.append(arguments[1])
        if arguments[1] == "logs":
            assert kwargs == {"capture": False, "timeout": 10, "check": False}
            return subprocess.CompletedProcess(arguments, stream_exit)
        if arguments[1] == "wait":
            assert kwargs == {"timeout": 6}
            return subprocess.CompletedProcess(arguments, 0, f"{exit_code}\n".encode())
        return subprocess.CompletedProcess(arguments, 0, json.dumps(exited_state(exit_code)).encode())

    monkeypatch.setattr(job, "command", command)
    if exit_code:
        with pytest.raises(RuntimeError, match=f"container \\(exit {exit_code}\\)"):
            job.wait_for_controller("isolated-controller", "integration", timeout=10)
    else:
        job.wait_for_controller("isolated-controller", "integration", timeout=10)
    assert calls == ["logs", "wait", "inspect"]
    assert ("confirmed controller exit 0" in capsys.readouterr().out) == (exit_code == 0 and stream_exit != 0)


@pytest.mark.parametrize(
    "state",
    [
        {},
        None,
        [],
        {**exited_state(), "Status": "created"},
        {**exited_state(), "Status": "running", "Running": True},
        {**exited_state(), "Running": True},
        {**exited_state(), "Dead": True},
        {**exited_state(), "OOMKilled": True},
        {**exited_state(), "Error": "private-error-payload"},
        {**exited_state(), "ExitCode": 1},
        {**exited_state(), "ExitCode": "0"},
        {**exited_state(), "ExitCode": False},
    ],
)
def test_zero_wait_never_accepts_unconfirmed_or_abnormal_state(monkeypatch, capsys, state):
    def command(arguments, **kwargs):
        output = json.dumps(state).encode() if arguments[1] == "inspect" else b"0\n"
        return subprocess.CompletedProcess(arguments, 0, output)

    monkeypatch.setattr(job, "command", command)
    with pytest.raises(RuntimeError, match="no confirmed normal") as error:
        job.wait_for_controller("isolated-controller", "integration")
    output = capsys.readouterr()
    assert "private-error-payload" not in str(error.value) + output.out + output.err


@pytest.mark.parametrize("wait_output", [b"", b"0\n1", b"-1", b"256", b"private-wait-payload", b"\xff"])
def test_invalid_wait_response_cannot_be_treated_as_success(monkeypatch, capsys, wait_output):
    def command(arguments, **kwargs):
        return subprocess.CompletedProcess(arguments, 0, wait_output)

    monkeypatch.setattr(job, "command", command)
    with pytest.raises((RuntimeError, UnicodeDecodeError)) as error:
        job.wait_for_controller("isolated-controller", "integration")
    output = capsys.readouterr()
    assert "private-wait-payload" not in str(error.value) + output.out + output.err


@pytest.mark.parametrize("kind", ["compose", "secrets", "scan", "build", "publish", "integration"])
def test_inner_dispatch_keeps_real_checks_including_scan_of_final_image(tmp_path, monkeypatch, kind):
    from scripts import ci, compose_check

    monkeypatch.setattr(job, "ROOT", tmp_path)
    monkeypatch.setenv("CI_JOB_ID", "123")
    calls = []
    for name in (
        "build",
        "image_check",
        "trivy",
        "export_image",
        "publish",
        "secrets_check",
        "cleanup_tests",
    ):
        monkeypatch.setattr(ci, name, lambda *args, _name=name, **kwargs: calls.append(_name))
    monkeypatch.setattr(compose_check, "check", lambda **kwargs: calls.append("nginx"))

    def command(arguments, **kwargs):
        assert arguments[0] == job.sys.executable
        if arguments[1:3] == ["-m", "pip"]:
            assert arguments[3:] == ["install", "--no-deps", "--editable", "."]
            assert kwargs == {"capture": False, "timeout": 120}
            calls.append("install-project")
        else:
            assert arguments[1:3] == ["-m", "pytest"]
            assert "--basetemp=.ci-tmp/pytest" in arguments
            calls.append("pytest")

    monkeypatch.setattr(job, "command", command)
    job.inner(kind)
    expected = {
        "compose": ["nginx"],
        "secrets": ["secrets_check"],
        "scan": ["build", "trivy"],
        "build": ["build", "image_check", "trivy", "export_image"],
        "publish": ["publish"],
        "integration": ["install-project", "pytest", "cleanup_tests"],
    }
    assert calls == expected[kind]


def test_integration_install_failure_stops_collection_and_still_cleans_own_resources(tmp_path, monkeypatch):
    from scripts import ci

    monkeypatch.setattr(job, "ROOT", tmp_path)
    monkeypatch.setenv("CI_JOB_ID", "123")
    calls = []

    def command(arguments, **kwargs):
        assert arguments[1:4] == ["-m", "pip", "install"]
        calls.append("install-project")
        raise RuntimeError("Project installation failed")

    monkeypatch.setattr(job, "command", command)
    monkeypatch.setattr(ci, "cleanup_tests", lambda: calls.append("cleanup_tests"))
    with pytest.raises(RuntimeError, match="Project installation failed"):
        job.inner("integration")
    assert calls == ["install-project", "cleanup_tests"]


CONFIG = """concurrent = 1
[[runners]]
  name = "existing-runner"
  executor = "docker"
  token = "fixture-token-must-never-be-printed"
  [runners.docker]
    image = "alpine:3.20"
    privileged = false
    volumes = [
      "/cache",
    ]
    shm_size = 0
  [runners.cache]
    Shared = false
"""


def test_runner_patch_preserves_every_other_setting_and_is_idempotent():
    before = tomllib.loads(CONFIG)
    result = runner.patch_config(CONFIG)
    after = tomllib.loads(result)
    docker = after["runners"][0]["docker"]
    assert docker["privileged"] is False and docker["services_privileged"] is True
    assert docker["allowed_privileged_services"] == runner.ALLOWED_IMAGES
    assert docker["volumes"] == ["/cache", "/certs/client"]
    for key in ("services_privileged", "allowed_privileged_services"):
        docker.pop(key)
    docker["volumes"] = ["/cache"]
    assert after == before
    assert runner.patch_config(result) == result


@pytest.mark.parametrize("defect", ["shell", "privileged", "socket", "allowlist", "multiple"])
def test_unsafe_or_ambiguous_runner_config_requires_manual_review(defect):
    config = CONFIG
    match defect:
        case "shell":
            config = config.replace('executor = "docker"', 'executor = "shell"')
        case "privileged":
            config = config.replace("privileged = false", "privileged = true")
        case "socket":
            config = config.replace('"/cache",', '"/var/run/docker.sock:/var/run/docker.sock",')
        case "allowlist":
            config = config.replace("shm_size = 0", 'allowed_privileged_services = ["*"]')
        case "multiple":
            config += '\n[[runners]]\nname="other"\nexecutor="docker"\n'
    with pytest.raises(ValueError):
        runner.patch_config(config)


def test_runner_update_is_explicit_private_and_never_prints_tokens(tmp_path, capsys):
    path = tmp_path / "config.toml"
    path.write_text(CONFIG)
    runner.configure(path, apply=False)
    assert path.read_text() == CONFIG
    assert not list(tmp_path.glob("*.backup.*"))
    assert runner.configure(path, apply=True) is True
    assert path.stat().st_mode & 0o777 == 0o600
    (backup,) = tmp_path.glob("*.backup.*")
    assert backup.read_text() == CONFIG and backup.stat().st_mode & 0o777 == 0o600
    assert runner.configure(path, apply=True) is False
    assert len(list(tmp_path.glob("*.backup.*"))) == 1
    output = capsys.readouterr()
    assert "fixture-token-must-never-be-printed" not in output.out + output.err
