import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

from scripts import ci, compose_check, setup, validate

ROOT = Path(__file__).resolve().parents[1]


def external_definition():
    definition = yaml.safe_load((ROOT / "compose.yaml").read_text())
    definition["services"]["core"]["environment"]["XARIONIX_OIDC_BACKCHANNEL"] = ""
    return definition


@pytest.mark.parametrize("filename", ["compose.yaml", "compose.dev.yaml", "compose.keycloak.yaml"])
def test_tmpfs_options_are_one_absolute_mount_not_yaml_array_items(filename):
    definition = yaml.safe_load((ROOT / filename).read_text())
    for service in definition["services"].values():
        if "tmpfs" in service:
            assert len(service["tmpfs"]) == 1
            assert service["tmpfs"][0].startswith("/tmp:rw,")
            assert "nosuid" in service["tmpfs"][0] and "nodev" in service["tmpfs"][0]
        for mount in service.get("volumes", []):
            assert isinstance(mount, dict) and mount["target"].startswith("/")
            if mount["type"] == "bind":
                assert mount["read_only"] is True
                assert mount["bind"]["create_host_path"] is False


@pytest.mark.parametrize(
    "defect",
    [
        "relative_tmpfs",
        "privileged",
        "unsafe_bind",
        "public_db",
        "host_network",
        "health",
        "migrations",
        "external_backchannel",
        "db_network",
    ],
)
def test_compose_security_audit_rejects_real_regressions(defect):
    definition = external_definition()
    compose_check.audit(definition, "external")
    services = definition["services"]
    match defect:
        case "relative_tmpfs":
            services["core"]["tmpfs"] = ["/tmp:rw", "noexec", "nosuid"]
        case "privileged":
            services["core"]["privileged"] = True
        case "unsafe_bind":
            services["nginx"]["volumes"][0]["bind"]["create_host_path"] = True
        case "public_db":
            services["postgres"]["ports"] = ["5432:5432"]
        case "host_network":
            services["core"]["network_mode"] = "host"
        case "health":
            del services["postgres"]["healthcheck"]
        case "migrations":
            services["core"]["depends_on"]["migrate"]["condition"] = "service_started"
        case "external_backchannel":
            services["core"]["environment"]["XARIONIX_OIDC_BACKCHANNEL"] = "http://untrusted"
        case "db_network":
            definition["networks"]["core_db"]["internal"] = False
    with pytest.raises(ValueError):
        compose_check.audit(definition, "external")


def test_compose_fixtures_never_read_existing_secrets(monkeypatch):
    def forbidden(*args):
        raise AssertionError("must not read installed dotenv")

    monkeypatch.setattr(setup, "read_env", forbidden)
    monkeypatch.setenv("XARIONIX_DB_PASSWORD", "sensitive-real-value")
    with compose_check.configurations() as configurations:
        assert {item.name for item in configurations} == {"dev", "external", "managed"}
        for item in configurations:
            assert item.project.startswith("xarionix-config-")
            path = Path(item.arguments[item.arguments.index("--env-file") + 1])
            assert path.stat().st_mode & 0o777 == 0o600
            assert "sensitive-real-value" not in path.read_text()
            assert "xarionix-core-dev" != item.project
    assert "XARIONIX_DB_PASSWORD" not in compose_check.clean_environment()


def test_docker_cli_absence_and_daemon_error_do_not_leak_output(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(RuntimeError, match="unavailable"):
        compose_check.docker(["info"])
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 1, b"", b"private password"),
    )
    with pytest.raises(RuntimeError) as error:
        compose_check.docker(["info"])
    assert "private password" not in str(error.value)


def test_docker_runner_preflight_fails_explicitly_not_as_a_skipped_success(monkeypatch):
    def unavailable(*args, **kwargs):
        raise RuntimeError("unavailable")

    monkeypatch.setattr(ci, "docker", unavailable)
    with pytest.raises(RuntimeError, match="dedicated Docker-capable runner"):
        ci.preflight()


@pytest.mark.parametrize("finding_report", [False, True])
def test_trivy_failures_block_and_never_reuse_a_stale_success(tmp_path, monkeypatch, finding_report):
    monkeypatch.setattr(ci, "ROOT", tmp_path)
    (tmp_path / ".ci-tmp").mkdir()
    (tmp_path / "reports").mkdir()
    report = tmp_path / "reports/trivy-image.json"
    report.write_text('{"Results": []}')

    def scan(arguments, **kwargs):
        if arguments[0] == "run":
            assert not report.exists()
            assert "--ignore-unfixed" not in arguments
            assert arguments[arguments.index("--timeout") + 1] == "12m"
            assert "--no-progress" in arguments
            assert arguments[arguments.index("--severity") + 1] == "HIGH,CRITICAL"
            assert not any("docker.sock" in argument for argument in arguments)
            if finding_report:
                report.write_text('{"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}]}')
            raise RuntimeError("raw scanner stderr is not safe to publish")
        return subprocess.CompletedProcess([], 0, b"")

    monkeypatch.setattr(ci, "docker", scan)
    with pytest.raises(RuntimeError, match="security gate remains blocking") as error:
        ci.trivy("xarionix-core:test")
    assert "raw scanner stderr" not in str(error.value)
    assert report.exists() is finding_report


def test_safe_yaml_rejects_duplicates_and_python_objects(tmp_path):
    path = tmp_path / "input.yaml"
    path.write_text("stage: validate\nstage: publish\n")
    with pytest.raises(ValueError, match="Duplicate"):
        validate.load_yaml(path)
    path.write_text('!!python/object/apply:os.system ["must never execute"]')
    with pytest.raises(yaml.constructor.ConstructorError):
        validate.load_yaml(path)


def test_real_repository_validation():
    validate.check()


def test_gitlab_pipeline_has_mandatory_gates_and_no_deployment():
    config = validate.load_yaml(ROOT / ".gitlab-ci.yml")
    assert config["stages"] == ["validate", "lint", "test", "integration", "security", "build", "publish"]
    jobs = {name: value for name, value in config.items() if isinstance(value, dict) and "stage" in value}
    assert {job["stage"] for job in jobs.values()} == set(config["stages"])
    assert all(not job.get("allow_failure") for job in jobs.values())
    assert config["workflow"]["rules"][0]["variables"]["XARIONIX_DOCKER_RUNNER_TAG"] == "xarionix-release"
    publish = jobs["publish:protected-release"]
    assert all(
        'CI_COMMIT_REF_PROTECTED == "true"' in rule["if"] and "CI_COMMIT_TAG" in rule["if"]
        for rule in publish["rules"]
    )
    assert publish["dependencies"] == ["build:production"]
    assert publish["tags"] == ["xarionix-release"]
    assert "XARIONIX_RUN_DOCKER_TESTS" in jobs["integration:managed-stack"]["variables"]
    assert "--cov" in " ".join(jobs["test:unit"]["script"])
    assert jobs["test:unit"]["artifacts"]["reports"]["coverage_report"]["coverage_format"] == "cobertura"
    assert jobs["test:unit"]["artifacts"]["reports"]["junit"]
    assert any("trivy" in command for command in jobs["build:production"]["script"])
    assert all(".env" not in str(job.get("artifacts", {})) for job in jobs.values())
    assert "services" not in config[".docker"]  # No automatic privileged DinD.


def test_oci_source_supports_self_hosted_gitlab_but_never_credentials(monkeypatch):
    monkeypatch.setenv("CI_COMMIT_SHA", "a" * 40)
    monkeypatch.setenv("CI_COMMIT_TIMESTAMP", "2026-11-01T00:00:00Z")
    for scheme in ("http", "https"):
        source = scheme + "://gitlab.example.test/team/core"
        monkeypatch.setenv("CI_PROJECT_URL", source)
        assert ci.metadata()["source"] == source
    monkeypatch.setenv(
        "CI_PROJECT_URL", "https://job-user:fixture-not-a-real-secret@gitlab.example.test/core"
    )
    with pytest.raises(ValueError, match="credential-free") as error:
        ci.metadata()
    assert "fixture-not-a-real-secret" not in str(error.value)


@pytest.mark.parametrize(
    "tag,protected", [("", "false"), ("v0.1.0", "false"), ("v9.9.9", "true"), ("branch", "true")]
)
def test_publish_refuses_non_release_before_any_docker_command(monkeypatch, tag, protected):
    monkeypatch.setenv("CI_COMMIT_TAG", tag)
    monkeypatch.setenv("CI_COMMIT_REF_PROTECTED", protected)
    monkeypatch.setenv("CI_COMMIT_SHA", "a" * 40)
    monkeypatch.setattr(ci, "docker", lambda *args, **kwargs: pytest.fail("must not contact registry"))
    with pytest.raises(ValueError, match="protected release"):
        ci.publish()


def release_fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(ci, "ROOT", tmp_path)
    values = {
        "version": "0.1.0",
        "revision": "a" * 40,
        "source": "https://gitlab.example.test/team/core",
        "created": "2026-11-01T00:00:00Z",
    }
    monkeypatch.setattr(ci, "metadata", lambda: values)
    for key, value in {
        "CI_COMMIT_TAG": "v0.1.0",
        "CI_COMMIT_REF_PROTECTED": "true",
        "CI_REGISTRY": "registry.example.test",
        "CI_REGISTRY_IMAGE": "registry.example.test/team/core",
        "CI_REGISTRY_USER": "job-token-user",
        "CI_REGISTRY_PASSWORD": "test-job-token-never-print",
    }.items():
        monkeypatch.setenv(key, value)
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/core-image.tar").write_bytes(b"test-image")
    descriptor = values | {"image": "xarionix-core:test", "sha256": hashlib.sha256(b"test-image").hexdigest()}
    (tmp_path / "dist/image.json").write_text(json.dumps(descriptor))
    return descriptor


def test_publish_uses_job_credentials_only_stdin_and_checked_artifact(tmp_path, monkeypatch, capsys):
    release_fixture(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(ci, "image_check", lambda image: calls.append((["checked", image], {})))
    monkeypatch.setattr(ci, "docker", lambda arguments, **kwargs: calls.append((arguments, kwargs)))
    ci.publish()
    assert all("test-job-token-never-print" not in str(arguments) for arguments, _ in calls)
    login = next((arguments, kwargs) for arguments, kwargs in calls if "login" in arguments)
    assert login[0][-1] == "--password-stdin" and login[1]["input_data"] == b"test-job-token-never-print"
    assert not Path(login[0][1]).exists()
    tags = [arguments[-1] for arguments, _ in calls if arguments[0] == "tag"]
    assert tags == [
        "registry.example.test/team/core:0.1.0",
        "registry.example.test/team/core:sha-" + "a" * 40,
    ]
    assert "test-job-token-never-print" not in capsys.readouterr().out


def test_publish_checks_artifact_integrity_before_login(tmp_path, monkeypatch):
    release_fixture(tmp_path, monkeypatch)
    (tmp_path / "dist/core-image.tar").write_bytes(b"tampered")
    monkeypatch.setattr(ci, "docker", lambda *args, **kwargs: pytest.fail("must not load/publish"))
    with pytest.raises(ValueError, match="checksum"):
        ci.publish()


def test_cleanup_never_removes_foreign_resources(monkeypatch):
    monkeypatch.setenv("CI_JOB_ID", "1234")
    calls = []

    def docker(arguments, **kwargs):
        calls.append(arguments)
        if "inspect" in arguments:
            return subprocess.CompletedProcess(
                [],
                0,
                json.dumps(
                    {"io.xarionix.test.job-id": "1234", "com.docker.compose.project": "xarionix-core-dev"}
                ).encode(),
            )
        return subprocess.CompletedProcess([], 0, b"foreign-id\n")

    monkeypatch.setattr(ci, "docker", docker)
    with pytest.raises(ValueError, match="Refusing cleanup"):
        ci.cleanup_tests()
    assert all("rm" not in call for call in calls)


def test_gitleaks_exception_is_an_exact_non_secret_endpoint_not_a_rule_disable():
    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
    assert config["extend"]["useDefault"] is True
    assert "disabledRules" not in config["extend"]
    (rule,) = config["allowlists"]
    assert rule["condition"] == "AND"
    manifest = yaml.safe_load((ROOT / "compose.keycloak.yaml").read_text())
    endpoint = manifest["services"]["keycloak"]["environment"]["KC_DB_URL"].removeprefix("jdbc:postgresql://")
    assert re.fullmatch(rule["regexes"][0], endpoint)
    assert not re.fullmatch(rule["regexes"][0], endpoint + "-unapproved")


@pytest.mark.parametrize("language", ["ru", "en"])
@pytest.mark.parametrize("missing_cli", [False, True])
def test_installer_docker_absence_is_localized_without_secrets(
    tmp_path, monkeypatch, capsys, language, missing_cli
):
    monkeypatch.setattr(setup, "ROOT", tmp_path)
    monkeypatch.setattr(setup.sys, "platform", "linux")
    monkeypatch.setattr(
        setup.shutil, "which", lambda tool: None if missing_cli and tool == "docker" else "/usr/bin/" + tool
    )

    def failed(command, **kwargs):
        raise setup.SetupError("command")

    monkeypatch.setattr(setup, "run", failed)
    with pytest.raises(setup.SetupError) as error:
        setup.check_system()
    assert error.value.key == "requirements"
    assert "Docker" in setup.message(error.value.key, language)
    assert "пароль" not in capsys.readouterr().err
