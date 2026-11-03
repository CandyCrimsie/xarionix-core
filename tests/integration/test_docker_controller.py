"""Real controller exit verification, without starting databases or touching dev volumes."""

import os
import subprocess
import uuid

import pytest

from scripts import docker_job
from scripts.ci import preflight

pytestmark = pytest.mark.integration
IMAGE = "docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb"


@pytest.mark.parametrize("exit_code", [0, 23])
@pytest.mark.parametrize("broken_log_stream", [False, True])
def test_real_controller_exit_is_independent_of_log_stream(monkeypatch, exit_code, broken_log_stream):
    if os.environ.get("XARIONIX_RUN_DOCKER_TESTS") != "1":
        if os.environ.get("CI") == "true":
            pytest.fail("CI integration must set XARIONIX_RUN_DOCKER_TESTS=1")
        pytest.skip("Opt-in Docker integration: XARIONIX_RUN_DOCKER_TESTS=1")
    preflight()
    name = "xarionix-controller-test-" + uuid.uuid4().hex
    docker_job.command(
        [
            "docker",
            "create",
            "--name",
            name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            "10001:10001",
            IMAGE,
            "sh",
            "-c",
            f"echo controller-smoke; sleep 0.2; exit {exit_code}",
        ]
    )
    original_command = docker_job.command
    try:
        original_command(["docker", "start", name])
        if broken_log_stream:

            def command(arguments, **kwargs):
                if arguments[1] == "logs":
                    # Disconnect early; real wait/inspect must still observe the process exit.
                    return subprocess.CompletedProcess(arguments, 1)
                return original_command(arguments, **kwargs)

            monkeypatch.setattr(docker_job, "command", command)
        if exit_code:
            with pytest.raises(RuntimeError, match=f"container \\(exit {exit_code}\\)"):
                docker_job.wait_for_controller(name, "smoke", timeout=30)
        else:
            docker_job.wait_for_controller(name, "smoke", timeout=30)
    finally:
        original_command(["docker", "rm", "--force", name], check=False)
