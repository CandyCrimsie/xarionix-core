"""Separate Agent and Hello image smoke/security gates. No module or production credentials."""

import json
import time
import uuid

from scripts import ci
from scripts.compose_check import ROOT, docker


def check(*, scan: bool = True) -> None:
    (ROOT / ".ci-tmp").mkdir(exist_ok=True)
    suffix = uuid.uuid4().hex[:12]
    agent, hello = "xarionix-deployment-agent:test-" + suffix, "xarionix-hello:test-" + suffix
    gateway, business = "xarionix-gateway-agent:test-" + suffix, "xarionix-hello-business:test-" + suffix
    name = "xarionix-runtime-smoke-" + suffix
    try:
        docker(["build", "--target", "deployment-agent", "--tag", agent, "."], timeout=1200)
        docker(["build", "--tag", hello, "examples/modules/hello-runtime"], timeout=600)
        docker(["build", "--target", "gateway-agent", "--tag", gateway, "."], timeout=1200)
        docker(["build", "--tag", business, "examples/modules/hello-business"], timeout=600)
        for image, user in (
            (agent, "1000:1000"),
            (hello, "10001:10001"),
            (gateway, "1000:1000"),
            (business, "10001:10001"),
        ):
            config = json.loads(docker(["image", "inspect", image]).stdout)[0]["Config"]
            if config["User"] != user or config.get("Volumes"):
                raise ValueError("Runtime image user or implicit mounts invalid")
            if any("SECRET=" in value or "PASSWORD=" in value for value in config.get("Env", [])):
                raise ValueError("Unexpected image credential")
        docker(
            [
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--entrypoint",
                "python",
                agent,
                "-I",
                "-c",
                "import os; import scripts.deployment_agent.__main__; import scripts.gateway_agent; assert os.getuid()==1000",
            ]
        )
        # The only writable runtime path is a private container tmpfs, not a host path.
        tmpfs = "/tmp:rw,noexec,nosuid,nodev,size=64m"  # nosec B108
        docker(
            [
                "run",
                "--detach",
                "--name",
                name,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                tmpfs,
                "--memory",
                "256m",
                "--cpus",
                "0.5",
                "--pids-limit",
                "64",
                hello,
            ]
        )
        probe = "import http.client; c=http.client.HTTPConnection('127.0.0.1',8080,timeout=2); c.request('GET','/health/ready'); assert c.getresponse().status==200"
        deadline = time.monotonic() + 30
        while True:
            try:
                docker(["exec", name, "python", "-I", "-c", probe], timeout=5)
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Hello image readiness smoke failed") from None
                time.sleep(0.25)
        if scan:
            ci.trivy(agent, "trivy-agent.json")
            ci.trivy(hello, "trivy-runtime.json")
            ci.trivy(gateway, "trivy-gateway-agent.json")
            ci.trivy(business, "trivy-business-runtime.json")
        print("Separate Deployment Agent and Hello image smoke gates passed (no registry push)")
    finally:
        try:
            docker(["rm", "--force", name])
        except RuntimeError:
            pass
        for image in (agent, hello, gateway, business):
            try:
                docker(["image", "rm", image])
            except RuntimeError:
                pass


if __name__ == "__main__":
    check()
