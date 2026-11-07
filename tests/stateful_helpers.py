"""Real SDK-built, signed OCI packages; only disposable local build inputs."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from runtime_helpers import runtime_package

ROOT = Path(__file__).resolve().parents[1]


def stateful_package(folder, *, platform, publisher, version="1.1.0", schema=1, key=None):
    folder.mkdir(parents=True)
    context = folder / "build"
    sdk = context / "sdk/python/src/xarionix_sdk"
    shutil.copytree(
        ROOT / "sdk/python/src/xarionix_sdk", sdk, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )
    app = context / "examples/modules/hello-business-stateful"
    app.mkdir(parents=True)
    for name in ("Dockerfile", "hello.py"):
        shutil.copyfile(ROOT / "examples/modules/hello-business-stateful" / name, app / name)
    manifest = json.loads((ROOT / "examples/modules/hello-business-stateful/manifest.json").read_text())
    manifest["module"]["version"], manifest["publisher"]["id"] = version, publisher
    (app / "manifest.json").write_text(json.dumps(manifest))
    environment = {k: os.environ[k] for k in ("PATH", "LANG") if k in os.environ}
    environment |= {
        "PYTHONPATH": str(ROOT / "sdk/python/src"),
        "HELLO_VERSION": version,
        "HELLO_DATA_SCHEMA": str(schema),
    }
    subprocess.run(
        [
            sys.executable,
            "-m",
            "xarionix_sdk",
            "metadata",
            "hello:module",
            "--manifest",
            "manifest.json",
            "--output",
            ".",
        ],
        cwd=app,
        env=environment,
        capture_output=True,
        check=True,
        timeout=30,
    )
    tag = "xarionix-stateful-test:" + uuid4().hex
    archive = folder / "image.tar"
    try:
        subprocess.run(
            [
                "docker",
                "build",
                "--platform",
                platform,
                "-f",
                str(app / "Dockerfile"),
                "--build-arg",
                "HELLO_VERSION=" + version,
                "--build-arg",
                "HELLO_DATA_SCHEMA=" + str(schema),
                "-t",
                tag,
                str(context),
            ],
            check=True,
            capture_output=True,
            timeout=600,
        )
        subprocess.run(
            ["docker", "save", "--output", str(archive), tag], check=True, capture_output=True, timeout=120
        )
    finally:
        subprocess.run(["docker", "image", "rm", tag], capture_output=True, timeout=30)

    def metadata(distribution):
        for name in ("module-api-v1.json", "module-sdk-v1.json"):
            shutil.copyfile(app / name, distribution / "payload/resources" / name)

    path, trust, report, contract = runtime_package(
        folder / "package",
        source=archive,
        transform=metadata,
        module=manifest["module"]["id"],
        namespace="hello",
        publisher=publisher,
        version=version,
        key=key,
        manifest=manifest,
    )
    return {
        "path": path,
        "trust": trust,
        "report": report,
        "contract": contract,
        "manifest": manifest,
        "namespace": "hello",
    }
