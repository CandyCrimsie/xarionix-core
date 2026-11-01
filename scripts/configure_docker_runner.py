"""Explicit, idempotent operator action: allow ONLY pinned rootless DinD services.

Standalone stdlib script, safe to copy to the Runner VM. Never prints TOML/auth
tokens. Defaults to check-only; --apply makes a private backup and atomic update.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import tempfile
import time
import tomllib
from pathlib import Path

ROOTLESS_IMAGE = (
    "docker:29.9.2-dind-rootless@sha256:ae083cc7de51e7a8e5a597f8fb774ca7914c408a95fc0f1477826a913479518a"
)
ALLOWED_IMAGES = [ROOTLESS_IMAGE, "docker.io/library/" + ROOTLESS_IMAGE]


def patch_config(text: str, runner_name: str | None = None) -> str:
    before = tomllib.loads(text)
    runners = before.get("runners", [])
    candidates = [
        i for i, runner in enumerate(runners) if runner_name is None or runner.get("name") == runner_name
    ]
    if len(candidates) != 1:
        raise ValueError("Select exactly one runner with --runner-name; no configuration changed")
    index = candidates[0]
    runner = runners[index]
    docker = runner.get("docker", {})
    if runner.get("executor") != "docker" or docker.get("privileged", False):
        raise ValueError("Requires an existing Docker executor with privileged=false")
    if docker.get("allowed_privileged_services") not in (None, [], ALLOWED_IMAGES):
        raise ValueError(
            "Existing privileged-service allowlist requires manual review; no configuration changed"
        )
    volumes = docker.get("volumes", [])
    if any("docker.sock" in volume for volume in volumes):
        raise ValueError("Refusing a runner that exposes a host Docker socket to jobs")
    updates = {
        "privileged": False,
        "services_privileged": True,
        "allowed_privileged_services": ALLOWED_IMAGES,
        "volumes": volumes if "/certs/client" in volumes else [*volumes, "/certs/client"],
    }
    if all(docker.get(key) == value for key, value in updates.items()):
        return text
    lines = text.splitlines(keepends=True)
    blocks = [i for i, line in enumerate(lines) if re.fullmatch(r"\s*\[\[runners\]\]\s*\n?", line)]
    if len(blocks) != len(runners):
        raise ValueError("Unsupported TOML layout; no configuration changed")
    start = blocks[index]
    end = blocks[index + 1] if index + 1 < len(blocks) else len(lines)
    headers = [i for i in range(start, end) if re.fullmatch(r"\s*\[runners\.docker\]\s*\n?", lines[i])]
    if len(headers) != 1:
        raise ValueError("Docker section missing/ambiguous; no configuration changed")
    start = headers[0] + 1
    end = next((i for i in range(start, end) if lines[i].lstrip().startswith("[")), end)
    section = lines[start:end]
    # Parse just the affected assignment, including multiline arrays. Preserve all other text/tokens.
    for key in updates:
        positions = [i for i, line in enumerate(section) if re.match(r"\s*" + key + r"\s*=", line)]
        if len(positions) > 1:
            raise ValueError("Duplicate assignment; no configuration changed")
        if positions:
            first = positions[0]
            for last in range(first + 1, len(section) + 1):
                try:
                    parsed = tomllib.loads("".join(section[first:last]))
                except tomllib.TOMLDecodeError:
                    continue
                if set(parsed) == {key} and parsed[key] == docker.get(key):
                    section[first:last] = []
                    break
            else:
                raise ValueError("Unsupported assignment layout; no configuration changed")
    section = [f"  {key} = {json.dumps(value)}\n" for key, value in updates.items()] + section
    result = "".join(lines[:start] + section + lines[end:])
    expected = copy.deepcopy(before)
    expected["runners"][index].setdefault("docker", {}).update(updates)
    if tomllib.loads(result) != expected:
        raise ValueError("Unexpected configuration difference; no configuration changed")
    return result


def configure(path: Path, *, apply: bool, runner_name: str | None = None) -> bool:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Requires a regular existing runner config file")
    original = path.read_text()
    replacement = patch_config(original, runner_name)
    if replacement == original:
        print("Runner already configured: jobs unprivileged, only pinned rootless DinD services privileged")
        return False
    if not apply:
        print(
            "Check passed. --apply will back up config (0600) and change only rootless-service/TLS-volume settings"
        )
        return False
    stat = path.stat()
    backup = path.with_name(path.name + ".backup." + str(time.time_ns()))
    # Backup is explicit and private; no original TOML is ever printed or uploaded as an artifact.
    with backup.open("xb") as stream:
        os.chmod(backup, 0o600)
        stream.write(original.encode())
    descriptor, temporary = tempfile.mkstemp(prefix=".runner-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        if os.geteuid() == 0:
            os.fchown(descriptor, stat.st_uid, stat.st_gid)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink() or path.read_text() != original:
            raise ValueError("Runner configuration changed concurrently; refusing to overwrite it")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    print("Runner config updated atomically; private backup retained. No runner restart requested.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=Path, default=Path("/etc/gitlab-runner/config.toml"))
    parser.add_argument("--runner-name")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        configure(args.path, apply=args.apply, runner_name=args.runner_name)
    except (OSError, ValueError):
        # TOML parser exceptions can include source text; never reproduce config/token fragments.
        raise SystemExit(
            "Runner configuration check/update failed; no secrets printed. Inspect configuration locally."
        ) from None


if __name__ == "__main__":
    main()
