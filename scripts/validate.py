"""Repository checks which require neither production configuration nor Docker daemon."""

from __future__ import annotations

import re

# Git listing and shell syntax checks use fixed argv, never repository-supplied commands.
import subprocess  # nosec B404
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]


class UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        explicit: set[str] = set()
        for key, _ in node.value:
            if key.value != "<<":
                if key.value in explicit:
                    raise ValueError("Duplicate YAML mapping key")
                explicit.add(key.value)
        return super().construct_mapping(node, deep=deep)


def load_yaml(path: Path) -> Any:
    loader = UniqueLoader(path.read_text())
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def tracked_files() -> list[str]:
    result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)  # nosec B603 B607
    return result.stdout.decode().strip("\0").split("\0")


def check() -> None:
    required = [
        "Dockerfile",
        "deploy/ci/Dockerfile",
        "scripts/docker_job.py",
        "compose.yaml",
        "compose.dev.yaml",
        "compose.keycloak.yaml",
        ".gitlab-ci.yml",
        "install.sh",
        "scripts/setup.py",
        "alembic.ini",
        "migrations/versions/0001_identity.py",
        "requirements.lock",
        "requirements-dev.lock",
        "docs/ci-cd.md",
        ".env.example",
    ]
    for filename in required:
        if not (ROOT / filename).is_file():
            raise ValueError(f"Required file missing: {filename}")
    for path in (ROOT / "pyproject.toml", ROOT / "alembic.ini", ROOT / "Dockerfile"):
        if not path.read_text().strip():
            raise ValueError(f"Empty project file: {path.name}")
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    if metadata["name"] != "xarionix-core" or not re.fullmatch(r"\d+\.\d+\.\d+", metadata["version"]):
        raise ValueError("Invalid Python project metadata")
    for filename in ("compose.yaml", "compose.keycloak.yaml", "compose.dev.yaml", ".gitlab-ci.yml"):
        if not isinstance(load_yaml(ROOT / filename), dict):
            raise ValueError(f"Invalid YAML document: {filename}")
    for command in (["bash", "-n", "install.sh"], ["sh", "-n", "deploy/postgres/10-app-user.sh"]):
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True)  # nosec B603
    example = {}
    for line in (ROOT / ".env.example").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"XARIONIX_[A-Z_]+", key) or key in example:
            raise ValueError("Invalid .env.example syntax")
        example[key] = value
        if key.endswith(("PASSWORD", "SECRET", "TOKEN")) and value:
            raise ValueError("Secrets must be empty in .env.example")
    if example.get("XARIONIX_ENVIRONMENT") != "production" or example.get("XARIONIX_DOCS_ENABLED") != "false":
        raise ValueError("Unsafe production example defaults")
    for filename in tracked_files():
        name = Path(filename).name
        if name != ".env.example" and (
            name == ".env"
            or name.startswith(".env.")
            or name.endswith((".env", ".key", ".pem", ".p12", ".pfx", ".dump"))
        ):
            raise ValueError(f"Secret/config data file tracked in Git: {filename}")
        if filename.startswith(("app/", "scripts/")):
            content = (ROOT / filename).read_text()
            if re.search(
                r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|glpat-[A-Za-z0-9_-]{20,}", content
            ):
                raise ValueError(f"Credential pattern found (value redacted): {filename}")
    print("Repository metadata, YAML, shell syntax, example env and tracked secret-file checks: OK")


if __name__ == "__main__":
    check()
