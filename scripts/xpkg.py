"""Offline XPKG authoring. Outputs JSON reports, never private keys or archive contents."""

import argparse
import base64
import json
import os
import stat
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from app.domains.packages.archive import MANIFEST, SIGNATURE, Limits, digest_stream, verify
from app.domains.packages.codec import PackageError, canonical, fingerprint, load_json, sign
from app.domains.packages.reports import diff
from app.domains.packages.schema import Manifest, TrustKey, TrustStore, safe_path


def read_file(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise PackageError("input_not_regular")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise PackageError("input_size_limit")
    return data


def exclusive(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def keygen(private_path: Path, public_path: Path) -> dict[str, Any]:
    if private_path.exists() or public_path.exists() or private_path == public_path:
        raise PackageError("key_output_exists")
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    exclusive(private_path, private, 0o600)
    exclusive(public_path, (public + "\n").encode(), 0o644)
    return {"algorithm": "Ed25519", "public_key": public, "fingerprint": fingerprint(public)}


def load_key(path: Path) -> Ed25519PrivateKey:
    if stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) & 0o077:
        raise PackageError("private_key_permissions")
    key = serialization.load_pem_private_key(read_file(path, 8192), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise PackageError("private_key_algorithm")
    return key


def info(name: str) -> zipfile.ZipInfo:
    entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    entry.create_system, entry.external_attr = 3, (stat.S_IFREG | 0o644) << 16
    # STORED is reproducible across zlib versions and cannot produce a compression bomb.
    entry.compress_type = zipfile.ZIP_STORED
    return entry


def source_file(root: Path, path: Path) -> BinaryIO:
    """Open relative to pinned directory descriptors; no symlinked ancestors or hard links."""
    parts = path.relative_to(root).parts
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            os.close(descriptor)
            raise PackageError("source_non_regular_or_hardlink")
        return os.fdopen(descriptor, "rb")
    finally:
        os.close(parent)


def pack(
    source: Path, manifest_path: Path, key_path: Path, publisher: str, key_id: str, output: Path
) -> dict[str, Any]:
    if source.is_symlink() or not source.is_dir():
        raise PackageError("source_directory_required")
    root = source.resolve()
    if root == output.resolve() or root in output.resolve().parents or root in key_path.resolve().parents:
        raise PackageError("output_or_signing_key_inside_payload")
    data = load_json(read_file(manifest_path, 256 * 1024))
    paths: list[tuple[str, Path]] = []
    inventory = []
    for count, path in enumerate(root.rglob("*"), 1):
        if count > 2048:
            raise PackageError("source_entry_limit")
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise PackageError("source_non_regular")
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        safe_path(relative)
        lower = path.name.lower()
        if (
            lower.startswith(".env")
            or lower.endswith((".pem", ".key", ".p12", ".pfx"))
            or lower in {"id_rsa", "id_ed25519", "credentials", "secrets.json"}
        ):
            raise PackageError("possible_secret_in_payload")
        with source_file(root, path) as stream:
            digest, size = digest_stream(stream, Limits().file)
        inventory.append({"path": "payload/" + relative, "size": size, "sha256": digest})
        paths.append(("payload/" + relative, path))
        if len(paths) > 1022:
            raise PackageError("file_count_limit")
    paths.sort(key=lambda item: item[0])
    data["artifacts"] = sorted(inventory, key=lambda item: str(item["path"]))
    manifest = Manifest.model_validate(data)
    if manifest.publisher.id != publisher:
        raise PackageError("publisher_mismatch")
    key = load_key(key_path)
    envelope = sign(data, key, publisher, key_id)
    trust = TrustStore(
        schema_version=1,
        keys=[
            TrustKey(
                publisher_id=publisher,
                key_id=key_id,
                public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
                namespaces=[manifest.permissions.namespace],
            )
        ],
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".xpkg-", dir=output.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w+b") as stream:
            with zipfile.ZipFile(stream, "w", allowZip64=False) as archive:
                archive.writestr(info(MANIFEST), canonical(data))
                archive.writestr(info(SIGNATURE), canonical(envelope.model_dump()))
                for name, path in paths:
                    # Bounded stream; verify catches source changes between inventory and ZIP writing.
                    with archive.open(info(name), "w") as target, source_file(root, path) as input_file:
                        while chunk := input_file.read(64 * 1024):
                            target.write(chunk)
                            if stream.tell() > Limits().package:
                                raise PackageError("package_size_limit")
            stream.flush()
            os.fsync(stream.fileno())
        result = verify(temporary, trust)
        os.link(temporary, output)  # NO overwrite, including parallel publishers.
        return result.report()
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Xarionix offline package tools (no installation)")
    commands = parser.add_subparsers(dest="command", required=True)
    key = commands.add_parser("keygen")
    key.add_argument("--private-key", type=Path, required=True)
    key.add_argument("--public-key", type=Path, required=True)
    for name in ("pack", "sign"):
        command = commands.add_parser(
            name, help="Build/re-sign a prepared distribution, never modify an existing package"
        )
        for flag in ("source", "manifest", "signing-key", "output"):
            command.add_argument("--" + flag, type=Path, required=True)
        for flag in ("publisher", "key-id"):
            command.add_argument("--" + flag, required=True)
    command = commands.add_parser("verify")
    command.add_argument("--package", type=Path, required=True)
    command.add_argument("--trust-store", type=Path, required=True)
    command.add_argument(
        "--limits", type=Path, help="Optional bounded JSON policy; values can only lower V1 hard caps"
    )
    command = commands.add_parser("diff")
    command.add_argument("--previous", type=Path, required=True)
    command.add_argument("--current", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        match arguments.command:
            case "keygen":
                result = keygen(arguments.private_key, arguments.public_key)
            case "pack" | "sign":
                result = pack(
                    arguments.source,
                    arguments.manifest,
                    arguments.signing_key,
                    arguments.publisher,
                    arguments.key_id,
                    arguments.output,
                )
            case "verify":
                trust = TrustStore.model_validate(
                    load_json(read_file(arguments.trust_store, 512 * 1024), 512 * 1024)
                )
                limits = (
                    Limits(**load_json(read_file(arguments.limits, 4096), 4096))
                    if arguments.limits
                    else Limits()
                )
                result = verify(arguments.package, trust, limits).report()
            case _:
                result = diff(
                    Manifest.model_validate(load_json(read_file(arguments.previous, 256 * 1024))),
                    Manifest.model_validate(load_json(read_file(arguments.current, 256 * 1024))),
                )
        print(json.dumps({"ok": True, **result}, ensure_ascii=True, sort_keys=True))
        return 0
    except PackageError as error:
        print(json.dumps({"ok": False, "code": str(error)}), file=sys.stderr)
    except (OSError, ValueError, ValidationError, TypeError):
        print('{"ok":false,"code":"input_or_configuration_invalid"}', file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
