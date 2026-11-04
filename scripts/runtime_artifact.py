"""Offline authoring from a local Docker-save archive, not an HTTP/Core execution path."""

import argparse
import gzip
import hashlib
import json
import os
import tarfile
from pathlib import Path
from typing import IO, Any

from app.domains.deployments.artifacts import OCI_CONFIG, OCI_LAYER, OCI_MANIFEST, PREFIX, RUNTIME
from app.domains.packages.archive import CHUNK, Limits
from app.domains.packages.codec import PackageError, canonical
from app.domains.packages.schema import safe_path


def convert(source: Path, output: Path) -> dict[str, Any]:
    """No extraction, registry access or layer execution; output must be a NEW private directory."""
    output.mkdir(mode=0o700)
    oci = output / PREFIX
    blobs = oci / "blobs/sha256"
    blobs.mkdir(mode=0o700, parents=True)
    with source.open("rb") as stream, tarfile.open(fileobj=stream, mode="r:") as archive:
        # Docker-save producer is trusted local tooling, but reject ambiguous/path-bearing entries.
        entries = {}
        for count, entry in enumerate(archive, 1):
            if count > 2048 or entry.name in entries:
                raise PackageError("oci_export_inventory_invalid")
            safe_path(entry.name.rstrip("/"))
            if not entry.isdir() and not entry.isfile():
                raise PackageError("oci_export_entry_invalid")
            entries[entry.name] = entry

        def reader(name: str) -> IO[bytes]:
            entry = entries.get(name)
            if entry is None or not entry.isfile() or entry.size > Limits().total:
                raise PackageError("oci_export_reference_invalid")
            opened = archive.extractfile(entry)
            if opened is None:
                raise PackageError("oci_export_reference_invalid")
            return opened

        with reader("manifest.json") as data:
            inventory = json.loads(data.read(65537))
        if (
            not isinstance(inventory, list)
            or len(inventory) != 1
            or not isinstance(inventory[0].get("Layers"), list)
            or not 1 <= len(inventory[0]["Layers"]) <= 64
        ):
            raise PackageError("oci_export_single_image_required")

        def publish(data: bytes) -> dict[str, Any]:
            sha = hashlib.sha256(data).hexdigest()
            path = blobs / sha
            if not path.exists():
                with path.open("xb") as target:
                    target.write(data)
            return {"digest": "sha256:" + sha, "size": len(data)}

        with reader(inventory[0]["Config"]) as data:
            raw = data.read(262145)
        if len(raw) > 262144:
            raise PackageError("oci_export_config_limit")
        config = json.loads(raw)
        platform = config.get("os", "") + "/" + config.get("architecture", "")
        if platform not in {"linux/amd64", "linux/arm64"}:
            raise PackageError("oci_export_platform_invalid")
        config_ref = publish(raw) | {"mediaType": OCI_CONFIG}
        layers, total = [], 0
        for index, name in enumerate(inventory[0]["Layers"]):
            temporary = output / f"layer-{index}.gzip"
            with reader(name) as data:
                already_gzip = data.read(2) == b"\x1f\x8b"
            diff = hashlib.sha256()
            with (
                reader(name) as data,
                temporary.open("xb") as target,
                gzip.GzipFile(fileobj=target, mode="wb", filename="", mtime=0) as compressed,
            ):
                decoded = gzip.GzipFile(fileobj=data) if already_gzip else data
                try:
                    while chunk := decoded.read(CHUNK):
                        total += len(chunk)
                        if total > Limits().total:
                            raise PackageError("oci_export_expansion_limit")
                        diff.update(chunk)
                        compressed.write(chunk)
                finally:
                    if decoded is not data:
                        decoded.close()
            if "sha256:" + diff.hexdigest() != config["rootfs"]["diff_ids"][index]:
                raise PackageError("oci_export_diff_id_mismatch")
            if temporary.stat().st_size > Limits().file:
                raise PackageError("oci_export_blob_limit")
            sha = hashlib.sha256()
            with temporary.open("rb") as data:
                while chunk := data.read(CHUNK):
                    sha.update(chunk)
            path = blobs / sha.hexdigest()
            size = temporary.stat().st_size
            os.rename(temporary, path)
            layers.append(
                {"mediaType": OCI_LAYER + "+gzip", "digest": "sha256:" + sha.hexdigest(), "size": size}
            )
        image = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": config_ref, "layers": layers}
        manifest_ref = publish(canonical(image)) | {
            "mediaType": OCI_MANIFEST,
            "platform": {"os": "linux", "architecture": platform.split("/")[1]},
        }
        documents: dict[Path, dict[str, Any]] = {
            oci / "oci-layout": {"imageLayoutVersion": "1.0.0"},
            oci / "index.json": {"schemaVersion": 2, "manifests": [manifest_ref]},
            output / RUNTIME: {
                "schema_version": 1,
                "engine": "oci",
                "platform": platform,
                "image_digest": manifest_ref["digest"],
                "config_digest": config_ref["digest"],
                "health_contract": "http-python-v1",
                "health_port": 8080,
            },
        }
        for path, value in documents.items():
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open("xb") as target:
                target.write(canonical(value))
    return documents[output / RUNTIME]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert a local single-image Docker-save tar to bounded XPKG OCI payload"
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    try:
        print(json.dumps(convert(arguments.source, arguments.output), sort_keys=True))
    except (OSError, ValueError, KeyError, tarfile.TarError):
        raise SystemExit(
            "Runtime artifact conversion failed; inspect limits and the source archive"
        ) from None


if __name__ == "__main__":
    main()
