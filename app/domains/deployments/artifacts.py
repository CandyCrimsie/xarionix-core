"""XPKG V1 OCI profile: bounded offline blobs, no extraction or registry URLs."""

import gzip
import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import Field

from app.domains.packages.archive import CHUNK, Limits, read_member
from app.domains.packages.codec import PackageError, load_json, pairs
from app.domains.packages.schema import Manifest, Strict

RUNTIME = "payload/resources/runtime-v1.json"
PREFIX = "payload/backend/oci/"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar"
SHA = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class RuntimeContract(Strict):
    schema_version: Literal[1]
    engine: Literal["oci"]
    platform: Literal["linux/amd64", "linux/arm64"]
    image_digest: SHA
    config_digest: SHA
    health_contract: Literal["http-python-v1"]
    health_port: Literal[8080]


def descriptor(value: Any, media: str) -> tuple[str, int]:
    if (
        not isinstance(value, dict)
        or set(value) - {"mediaType", "digest", "size", "platform", "annotations"}
        or value.get("mediaType") != media
        or not isinstance(value.get("digest"), str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"])
        or type(value.get("size")) is not int
        or not 0 < value["size"] <= Limits().file
    ):
        raise PackageError("oci_descriptor_invalid")
    return value["digest"], value["size"]


def blob_path(digest: str) -> str:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise PackageError("oci_digest_invalid")
    return PREFIX + "blobs/sha256/" + digest[7:]


def oci_json(raw: bytes) -> dict[str, Any]:
    """OCI config permits escaped newlines (e.g. image history); XPKG canonical JSON stays unchanged."""
    if len(raw) > 262144:
        raise PackageError("oci_json_limit")
    value = json.loads(raw, object_pairs_hook=pairs)

    def bounded(node: Any, depth: int = 0) -> None:
        if depth > 16:
            raise PackageError("oci_json_depth")
        if isinstance(node, dict):
            if len(node) > 1024:
                raise PackageError("oci_json_collection")
            for key, item in node.items():
                bounded(key, depth + 1)
                bounded(item, depth + 1)
        elif isinstance(node, list):
            if len(node) > 2048:
                raise PackageError("oci_json_collection")
            for item in node:
                bounded(item, depth + 1)
        elif isinstance(node, str):
            if len(node) > 65536:
                raise PackageError("oci_json_string")
        elif node is not None and not isinstance(node, (bool, int)):
            raise PackageError("oci_json_type")

    bounded(value)
    if not isinstance(value, dict):
        raise PackageError("oci_json_object_required")
    return value


def validate_runtime(path: Path, manifest: Manifest) -> RuntimeContract:
    try:
        return _validate_runtime(path, manifest)
    except PackageError:
        raise
    except (
        ValueError,
        KeyError,
        AttributeError,
        TypeError,
        OSError,
        EOFError,
        RecursionError,
        zipfile.BadZipFile,
        tarfile.TarError,
    ):
        raise PackageError("oci_structure_invalid") from None


def _validate_runtime(path: Path, manifest: Manifest) -> RuntimeContract:
    """Caller first verifies the XPKG signature and full inventory with the existing V1 verifier."""
    if manifest.module.type != "standard":
        raise PackageError("oci_standard_module_required")
    inventory = {a.path: a for a in manifest.artifacts}
    if RUNTIME not in inventory:
        raise PackageError("oci_runtime_contract_missing")
    with zipfile.ZipFile(path) as archive:
        contract = RuntimeContract.model_validate(load_json(read_member(archive, RUNTIME, 8192), 8192))
        layout = load_json(read_member(archive, PREFIX + "oci-layout", 4096), 4096)
        index = load_json(read_member(archive, PREFIX + "index.json", 65536), 65536)
        if (
            layout != {"imageLayoutVersion": "1.0.0"}
            or index.get("schemaVersion") != 2
            or set(index) - {"schemaVersion", "mediaType", "manifests"}
            or not isinstance(index.get("manifests"), list)
            or len(index["manifests"]) != 1
        ):
            raise PackageError("oci_layout_invalid")
        root_digest, root_size = descriptor(index["manifests"][0], OCI_MANIFEST)
        platform = index["manifests"][0].get("platform", {})
        if root_digest != contract.image_digest or platform != {
            "os": "linux",
            "architecture": contract.platform.split("/")[1],
        }:
            raise PackageError("oci_platform_or_manifest_mismatch")

        def json_blob(digest: str, size: int) -> dict[str, Any]:
            name = blob_path(digest)
            artifact = inventory.get(name)
            if artifact is None or artifact.sha256 != digest[7:] or artifact.size != size:
                raise PackageError("oci_inventory_mismatch")
            raw = read_member(archive, name, 262144)
            if hashlib.sha256(raw).hexdigest() != digest[7:]:
                raise PackageError("oci_blob_corrupt")
            return oci_json(raw)

        image = json_blob(root_digest, root_size)
        if (
            image.get("schemaVersion") != 2
            or image.get("mediaType") != OCI_MANIFEST
            or set(image) - {"schemaVersion", "mediaType", "config", "layers", "annotations"}
            or not isinstance(image.get("layers"), list)
            or not 1 <= len(image["layers"]) <= 64
        ):
            raise PackageError("oci_manifest_invalid")
        config_digest, config_size = descriptor(image.get("config"), OCI_CONFIG)
        config = json_blob(config_digest, config_size)
        if (
            config_digest != contract.config_digest
            or config.get("os") != "linux"
            or config.get("architecture") != contract.platform.split("/")[1]
            or config.get("rootfs", {}).get("type") != "layers"
            or len(config.get("rootfs", {}).get("diff_ids", [])) != len(image["layers"])
            or config.get("config", {}).get("Volumes")
            or config.get("config", {}).get("OnBuild")
        ):
            raise PackageError("oci_config_invalid")
        expected = {
            RUNTIME,
            PREFIX + "oci-layout",
            PREFIX + "index.json",
            blob_path(root_digest),
            blob_path(config_digest),
        }
        expanded = 0
        logical = 0
        for layer, diff_id in zip(image["layers"], config["rootfs"]["diff_ids"], strict=True):
            media = layer.get("mediaType") if isinstance(layer, dict) else None
            if media not in {OCI_LAYER, OCI_LAYER + "+gzip"}:
                raise PackageError("oci_layer_type_invalid")
            digest, size = descriptor(layer, media)
            name = blob_path(digest)
            artifact = inventory.get(name)
            if name in expected or artifact is None or artifact.sha256 != digest[7:] or artifact.size != size:
                raise PackageError("oci_layer_inventory_invalid")
            expected.add(name)
            compressed = hashlib.sha256()
            with archive.open(name) as stream:
                while chunk := stream.read(CHUNK):
                    compressed.update(chunk)
            if compressed.hexdigest() != digest[7:]:
                raise PackageError("oci_blob_corrupt")
            actual = hashlib.sha256()
            with archive.open(name) as stream:
                decoded = gzip.GzipFile(fileobj=stream) if media.endswith("+gzip") else stream
                try:
                    while chunk := decoded.read(CHUNK):
                        expanded += len(chunk)
                        if expanded > Limits().total:
                            raise PackageError("oci_expansion_limit")
                        actual.update(chunk)
                finally:
                    if decoded is not stream:
                        decoded.close()
            if "sha256:" + actual.hexdigest() != diff_id:
                raise PackageError("oci_diff_id_mismatch")
            with archive.open(name) as stream:
                decoded = gzip.GzipFile(fileobj=stream) if media.endswith("+gzip") else stream
                try:
                    logical += layer_structure(decoded)
                    if logical > Limits().total:
                        raise PackageError("oci_logical_expansion_limit")
                finally:
                    if decoded is not stream:
                        decoded.close()
        from app.domains.module_gateway.contracts import API_RESOURCE, read_contract
        from app.domains.module_sdk.contracts import SDK_RESOURCE, read_sdk_contract

        api = read_contract(path, manifest)
        if api is not None:
            expected.add(API_RESOURCE)
        if read_sdk_contract(path, manifest, api) is not None:
            expected.add(SDK_RESOURCE)
        if set(inventory) != expected:
            raise PackageError("oci_unexpected_artifact")
    return contract


def layer_structure(stream: Any) -> int:
    """Inspect tar headers without extraction; sparse/huge logical files are not bounded by gzip size."""
    total = 0
    with tarfile.open(fileobj=stream, mode="r|") as layer:
        for count, member in enumerate(layer, start=1):
            path = PurePosixPath(member.name)
            if (
                count > 65536
                or len(member.name) > 1024
                or path.is_absolute()
                or ".." in path.parts
                or member.issparse()
                or not (member.isfile() or member.isdir() or member.issym() or member.islnk())
                or member.size < 0
            ):
                raise PackageError("oci_layer_structure_invalid")
            total += member.size
            if total > Limits().total:
                raise PackageError("oci_logical_expansion_limit")
    return total


def write_oci_archive(package: Path, manifest: Manifest, destination: Path) -> RuntimeContract:
    """Repackage verified regular members only. Never unpack ZIP, layers or nested archives."""
    contract = validate_runtime(package, manifest)
    with (
        zipfile.ZipFile(package) as source,
        destination.open("xb") as output,
        tarfile.open(fileobj=output, mode="w|", format=tarfile.USTAR_FORMAT) as target,
    ):
        for artifact in manifest.artifacts:
            if not artifact.path.startswith(PREFIX):
                continue
            entry = tarfile.TarInfo(artifact.path.removeprefix(PREFIX))
            entry.size, entry.mode = artifact.size, 0o644
            with source.open(artifact.path) as stream:
                target.addfile(entry, stream)
        output.flush()
    return contract
