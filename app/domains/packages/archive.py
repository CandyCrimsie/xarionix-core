"""Bounded ZIP reader. Never extracts, imports, executes or fetches archive contents."""

import hashlib
import os
import stat
import struct
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from pydantic import ValidationError

from app.core.config import Settings
from app.domains.packages.codec import PackageError, canonical, fingerprint, load_json, verify_signature
from app.domains.packages.schema import Envelope, Manifest, TrustStore, safe_path
from app.domains.packages.semver import Range
from app.version import VERSION

CHUNK = 64 * 1024
MANIFEST = "manifest.json"
SIGNATURE = "signatures/publisher.json"


@dataclass(frozen=True)
class Limits:
    package: int = 128 * 1024 * 1024
    total: int = 256 * 1024 * 1024
    file: int = 32 * 1024 * 1024
    files: int = 1024
    ratio: int = 100
    path_depth: int = 12
    path_bytes: int = 240
    manifest: int = 256 * 1024
    envelope: int = 4096

    def __post_init__(self) -> None:
        for value, maximum in (
            (self.package, 128 * 1024 * 1024),
            (self.total, 256 * 1024 * 1024),
            (self.file, 32 * 1024 * 1024),
            (self.files, 1024),
            (self.ratio, 100),
            (self.path_depth, 12),
            (self.path_bytes, 240),
            (self.manifest, 256 * 1024),
            (self.envelope, 4096),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
                raise ValueError("invalid_package_limits")

    @classmethod
    def configured(cls, settings: Settings) -> "Limits":
        return cls(
            package=settings.packages_max_bytes,
            total=settings.packages_max_total_bytes,
            file=settings.packages_max_file_bytes,
            files=settings.packages_max_files,
            ratio=settings.packages_max_ratio,
            path_depth=settings.packages_max_path_depth,
            path_bytes=settings.packages_max_path_bytes,
            manifest=settings.packages_max_manifest_bytes,
            envelope=settings.packages_max_signature_bytes,
        )


@dataclass(frozen=True)
class Verified:
    manifest: Manifest
    manifest_data: dict[str, Any]
    envelope: Envelope
    package_sha256: str
    manifest_sha256: str
    size: int
    key_fingerprint: str
    core_compatible: bool
    api_contract: dict[str, Any] | None = None
    sdk_contract: dict[str, Any] | None = None

    def report(self) -> dict[str, Any]:
        return {
            "module_id": self.manifest.module.id,
            "version": self.manifest.module.version,
            "publisher_id": self.envelope.publisher_id,
            "key_id": self.envelope.key_id,
            "key_fingerprint": self.key_fingerprint,
            "package_sha256": self.package_sha256,
            "manifest_sha256": self.manifest_sha256,
            "size": self.size,
            "structural_validity": True,
            "cryptographic_validity": True,
            "current_trust": True,
            "core_compatible": self.core_compatible,
            "namespaces": [self.manifest.permissions.namespace],
            "permissions": [p.key for p in self.manifest.permissions.definitions],
            "dependencies": [p.model_dump() for p in self.manifest.dependencies],
            "deployment_ready": False,
            "execution_supported": False,
        }


class Reader(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


def digest_stream(stream: Reader, limit: int) -> tuple[str, int]:
    digest, count = hashlib.sha256(), 0
    while data := stream.read(CHUNK):
        count += len(data)
        if count > limit:
            raise PackageError("package_size_limit")
        digest.update(data)
    return digest.hexdigest(), count


def zip_layout(stream: BinaryIO, size: int, limits: Limits) -> None:
    """Reject ZIP64, SFX, descriptors, holes, overlaps and central/local ambiguities BEFORE ZipFile allocation."""
    if size < 22:
        raise PackageError("zip_layout_invalid")
    stream.seek(size - 22)
    end = struct.unpack("<4s4H2IH", stream.read(22))
    if (
        end[0] != b"PK\x05\x06"
        or any(end[i] for i in (1, 2, 7))
        or end[3] != end[4]
        or not 2 <= end[4] <= limits.files
        or end[5] > 2 * 1024 * 1024
        or end[5] + end[6] != size - 22
    ):
        raise PackageError("zip_directory_invalid")
    stream.seek(end[6])
    directory = stream.read(end[5])
    cursor, expected_local, uncompressed = 0, 0, 0
    names: set[str] = set()
    for _ in range(end[4]):
        if cursor + 46 > len(directory):
            raise PackageError("zip_directory_invalid")
        c = struct.unpack_from("<4s6H3I5H2I", directory, cursor)
        if (
            c[0] != b"PK\x01\x02"
            or c[2] > 20
            or c[3] not in {0, 2048}
            or c[4] not in {0, 8}
            or c[11]
            or c[12]
            or c[13]
            or not 1 <= c[10] <= limits.path_bytes
            or c[16] != expected_local
        ):
            raise PackageError("zip_entry_unsupported")
        mode = c[15] >> 16
        if stat.S_IFMT(mode) not in {0, stat.S_IFREG} or c[15] & 0x10:
            raise PackageError("zip_non_regular_file")
        name_bytes = directory[cursor + 46 : cursor + 46 + c[10]]
        try:
            name = safe_path(name_bytes.decode("ascii"))
            if len(name.split("/")) > limits.path_depth:
                raise ValueError("path_depth_limit")
        except (UnicodeError, ValueError):
            raise PackageError("zip_path_invalid") from None
        if name.casefold() in names:
            raise PackageError("zip_duplicate_path")
        names.add(name.casefold())
        uncompressed += c[9]
        if (
            c[9] > limits.file
            or uncompressed > limits.total
            or c[9] > max(c[8], 1) * limits.ratio
            or (c[4] == 0 and c[8] != c[9])
        ):
            raise PackageError("zip_expansion_limit")
        stream.seek(c[16])
        header = stream.read(30)
        if len(header) != 30:
            raise PackageError("zip_local_invalid")
        local = struct.unpack("<4s5H3I2H", header)
        if (
            local[0] != b"PK\x03\x04"
            or local[1:9] != c[2:10]
            or local[9] != c[10]
            or local[10]
            or stream.read(local[9]) != name_bytes
        ):
            raise PackageError("zip_local_mismatch")
        expected_local = c[16] + 30 + c[10] + c[8]
        if expected_local > end[6]:
            raise PackageError("zip_overlap")
        cursor += 46 + c[10]
    if cursor != len(directory) or expected_local != end[6]:
        raise PackageError("zip_hidden_data")


def member_chunks(archive: zipfile.ZipFile, name: str) -> Iterator[bytes]:
    """Require the WHOLE compressed stream to belong to one member, including DEFLATE EOF."""
    entry = archive.getinfo(name)
    stream = archive.fp
    if stream is None:
        raise PackageError("zip_closed")
    stream.seek(entry.header_offset + 30 + len(name.encode("ascii")))
    remaining, count, crc = entry.compress_size, 0, 0
    decoder = zlib.decompressobj(-15) if entry.compress_type == zipfile.ZIP_DEFLATED else None
    while remaining:
        pending = stream.read(min(CHUNK, remaining))
        if not pending:
            raise PackageError("zip_member_truncated")
        remaining -= len(pending)
        while pending:
            data = decoder.decompress(pending, CHUNK) if decoder else pending
            pending = decoder.unconsumed_tail if decoder else b""
            if decoder and decoder.unused_data:
                raise PackageError("zip_unused_compressed_data")
            count += len(data)
            if count > entry.file_size:
                raise PackageError("artifact_size_mismatch")
            crc = zlib.crc32(data, crc)
            yield data
    if (decoder and not decoder.eof) or count != entry.file_size or crc != entry.CRC:
        raise PackageError("zip_member_integrity_invalid")


def read_member(archive: zipfile.ZipFile, name: str, limit: int) -> bytes:
    if archive.getinfo(name).file_size > limit:
        raise PackageError("metadata_size_limit")
    value = b"".join(member_chunks(archive, name))
    if len(value) > limit:
        raise PackageError("metadata_size_limit")
    return value


def verify(path: Path, trust: TrustStore, limits: Limits = Limits()) -> Verified:
    try:
        # O_NOFOLLOW rejects an operator-provided symlink, even on CLI; HTTP never supplies a path.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limits.package:
                raise PackageError("package_size_or_type_invalid")
            package_digest, size = digest_stream(stream, limits.package)
            zip_layout(stream, size, limits)
            stream.seek(0)
            with zipfile.ZipFile(stream) as archive:
                raw = read_member(archive, MANIFEST, limits.manifest)
                data = load_json(raw, limits.manifest)
                if raw != canonical(data):
                    raise PackageError("manifest_not_canonical")
                manifest = Manifest.model_validate(data)
                envelope = Envelope.model_validate(
                    load_json(read_member(archive, SIGNATURE, limits.envelope), limits.envelope)
                )
                if envelope.publisher_id != manifest.publisher.id:
                    raise PackageError("publisher_mismatch")
                key = next(
                    (
                        item
                        for item in trust.keys
                        if (item.publisher_id, item.key_id) == (envelope.publisher_id, envelope.key_id)
                    ),
                    None,
                )
                if key is None:
                    raise PackageError("signing_key_unknown")
                if key.status != "active" or key.publisher_status != "active":
                    raise PackageError("signing_trust_revoked")
                if manifest.permissions.namespace not in key.namespaces:
                    raise PackageError("publisher_namespace_denied")
                verify_signature(data, envelope, key.public_key)
                expected = {MANIFEST, SIGNATURE, *(item.path for item in manifest.artifacts)}
                if set(archive.namelist()) != expected:
                    raise PackageError("inventory_mismatch")
                total = 0
                for artifact in manifest.artifacts:
                    if archive.getinfo(artifact.path).file_size != artifact.size:
                        raise PackageError("artifact_size_mismatch")
                    checksum, count = hashlib.sha256(), 0
                    for chunk in member_chunks(archive, artifact.path):
                        count += len(chunk)
                        if count > min(limits.file, artifact.size):
                            raise PackageError("artifact_size_mismatch")
                        checksum.update(chunk)
                    digest = checksum.hexdigest()
                    total += count
                    if count != artifact.size or digest != artifact.sha256:
                        raise PackageError("artifact_integrity_mismatch")
                    if total > limits.total:
                        raise PackageError("zip_expansion_limit")
            from app.domains.module_gateway.contracts import read_contract
            from app.domains.module_sdk.contracts import read_sdk_contract

            api = read_contract(path, manifest)
            sdk = read_sdk_contract(path, manifest, api)
            return Verified(
                manifest,
                data,
                envelope,
                package_digest,
                hashlib.sha256(raw).hexdigest(),
                size,
                fingerprint(key.public_key),
                Range.parse(manifest.compatibility.core).contains(VERSION),
                api.model_dump() if api else None,
                sdk.document() if sdk else None,
            )
    except (
        OSError,
        KeyError,
        zipfile.BadZipFile,
        NotImplementedError,
        RuntimeError,
        ValidationError,
        struct.error,
        zlib.error,
    ):
        raise PackageError("package_structure_invalid") from None
