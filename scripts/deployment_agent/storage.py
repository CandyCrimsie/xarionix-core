"""Owned named volumes and offline SQLite snapshots; no manifest paths or deletion API."""

import hashlib
import io
import json
import os
import sqlite3
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

from xarionix_sdk.configuration import Configuration
from xarionix_sdk.storage import SQLiteStorage, StorageError, initialize, private_directory, private_file

from app.domains.deployments.contracts import BackupMetadata, Delivery, StorageReport
from app.domains.packages.codec import load_json

DATA_PATH = "/data"
OWNER_FILE = ".xarionix-storage.json"
ALLOWED = {OWNER_FILE, ".writer.lock", "data.sqlite3", "data.sqlite3-journal"}


def volume_name(job: Delivery, epoch: UUID) -> str:
    if job.storage is None or epoch not in {job.storage.epoch_id, job.storage.next_epoch_id}:
        raise StorageError("storage_binding_required")
    return f"xarionix-data-v1-{job.host_id.hex}-{job.installation_id.hex}-{epoch.hex}"


def labels(job: Delivery, epoch: UUID) -> dict[str, str]:
    return {
        "io.xarionix.storage.kind": "sqlite-data-v1",
        "io.xarionix.storage.host": str(job.host_id),
        "io.xarionix.storage.installation": str(job.installation_id),
        "io.xarionix.storage.epoch": str(epoch),
        "io.xarionix.storage.engine": job.engine_id,
        "io.xarionix.storage.maximum": "67108864",
    }


def configuration(job: Delivery) -> dict[str, Any]:
    value = job.storage
    if value is None or job.installation_generation is None:
        raise StorageError("storage_configuration_required")
    return {
        "schema_version": 1,
        "installation_id": str(job.installation_id),
        "installation_generation": job.installation_generation,
        "module_id": value.module_id,
        "package_version": value.package_version,
        "public": {"title": "Деловые записи"},
        "approved": {"max_items_per_company": 100},
        "runtime": {
            "storage_max_bytes": value.maximum_bytes,
            "expected_schema_version": value.expected_schema_version,
            "target_schema_version": value.target_schema_version,
            "allow_migration": value.allow_migration,
        },
    }


CONFIG_ENV = "XARIONIX_MODULE_CONFIGURATION="
CONFIG_LABEL = "io.xarionix.storage.configuration-sha256"


def configuration_text(job: Delivery) -> str:
    return json.dumps(configuration(job), sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def validate_configuration(info: dict[str, Any], image: dict[str, Any], job: Delivery) -> Configuration:
    values = info.get("Config", {}).get("Env", [])
    base = image.get("Config", {}).get("Env", []) or []
    extra = [value for value in values if isinstance(value, str) and value.startswith(CONFIG_ENV)]
    if len(extra) != 1 or values != [*base, extra[0]]:
        raise StorageError("storage_configuration_denied")
    text = extra[0][len(CONFIG_ENV) :]
    value = Configuration.parse(load_json(text.encode(), 4096))
    binding = job.storage
    if (
        binding is None
        or value.installation_id != job.installation_id
        or value.module_id != binding.module_id
        or value.package_version != binding.package_version
        or value.storage_max_bytes != binding.maximum_bytes
        or value.max_items_per_company != 100
        or value.title != "Деловые записи"
        or info.get("Config", {}).get("Labels", {}).get(CONFIG_LABEL)
        != hashlib.sha256(text.encode()).hexdigest()
    ):
        raise StorageError("storage_configuration_binding_changed")
    return value


class StorageController:
    def __init__(self, engine: Any, root: Path | None):
        self.engine, self.root = engine, root

    def current_epoch(self, job: Delivery) -> UUID:
        if job.storage is None:
            raise StorageError("storage_binding_required")
        epoch = job.storage.epoch_id
        if job.operation != "restore" or self.root is None:
            return epoch
        private_directory(self.root)
        path = self.root / "state.sqlite3"
        os.close(private_file(path))
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1) as database:
            row = database.execute(
                "SELECT receipt FROM runtime WHERE installation=? AND generation=?",
                (str(job.installation_id), job.generation),
            ).fetchone()
        if row and row[0]:
            receipt = load_json(row[0].encode(), 65536)
            if receipt.get("success") is True and receipt.get("report", {}).get("storage", {}).get(
                "epoch_id"
            ) == str(job.storage.next_epoch_id):
                return job.storage.next_epoch_id
        return epoch

    def volume(self, job: Delivery, epoch: UUID, *, create: bool = False) -> dict[str, Any]:
        self.engine.identity(job)
        name = volume_name(job, epoch)
        value = self.engine.call("GET", "/volumes/" + name)
        if value is None and create:
            value = self.engine.call(
                "POST",
                "/volumes/create",
                json={"Name": name, "Driver": "local", "Labels": labels(job, epoch)},
            )
        if (
            not isinstance(value, dict)
            or value.get("Name") != name
            or value.get("Driver") != "local"
            or value.get("Scope") != "local"
            or value.get("Options") not in (None, {})
            or value.get("Labels") != labels(job, epoch)
            or not isinstance(value.get("Mountpoint"), str)
            or not PurePosixPath(value["Mountpoint"]).is_absolute()
            or ".." in PurePosixPath(value["Mountpoint"]).parts
            or not value["Mountpoint"].endswith("/volumes/" + name + "/_data")
        ):
            raise StorageError("storage_volume_ownership_denied")
        return value

    def mount(self, job: Delivery, epoch: UUID) -> dict[str, Any]:
        return {
            "Type": "volume",
            "Source": volume_name(job, epoch),
            "Target": DATA_PATH,
            "ReadOnly": False,
            "VolumeOptions": {"NoCopy": True},
        }

    def validate_mounts(self, info: dict[str, Any], job: Delivery, epoch: UUID) -> None:
        volume = self.volume(job, epoch)
        configured = info.get("HostConfig", {}).get("Mounts")
        actual = info.get("Mounts")
        # Engine omits the false ReadOnly default in inspect; all other options
        # remain exact, including NoCopy and the installation-derived source.
        if isinstance(configured, list):
            configured = [
                {**mount, "ReadOnly": mount.get("ReadOnly", False)} if isinstance(mount, dict) else mount
                for mount in configured
            ]
        if configured != [self.mount(job, epoch)] or not isinstance(actual, list) or len(actual) != 1:
            raise StorageError("storage_mount_denied")
        mounted = actual[0]
        if (
            mounted.get("Type") != "volume"
            or mounted.get("Name") != volume["Name"]
            or mounted.get("Source") != volume["Mountpoint"]
            or mounted.get("Destination") != DATA_PATH
            or mounted.get("RW") is not True
            or mounted.get("Driver") != "local"
        ):
            raise StorageError("storage_mount_denied")

    def stopped(self, job: Delivery) -> None:
        for row in self.engine.owned(job):
            info = self.engine.inspect(row["Id"])
            if info is None or info.get("State", {}).get("Running"):
                raise StorageError("storage_writer_must_be_stopped")

    def _cache(self, job: Delivery) -> Path:
        if self.root is None:
            raise StorageError("storage_private_root_required")
        private_directory(self.root)
        base = self.root
        for part in ("installations", str(job.installation_id), "data", "backups"):
            base = base / part
            base.mkdir(mode=0o700, exist_ok=True)
            private_directory(base)
        return base

    def read(self, identifier: str, job: Delivery, destination: Path) -> set[str]:
        """Read only the fixed data directory; never tar.extract or arbitrary Docker paths."""
        if job.storage is None:
            raise StorageError("storage_binding_required")
        self.stopped(job)
        raw = bytearray()
        with self.engine.client.stream(
            "GET", "/containers/" + identifier + "/archive", params={"path": DATA_PATH}
        ) as response:
            if response.status_code != 200:
                raise StorageError("storage_read_failed")
            for chunk in response.iter_bytes(65536):
                raw.extend(chunk)
                if len(raw) > job.storage.maximum_bytes + 131072:
                    raise StorageError("storage_archive_size_exceeded")
        files: set[str] = set()
        total = 0
        directory = None
        envelope = False
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r|") as archive:
            for count, entry in enumerate(archive):
                if count > 8:
                    raise StorageError("storage_archive_entry_limit")
                if entry.isdir() and entry.name.rstrip("/") == "data":
                    if envelope:
                        raise StorageError("storage_archive_duplicate_directory")
                    envelope = True
                    continue
                if entry.isdir() and entry.name.rstrip("/") == "data/storage":
                    if directory is not None:
                        raise StorageError("storage_archive_duplicate_directory")
                    directory = (entry.uid, entry.gid, entry.mode & 0o777)
                    continue
                parts = PurePosixPath(entry.name).parts
                if (
                    len(parts) != 3
                    or parts[:2] != ("data", "storage")
                    or parts[2] not in ALLOWED
                    or parts[2] in files
                    or not entry.isfile()
                    or entry.issparse()
                    or entry.uid != 10001
                    or entry.gid != 10001
                    or entry.mode & 0o777 != 0o600
                    or not 0 <= entry.size <= job.storage.maximum_bytes
                ):
                    raise StorageError("storage_archive_entry_denied")
                total += entry.size
                if total > job.storage.maximum_bytes:
                    raise StorageError("storage_archive_size_exceeded")
                content = archive.extractfile(entry)
                if content is None:
                    raise StorageError("storage_archive_entry_denied")
                path = destination / parts[2]
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    remaining = entry.size
                    while remaining:
                        chunk = content.read(min(65536, remaining))
                        if not chunk:
                            raise StorageError("storage_archive_truncated")
                        stream.write(chunk)
                        remaining -= len(chunk)
                files.add(parts[2])
        if files and directory != (10001, 10001, 0o700):
            raise StorageError("storage_directory_owner_denied")
        return files

    def write(self, identifier: str, job: Delivery, files: dict[str, bytes]) -> None:
        self.stopped(job)
        if set(files) - {OWNER_FILE, "data.sqlite3"} or job.storage is None:
            raise StorageError("storage_write_denied")
        if sum(len(raw) for raw in files.values()) > job.storage.maximum_bytes:
            raise StorageError("storage_write_size_exceeded")
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            # Docker intentionally ignores extraction-root '.' headers. A fixed
            # child directory gets real owner/mode metadata without a root helper
            # container or allowing a write to the read-only container rootfs.
            directory = tarfile.TarInfo("storage")
            directory.type, directory.mode, directory.uid, directory.gid = (
                tarfile.DIRTYPE,
                0o700,
                10001,
                10001,
            )
            archive.addfile(directory)
            for name, content in files.items():
                entry = tarfile.TarInfo("storage/" + name)
                entry.mode, entry.uid, entry.gid, entry.size = 0o600, 10001, 10001, len(content)
                archive.addfile(entry, io.BytesIO(content))
        self.engine.call(
            "PUT",
            "/containers/" + identifier + "/archive",
            params={"path": DATA_PATH},
            content=output.getvalue(),
            headers={"Content-Type": "application/x-tar"},
        )

    def initialize(self, identifier: str, job: Delivery) -> None:
        if job.storage is None:
            raise StorageError("storage_binding_required")
        with tempfile.TemporaryDirectory(prefix="storage-inspect-", dir=self._cache(job).parent) as temporary:
            root = Path(temporary)
            files = self.read(identifier, job, root)
            if not files and job.storage.expected_schema_version == 0:
                self.write(
                    identifier,
                    job,
                    {
                        OWNER_FILE: json.dumps(
                            {"schema_version": 1, "installation_id": str(job.installation_id)}, sort_keys=True
                        ).encode()
                    },
                )
            elif OWNER_FILE not in files:
                raise StorageError("storage_owner_metadata_missing")

    def inspect(self, identifier: str, job: Delivery, epoch: UUID) -> StorageReport:
        if job.storage is None:
            raise StorageError("storage_binding_required")
        with tempfile.TemporaryDirectory(prefix="storage-inspect-", dir=self._cache(job).parent) as temporary:
            root = Path(temporary)
            files = self.read(identifier, job, root)
            if OWNER_FILE not in files:
                raise StorageError("storage_owner_metadata_missing")
            with SQLiteStorage(
                root, job.installation_id, maximum_bytes=job.storage.maximum_bytes
            ) as database:
                schema = database.schema_version
            if schema == 0 and job.storage.expected_schema_version > 0:
                raise StorageError("storage_data_missing")
            return StorageReport(epoch_id=epoch, data_schema_version=schema)

    def backup_metadata(self, job: Delivery) -> BackupMetadata:
        value = job.storage
        if value is None or value.backup_id is None:
            raise StorageError("storage_backup_binding_required")
        root = self._cache(job)
        with os.fdopen(private_file(root / f"{value.backup_id}.json"), "rb") as stream:
            document = load_json(stream.read(8193), 8192)
        if (
            not isinstance(document, dict)
            or set(document)
            != {
                "schema_version",
                "installation_id",
                "data_schema_version",
                "package_version",
                "sha256",
                "size",
                "backup_id",
            }
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or document["installation_id"] != str(job.installation_id)
            or document["backup_id"] != str(value.backup_id)
        ):
            raise StorageError("storage_backup_metadata_invalid")
        with os.fdopen(private_file(root / f"{value.backup_id}.sqlite3"), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not 0 < info.st_size <= value.maximum_bytes // 3:
                raise StorageError("storage_backup_size_invalid")
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if (
            digest != document["sha256"]
            or info.st_size != document["size"]
            or (value.backup_sha256 is not None and digest != value.backup_sha256)
        ):
            raise StorageError("storage_backup_integrity_invalid")
        return BackupMetadata(
            id=value.backup_id,
            epoch_id=value.epoch_id,
            data_schema_version=document["data_schema_version"],
            sha256=digest,
            size=info.st_size,
            package_version=document["package_version"],
        )

    def backup(self, identifier: str, job: Delivery) -> StorageReport:
        value = job.storage
        if value is None or value.backup_id is None:
            raise StorageError("storage_backup_binding_required")
        root = self._cache(job)
        if (root / f"{value.backup_id}.json").exists():
            metadata = self.backup_metadata(job)
            return StorageReport(
                epoch_id=value.epoch_id, data_schema_version=metadata.data_schema_version, backup=metadata
            )
        if len(list(root.iterdir())) >= 16:
            raise StorageError("storage_backup_retention_full")
        with tempfile.TemporaryDirectory(prefix="storage-backup-", dir=root.parent) as temporary:
            snapshot = Path(temporary)
            files = self.read(identifier, job, snapshot)
            if "data.sqlite3" not in files:
                raise StorageError("storage_data_missing")
            with SQLiteStorage(snapshot, job.installation_id, maximum_bytes=value.maximum_bytes) as database:
                if database.schema_version != value.expected_schema_version or database.schema_version == 0:
                    raise StorageError("storage_schema_conflict")
                database.backup(root, package_version=value.package_version, identifier=value.backup_id)
        metadata = self.backup_metadata(job)
        return StorageReport(
            epoch_id=value.epoch_id, data_schema_version=metadata.data_schema_version, backup=metadata
        )

    def validate_migration_backup(self, job: Delivery) -> None:
        value = job.storage
        if value is None or not value.allow_migration:
            raise StorageError("storage_migration_not_approved")
        metadata = self.backup_metadata(job)
        if (
            metadata.sha256 != value.backup_sha256
            or metadata.data_schema_version != value.expected_schema_version
        ):
            raise StorageError("storage_migration_backup_conflict")

    def restore(self, identifier: str, job: Delivery) -> StorageReport:
        value = job.storage
        if value is None or value.backup_id is None or value.next_epoch_id == value.epoch_id:
            raise StorageError("storage_restore_binding_required")
        self.stopped(job)
        self.backup_metadata(job)
        root = self._cache(job)
        with tempfile.TemporaryDirectory(prefix="storage-restore-", dir=root.parent) as temporary:
            snapshot = Path(temporary)
            initialize(snapshot, job.installation_id)
            with SQLiteStorage(snapshot, job.installation_id, maximum_bytes=value.maximum_bytes) as database:
                database.restore(
                    root,
                    value.backup_id,
                    minimum_schema=value.compatible_minimum,
                    maximum_schema=value.compatible_maximum,
                )
                version = database.schema_version
            data = (snapshot / "data.sqlite3").read_bytes()
            with tempfile.TemporaryDirectory(prefix="storage-target-", dir=root.parent) as target:
                if self.read(identifier, job, Path(target)):
                    raise StorageError("storage_restore_target_not_empty")
            self.write(
                identifier, job, {OWNER_FILE: (snapshot / OWNER_FILE).read_bytes(), "data.sqlite3": data}
            )
            with tempfile.TemporaryDirectory(prefix="storage-verify-", dir=root.parent) as verified:
                copied = Path(verified)
                files = self.read(identifier, job, copied)
                if "data.sqlite3" not in files or (copied / "data.sqlite3").read_bytes() != data:
                    raise StorageError("storage_restore_write_integrity_failed")
                with SQLiteStorage(
                    copied, job.installation_id, maximum_bytes=value.maximum_bytes
                ) as database:
                    if database.schema_version != version:
                        raise StorageError("storage_restore_schema_conflict")
            return StorageReport(epoch_id=value.next_epoch_id, data_schema_version=version)
