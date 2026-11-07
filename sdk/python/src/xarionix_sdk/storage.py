"""Single-writer SQLite storage. This code runs inside the owned module volume boundary."""

import contextlib
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4


class StorageError(Exception):
    pass


def private_directory(path: Path) -> None:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or path.resolve() != path
        or not path.is_dir()
        or path.stat().st_uid != os.geteuid()
        or stat.S_IMODE(path.stat().st_mode) != 0o700
    ):
        raise StorageError("storage_directory_denied")


def private_file(path: Path, *, create: bool = False) -> int:
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags | (os.O_CREAT if create else 0), 0o600)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        os.close(fd)
        raise StorageError("storage_file_denied")
    return fd


def initialize(root: Path, installation: UUID) -> None:
    """Only for an explicitly provisioned empty volume, before any runtime writer starts."""
    private_directory(root)
    if any(root.iterdir()):
        raise StorageError("storage_not_empty")
    data = json.dumps({"schema_version": 1, "installation_id": str(installation)}, sort_keys=True).encode()
    fd = os.open(root / ".xarionix-storage.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


@dataclass(frozen=True)
class Migration:
    version: int
    statements: tuple[str, ...]


@dataclass(frozen=True)
class StorageSchema:
    version: int
    compatible_minimum: int
    compatible_maximum: int
    migrations: tuple[Migration, ...]

    def document(self) -> dict[str, Any]:
        if (
            any(
                type(value) is not int
                for value in (self.version, self.compatible_minimum, self.compatible_maximum)
            )
            or not 1 <= self.compatible_minimum <= self.version <= self.compatible_maximum <= 128
            or [step.version for step in self.migrations] != list(range(1, self.version + 1))
        ):
            raise StorageError("storage_schema_declaration_invalid")
        from .validation import json_bytes

        return {
            "engine": "sqlite",
            "data_schema_version": self.version,
            "compatible_minimum": self.compatible_minimum,
            "compatible_maximum": self.compatible_maximum,
            "migrations": [
                {
                    "version": step.version,
                    "sha256": hashlib.sha256(
                        json_bytes(
                            {
                                "version": step.version,
                                "statements": list(step.statements),
                            }
                        )
                    ).hexdigest(),
                }
                for step in self.migrations
            ],
        }


class SQLiteStorage:
    def __init__(self, root: Path, installation: UUID, *, maximum_bytes: int = 67108864):
        if type(maximum_bytes) is not int or not 1048576 <= maximum_bytes <= 67108864:
            raise StorageError("storage_size_policy_denied")
        private_directory(root)
        with os.fdopen(private_file(root / ".xarionix-storage.json"), "rb") as stream:
            raw = stream.read(1025)
        if len(raw) > 1024 or json.loads(raw) != {"schema_version": 1, "installation_id": str(installation)}:
            raise StorageError("storage_installation_mismatch")
        self.root, self.installation, self.maximum_bytes = root, UUID(str(installation)), maximum_bytes
        self._thread_lock = threading.RLock()
        self._transaction_control = False
        self.lock = os.fdopen(private_file(root / ".writer.lock", create=True), "r+b")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            raise StorageError("storage_writer_active") from None
        self.db: sqlite3.Connection
        try:
            path = root / "data.sqlite3"
            os.close(private_file(path, create=True))
            self.db = sqlite3.connect(
                path, timeout=2, isolation_level=None, check_same_thread=False, cached_statements=0
            )
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.execute("PRAGMA foreign_keys=ON")
            page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
            # Reserve space for rollback journal and interrupted-write recovery.
            pages = maximum_bytes // (3 * page_size)
            if self.db.execute(f"PRAGMA max_page_count={pages}").fetchone()[0] > pages:
                raise StorageError("storage_size_exceeded")
            self.integrity()
            self.db.set_authorizer(self._authorize)
        except Exception:
            if hasattr(self, "db"):
                self.db.close()
            self.lock.close()
            raise

    @property
    def schema_version(self) -> int:
        return int(self.db.execute("PRAGMA user_version").fetchone()[0])

    def compatible(self, minimum: int, maximum: int) -> None:
        if not 1 <= minimum <= self.schema_version <= maximum <= 1024:
            raise StorageError("storage_schema_incompatible")

    def integrity(self) -> None:
        if self.db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise StorageError("storage_integrity_failed")
        for path in self.root.iterdir():
            if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
                raise StorageError("storage_entry_denied")
        if sum(p.stat().st_size for p in self.root.iterdir()) > self.maximum_bytes:
            raise StorageError("storage_size_exceeded")

    def _authorize(
        self, action: int, first: str | None, second: str | None, database: str | None, trigger: str | None
    ) -> int:
        if action in {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_SAVEPOINT}:
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_TRANSACTION and not self._transaction_control:
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_PRAGMA and first not in {
            "user_version",
            "table_info",
            "index_info",
            "foreign_key_list",
            "integrity_check",
            "quick_check",
            "foreign_key_check",
            "data_version",
            "schema_version",
        }:
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION and second in {"load_extension", "readfile", "writefile"}:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def _control(self, statement: str) -> None:
        self._transaction_control = True
        try:
            self.db.execute(statement)
        finally:
            self._transaction_control = False

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._thread_lock:
            self._control("BEGIN IMMEDIATE")
            try:
                yield self.db
                self._control("COMMIT")
            except BaseException:
                if self.db.in_transaction:
                    self._control("ROLLBACK")
                raise

    def migrate(self, migrations: tuple[Migration, ...], target: int, *, expected: int) -> None:
        if self.schema_version != expected or not expected < target <= 1024:
            raise StorageError("storage_migration_version_conflict")
        steps = [step for step in migrations if expected < step.version <= target]
        if [s.version for s in steps] != list(range(expected + 1, target + 1)):
            raise StorageError("storage_migration_missing")
        with self.transaction() as database:
            for migration in steps:
                for statement in migration.statements:
                    # SQLite execute accepts one statement, never executes uploaded scripts in Core.
                    database.execute(statement)
                database.execute(f"PRAGMA user_version={migration.version}")
            if database.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise StorageError("storage_migration_invalid")
        self.integrity()

    def backup(self, destination: Path, *, package_version: str, identifier: UUID | None = None) -> UUID:
        """SQLite online backup API, not a live filesystem copy."""
        private_directory(destination)
        identifier = UUID(str(identifier)) if identifier is not None else uuid4()
        path = destination / f"{identifier}.sqlite3"
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))
        try:
            with sqlite3.connect(path) as snapshot:
                self.db.backup(snapshot)
                if snapshot.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise StorageError("backup_integrity_failed")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
                os.fsync(stream.fileno())
            metadata = {
                "schema_version": 1,
                "installation_id": str(self.installation),
                "data_schema_version": self.schema_version,
                "package_version": package_version,
                "sha256": digest,
                "size": path.stat().st_size,
                "backup_id": str(identifier),
            }
            document = destination / f"{identifier}.json"
            fd = os.open(document, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(metadata, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            return identifier
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def restore(self, source: Path, identifier: UUID, *, minimum_schema: int, maximum_schema: int) -> None:
        """Caller holds the sole-writer lock; the deployment layer must stop runtime first."""
        private_directory(source)
        identifier = UUID(str(identifier))
        with os.fdopen(private_file(source / f"{identifier}.json"), "rb") as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise StorageError("backup_metadata_invalid")
        metadata = json.loads(raw)
        path = source / f"{identifier}.sqlite3"
        with os.fdopen(private_file(path), "rb") as stream:
            info = os.fstat(stream.fileno())
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if (
            set(metadata)
            != {
                "schema_version",
                "installation_id",
                "data_schema_version",
                "package_version",
                "sha256",
                "size",
                "backup_id",
            }
            or metadata["schema_version"] != 1
            or metadata["installation_id"] != str(self.installation)
            or metadata["backup_id"] != str(identifier)
            or metadata["size"] != info.st_size
            or not 0 < info.st_size <= self.maximum_bytes // 3
            or metadata["sha256"] != digest
            or type(metadata["data_schema_version"]) is not int
            or not minimum_schema <= metadata["data_schema_version"] <= maximum_schema
        ):
            raise StorageError("backup_binding_or_integrity_invalid")
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as snapshot:
            if (
                snapshot.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
                or snapshot.execute("PRAGMA user_version").fetchone()[0] != metadata["data_schema_version"]
            ):
                raise StorageError("backup_integrity_failed")
            snapshot.backup(self.db)
        self.integrity()

    def close(self) -> None:
        self.db.close()
        self.lock.close()

    def __enter__(self) -> "SQLiteStorage":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
