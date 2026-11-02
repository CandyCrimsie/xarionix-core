"""Local-only CAS. Blob-first publication leaves recoverable orphans, not fake DB/FS atomicity."""

import fcntl
import hashlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from app.domains.packages.archive import CHUNK, Limits, digest_stream
from app.domains.packages.codec import PackageError


@dataclass
class Lease:
    maintenance: BinaryIO
    slot: BinaryIO

    def close(self) -> None:
        self.slot.close()
        self.maintenance.close()


class Storage:
    def __init__(self, root: Path):
        if not root.is_absolute() or root.is_symlink():
            raise PackageError("storage_configuration_invalid")
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if (
            root.resolve() != root
            or stat.S_IMODE(root.stat().st_mode) & 0o077
            or root.stat().st_uid != os.geteuid()
        ):
            raise PackageError("storage_permissions_invalid")
        self.root = root
        for name in ("staging", "sha256"):
            directory = root / name
            directory.mkdir(mode=0o700, exist_ok=True)
            if (
                directory.is_symlink()
                or not directory.is_dir()
                or directory.stat().st_uid != os.geteuid()
                or stat.S_IMODE(directory.stat().st_mode) & 0o077
            ):
                raise PackageError("storage_directory_invalid")

    def lock_file(self, name: str) -> BinaryIO:
        return os.fdopen(os.open(self.root / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), "r+b")

    def lease(self) -> Lease:
        # Cross-worker/process, not just an asyncio semaphore. Never wait with a DB connection.
        maintenance = self.lock_file("maintenance.lock")
        try:
            fcntl.flock(maintenance, fcntl.LOCK_SH | fcntl.LOCK_NB)
            for number in range(2):
                slot = self.lock_file(f"slot-{number}.lock")
                try:
                    fcntl.flock(slot, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return Lease(maintenance, slot)
                except BlockingIOError:
                    slot.close()
        except BlockingIOError:
            pass
        maintenance.close()
        raise PackageError("package_capacity_busy")

    def temporary(self) -> tuple[Path, BinaryIO]:
        free = os.statvfs(self.root)
        if free.f_bavail * free.f_frsize < 2 * Limits().package + 64 * 1024 * 1024:
            raise PackageError("storage_capacity_low")
        descriptor, name = tempfile.mkstemp(prefix="upload-", dir=self.root / "staging")
        return Path(name), os.fdopen(descriptor, "w+b")

    def blob(self, digest: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PackageError("invalid_storage_reference")
        directory = self.root / "sha256" / digest[:2]
        directory.mkdir(mode=0o700, exist_ok=True)
        if (
            directory.is_symlink()
            or stat.S_IMODE(directory.stat().st_mode) & 0o077
            or directory.stat().st_uid != os.geteuid()
        ):
            raise PackageError("storage_directory_invalid")
        return directory / (digest + ".xpkg")

    def check(self, digest: str) -> bool:
        path = self.blob(digest)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    return False
                actual, _ = digest_stream(stream, Limits().package)
            return actual == digest
        except (OSError, PackageError):
            return False

    def publish(self, stage: Path, digest: str) -> None:
        target = self.blob(digest)
        descriptor, name = tempfile.mkstemp(prefix="publish-", dir=self.root / "staging")
        temporary = Path(name)
        try:
            # Verify the actual bytes being published, not a prior mutable-path snapshot.
            with (
                os.fdopen(descriptor, "wb") as destination,
                os.fdopen(os.open(stage, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source,
            ):
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise PackageError("staging_type_changed")
                actual, total = hashlib.sha256(), 0
                while chunk := source.read(CHUNK):
                    total += len(chunk)
                    if total > Limits().package:
                        raise PackageError("package_size_limit")
                    actual.update(chunk)
                    destination.write(chunk)
                if actual.hexdigest() != digest:
                    raise PackageError("staging_integrity_changed")
                destination.flush()
                os.fchmod(destination.fileno(), 0o400)
                os.fsync(destination.fileno())
            try:
                os.link(temporary, target, follow_symlinks=False)
            except FileExistsError:
                if not self.check(digest):
                    raise PackageError("existing_blob_corrupt") from None
            for folder in (target.parent, self.root / "sha256", self.root):
                fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)

    def reconcile(self, references: set[str], *, remove: bool = False) -> dict[str, int]:
        # Caller must obtain EXCLUSIVE maintenance.lock BEFORE reading the DB reference set.
        # The CLI does this across its short DB snapshot and filesystem scan.
        counts = {"orphan_blobs": 0, "stale_staging": 0, "missing_or_corrupt": 0, "removed": 0}
        for path in (self.root / "staging").iterdir():
            if path.name.startswith(("upload-", "publish-")) and path.is_file() and not path.is_symlink():
                counts["stale_staging"] += 1
                if remove:
                    path.unlink()
                    counts["removed"] += 1
        for folder in (self.root / "sha256").iterdir():
            if folder.is_symlink() or not folder.is_dir() or not re.fullmatch(r"[0-9a-f]{2}", folder.name):
                raise PackageError("storage_directory_invalid")
            for path in folder.iterdir():
                digest = path.stem
                if (
                    path.suffix == ".xpkg"
                    and path.is_file()
                    and not path.is_symlink()
                    and re.fullmatch(r"[0-9a-f]{64}", digest)
                    and digest.startswith(folder.name)
                    and digest not in references
                ):
                    counts["orphan_blobs"] += 1
                    if remove:
                        path.unlink()
                        counts["removed"] += 1
        for digest in references:
            counts["missing_or_corrupt"] += not self.check(digest)
        return counts
