"""Bounded single-writer local journal. No credentials or raw engine responses."""

import fcntl
import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any
from uuid import UUID

from app.domains.deployments.contracts import Delivery


class State:
    def __init__(self, root: Path):
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if (
            not root.is_absolute()
            or root.is_symlink()
            or root.resolve() != root
            or root.stat().st_uid != os.geteuid()
            or stat.S_IMODE(root.stat().st_mode) & 0o077
        ):
            raise ValueError("deployment_storage_denied")
        self.root = root
        self.lock = os.fdopen(
            os.open(root / "agent.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), "r+b"
        )
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        database = root / "state.sqlite3"
        fd = os.open(database, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(database, timeout=5)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""CREATE TABLE IF NOT EXISTS sequence(id integer PRIMARY KEY CHECK(id=1), value integer NOT NULL);
        INSERT OR IGNORE INTO sequence VALUES(1,0);
        CREATE TABLE IF NOT EXISTS runtime(installation text PRIMARY KEY, generation integer NOT NULL, delivery text NOT NULL, receipt text);
        """)
        for pending in self.jobs():
            self.clear_staging(pending.installation_id)

    def close(self) -> None:
        self.db.close()
        self.lock.close()

    def sequence(self) -> int:
        with self.db:
            self.db.execute("UPDATE sequence SET value=value+1 WHERE id=1")
            return int(self.db.execute("SELECT value FROM sequence WHERE id=1").fetchone()[0])

    def accept(self, job: Delivery) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT generation,delivery,receipt FROM runtime WHERE installation=?",
            (str(job.installation_id),),
        ).fetchone()
        if row and row[0] > job.generation:
            raise ValueError("deployment_stale_generation")
        if row and row[0] == job.generation:
            previous = Delivery.model_validate_json(row[1])
            if (
                previous.id != job.id
                or previous.runtime != job.runtime
                or previous.profile != job.profile
                or previous.operation != job.operation
            ):
                raise ValueError("deployment_generation_identity_conflict")
            if row[2]:
                return dict(json.loads(row[2]))
        if row is None and self.db.execute("SELECT count(*) FROM runtime").fetchone()[0] >= 32:
            raise ValueError("deployment_local_capacity")
        self.workspace(job.installation_id)
        with self.db:
            self.db.execute(
                "INSERT INTO runtime VALUES(?,?,?,NULL) ON CONFLICT(installation) DO UPDATE SET generation=excluded.generation,delivery=excluded.delivery,receipt=NULL",
                (str(job.installation_id), job.generation, job.model_dump_json()),
            )
        return None

    def workspace(self, identifier: UUID) -> Path:
        # The only path input is a validated server UUID, never a manifest path.
        base = self.root / "installations"
        target = base / str(UUID(str(identifier)))
        for path in (base, target, target / "cache", target / "data"):
            path.mkdir(mode=0o700, exist_ok=True)
            if (
                path.is_symlink()
                or path.resolve() != path
                or path.stat().st_uid != os.geteuid()
                or stat.S_IMODE(path.stat().st_mode) & 0o077
            ):
                raise ValueError("deployment_workspace_denied")
        return target

    def clear_staging(self, identifier: UUID) -> None:
        # User data and the durable journal are never cleanup targets.
        cache = self.workspace(identifier) / "cache"
        for name in ("package.xpkg", "image.tar"):
            path = cache / name
            if path.is_symlink() or (
                path.exists() and (not path.is_file() or path.stat().st_uid != os.geteuid())
            ):
                raise ValueError("deployment_staging_denied")
            path.unlink(missing_ok=True)

    def completed(self, job: Delivery, receipt: dict[str, Any]) -> None:
        with self.db:
            self.db.execute(
                "UPDATE runtime SET receipt=? WHERE installation=? AND generation=?",
                (json.dumps(receipt, separators=(",", ":")), str(job.installation_id), job.generation),
            )

    def jobs(self) -> list[Delivery]:
        return [
            Delivery.model_validate_json(row[0])
            for row in self.db.execute("SELECT delivery FROM runtime ORDER BY installation LIMIT 32")
        ]
