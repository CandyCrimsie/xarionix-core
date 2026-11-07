import json
import os
import select
import sqlite3
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from xarionix_sdk.storage import Migration, SQLiteStorage, StorageError, initialize

MIGRATIONS = (
    Migration(1, ("CREATE TABLE items(id TEXT PRIMARY KEY,company TEXT NOT NULL,name TEXT NOT NULL)",)),
    Migration(2, ("ALTER TABLE items ADD COLUMN description TEXT NOT NULL DEFAULT ''",)),
)


@pytest.fixture
def storage(tmp_path):
    root = tmp_path.resolve() / "data"
    root.mkdir(mode=0o700)
    installation = uuid4()
    initialize(root, installation)
    with SQLiteStorage(root, installation) as value:
        value.migrate(MIGRATIONS, 1, expected=0)
        yield value


def create(storage, company, name):
    with storage.transaction() as database:
        database.execute("INSERT INTO items(id,company,name) VALUES(?,?,?)", (str(uuid4()), company, name))


def names(storage, company):
    with storage.transaction() as database:
        return [
            r[0] for r in database.execute("SELECT name FROM items WHERE company=? ORDER BY name", (company,))
        ]


def backup_dir(storage):
    directory = storage.root.parent / "backups"
    directory.mkdir(mode=0o700)
    return directory


def test_real_sqlite_restart_and_company_isolation(storage):
    create(storage, "A", "A1")
    create(storage, "B", "B1")
    storage.close()
    with SQLiteStorage(storage.root, storage.installation) as restarted:
        assert names(restarted, "A") == ["A1"]
        assert names(restarted, "B") == ["B1"]
    assert not (storage.root / "data.sqlite3-wal").exists()
    assert not (storage.root / "data.sqlite3-journal").exists()


def test_writer_lock_and_installation_binding(storage):
    with pytest.raises(StorageError, match="writer_active"):
        SQLiteStorage(storage.root, storage.installation)
    with pytest.raises(StorageError, match="installation_mismatch"):
        SQLiteStorage(storage.root, uuid4())


def test_migration_is_transactional_and_data_survives_compatible_update(storage):
    create(storage, "A", "A1")
    storage.migrate(MIGRATIONS, 2, expected=1)
    storage.compatible(1, 2)
    assert names(storage, "A") == ["A1"]
    with pytest.raises(StorageError, match="incompatible"):
        storage.compatible(1, 1)
    with pytest.raises(StorageError, match="conflict"):
        storage.migrate(MIGRATIONS, 2, expected=1)


@pytest.mark.parametrize(
    "bad",
    ["INVALID SQL", "COMMIT", "ATTACH DATABASE '/tmp/other.sqlite3' AS other", "PRAGMA journal_mode=OFF"],
)
def test_failed_or_escape_migration_rolls_back_every_change(storage, bad):
    migrations = MIGRATIONS[:1] + (Migration(2, ("CREATE TABLE staged(value TEXT)", bad)),)
    with pytest.raises(sqlite3.DatabaseError):
        storage.migrate(migrations, 2, expected=1)
    assert storage.schema_version == 1
    assert storage.db.execute("SELECT name FROM sqlite_master WHERE name='staged'").fetchall() == []


def test_backup_restore_is_consistent_and_bound_to_installation(storage):
    create(storage, "A", "A1")
    directory = backup_dir(storage)
    identifier = storage.backup(directory, package_version="1.0.0")
    create(storage, "A", "A2")
    storage.migrate(MIGRATIONS, 2, expected=1)
    storage.restore(directory, identifier, minimum_schema=1, maximum_schema=2)
    assert storage.schema_version == 1
    assert names(storage, "A") == ["A1"]
    metadata = json.loads((directory / f"{identifier}.json").read_text())
    assert metadata["installation_id"] == str(storage.installation)
    assert metadata["data_schema_version"] == 1
    assert len(metadata["sha256"]) == 64
    assert (directory / f"{identifier}.sqlite3").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "corruption", ["hash", "installation", "schema", "size", "backup_id", "file", "symlink"]
)
def test_invalid_backup_is_refused_without_altering_live_data(storage, corruption):
    directory = backup_dir(storage)
    create(storage, "A", "before")
    identifier = storage.backup(directory, package_version="1.0.0")
    document = directory / f"{identifier}.json"
    metadata = json.loads(document.read_text())
    if corruption == "hash":
        metadata["sha256"] = "0" * 64
    elif corruption == "installation":
        metadata["installation_id"] = str(uuid4())
    elif corruption == "schema":
        metadata["data_schema_version"] = 10
    elif corruption == "size":
        metadata["size"] += 1
    elif corruption == "backup_id":
        metadata["backup_id"] = str(uuid4())
    elif corruption == "file":
        (directory / f"{identifier}.sqlite3").write_bytes(b"corrupted")
    else:
        actual = directory / f"{identifier}.sqlite3"
        actual.rename(directory / "elsewhere")
        actual.symlink_to(directory / "elsewhere")
    document.write_text(json.dumps(metadata))
    create(storage, "A", "after")
    with pytest.raises((StorageError, OSError)):
        storage.restore(directory, identifier, minimum_schema=1, maximum_schema=1)
    assert names(storage, "A") == ["after", "before"]


@pytest.mark.parametrize("defect", ["root_symlink", "file_symlink", "root_mode", "file_mode", "hardlink"])
def test_private_storage_rejects_path_and_permission_escapes(tmp_path, defect):
    root = tmp_path.resolve() / "data"
    root.mkdir(mode=0o700)
    installation = uuid4()
    initialize(root, installation)
    if defect == "root_symlink":
        alias = root.parent / "alias"
        alias.symlink_to(root)
        root = alias
    elif defect == "root_mode":
        root.chmod(0o755)
    elif defect == "file_mode":
        (root / ".xarionix-storage.json").chmod(0o644)
    elif defect == "file_symlink":
        (root / "data.sqlite3").symlink_to(root / "elsewhere")
    else:
        os.link(root / ".xarionix-storage.json", root / "extra")
    with pytest.raises((StorageError, OSError)):
        SQLiteStorage(root, installation)


def test_database_size_policy_rolls_back_an_oversized_write(tmp_path):
    root = tmp_path.resolve() / "data"
    root.mkdir(mode=0o700)
    installation = uuid4()
    initialize(root, installation)
    with SQLiteStorage(root, installation, maximum_bytes=1048576) as storage:
        storage.migrate((Migration(1, ("CREATE TABLE content(value BLOB)",)),), 1, expected=0)
        with pytest.raises(sqlite3.DatabaseError):
            with storage.transaction() as database:
                database.execute("INSERT INTO content VALUES(zeroblob(1048576))")
        assert storage.db.execute("SELECT count(*) FROM content").fetchone() == (0,)
        storage.integrity()


def test_process_crash_during_write_recovers_previous_committed_rows(tmp_path):
    root = tmp_path.resolve() / "data"
    root.mkdir(mode=0o700)
    installation = uuid4()
    initialize(root, installation)
    with SQLiteStorage(root, installation) as database:
        database.migrate(MIGRATIONS, 1, expected=0)
        create(database, "A", "committed")
    program = """import sys
from pathlib import Path
from uuid import UUID
from xarionix_sdk.storage import SQLiteStorage
with SQLiteStorage(Path(sys.argv[1]),UUID(sys.argv[2])) as db:
 with db.transaction() as connection:
  connection.execute("INSERT INTO items VALUES('crash','A','uncommitted')")
  print('writing',flush=True)
  sys.stdin.read()
"""
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "sdk/python/src"),
    }
    child = subprocess.Popen(
        [sys.executable, "-c", program, str(root), str(installation)],
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert select.select([child.stdout], [], [], 10)[0], "Writer did not enter transaction"
        assert child.stdout.readline() == b"writing\n"
        child.kill()
        child.wait(timeout=5)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stdin.close()
        child.stdout.close()
    with SQLiteStorage(root, installation) as database:
        assert names(database, "A") == ["committed"]
        database.integrity()
