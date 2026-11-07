import copy
import io
import json
import tarfile
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from xarionix_sdk.storage import Migration, SQLiteStorage, StorageError, initialize

from app.domains.deployments.contracts import Delivery, StorageBinding
from scripts.deployment_agent.storage import StorageController, labels, volume_name


@pytest.fixture
def job():
    epoch = uuid4()
    return Delivery(
        id=uuid4(),
        fence=uuid4(),
        host_id=uuid4(),
        installation_id=uuid4(),
        operation="backup",
        generation=2,
        installation_generation=1,
        lease_until=datetime.now(UTC) + timedelta(seconds=120),
        package_sha256="a" * 64,
        package_size=100,
        engine_id="test-rootless-engine",
        profile="module-api-stateful-v1",
        runtime={
            "schema_version": 1,
            "engine": "oci",
            "platform": "linux/amd64",
            "image_digest": "sha256:" + "b" * 64,
            "config_digest": "sha256:" + "c" * 64,
            "health_contract": "http-python-v1",
            "health_port": 8080,
        },
        trust={"schema_version": 1, "keys": []},
        storage=StorageBinding(
            module_id="hello-business",
            epoch_id=epoch,
            next_epoch_id=epoch,
            allocation_revision=1,
            expected_schema_version=1,
            target_schema_version=1,
            compatible_minimum=1,
            compatible_maximum=1,
            sdk_sha256="d" * 64,
            package_version="1.1.0",
            backup_id=uuid4(),
        ),
    )


def data_archive(files, *, mutation=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        root = tarfile.TarInfo("data")
        root.type, root.uid, root.gid, root.mode = tarfile.DIRTYPE, 0, 0, 0o755
        archive.addfile(root)
        root = tarfile.TarInfo("data/storage")
        root.type, root.uid, root.gid, root.mode = tarfile.DIRTYPE, 10001, 10001, 0o700
        if mutation == "directory":
            root.mode = 0o755
        archive.addfile(root)
        for index, (name, raw) in enumerate(files.items()):
            entry = tarfile.TarInfo("data/storage/" + name)
            entry.uid, entry.gid, entry.mode, entry.size = 10001, 10001, 0o600, len(raw)
            if index == 0:
                if mutation == "symlink":
                    entry.type, entry.linkname, entry.size = tarfile.SYMTYPE, "/etc/passwd", 0
                elif mutation == "owner":
                    entry.uid = 0
                elif mutation == "mode":
                    entry.mode = 0o644
                elif mutation == "path":
                    entry.name = "data/../../outside"
                elif mutation == "unknown":
                    entry.name = "data/unexpected"
            archive.addfile(entry, io.BytesIO(raw))
            if index == 0 and mutation == "duplicate":
                archive.addfile(entry, io.BytesIO(raw))
    return output.getvalue()


class Engine:
    def __init__(self, job, archive):
        self.job, self.archive = job, archive
        self.active = False
        self.volumes = {}
        self.client = httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, content=self.archive)),
            base_url="http://engine",
        )

    def identity(self, job):
        assert job.engine_id == self.job.engine_id

    def owned(self, job):
        return [{"Id": "a" * 64}]

    def inspect(self, identifier):
        return {"State": {"Running": self.active}}

    def call(self, method, path, **kwargs):
        if path == "/volumes/create":
            value = kwargs["json"]
            descriptor = value | {
                "Scope": "local",
                "Options": None,
                "Mountpoint": "/home/rootless/.local/share/docker/volumes/" + value["Name"] + "/_data",
            }
            self.volumes[value["Name"]] = descriptor
            return descriptor
        if path.startswith("/volumes/"):
            return self.volumes.get(path.split("/")[-1])
        raise AssertionError("unexpected engine mutation")


@pytest.fixture
def source(tmp_path, job):
    root = tmp_path.resolve() / "source"
    root.mkdir(mode=0o700)
    initialize(root, job.installation_id)
    with SQLiteStorage(root, job.installation_id) as database:
        database.migrate((Migration(1, ("CREATE TABLE items(company TEXT,name TEXT)",)),), 1, expected=0)
        with database.transaction() as connection:
            connection.execute("INSERT INTO items VALUES('A','A1'),('B','B1')")
    return {file.name: file.read_bytes() for file in root.iterdir()}


@pytest.fixture
def controller(tmp_path, job, source):
    root = tmp_path.resolve() / "agent"
    root.mkdir(mode=0o700)
    engine = Engine(job, data_archive(source))
    value = StorageController(engine, root)
    yield value
    engine.client.close()


def test_owned_volume_is_derived_from_installation_and_epoch(controller, job):
    value = controller.volume(job, job.storage.epoch_id, create=True)
    assert value["Name"] == volume_name(job, job.storage.epoch_id)
    assert value["Labels"] == labels(job, job.storage.epoch_id)
    assert controller.volume(job, job.storage.epoch_id) == value
    with pytest.raises(StorageError):
        controller.volume(job, uuid4(), create=True)


def test_real_engine_omitted_false_mount_default_is_accepted_without_accepting_extra_mounts(controller, job):
    volume = controller.volume(job, job.storage.epoch_id, create=True)
    mount = controller.mount(job, job.storage.epoch_id)
    mount.pop("ReadOnly")
    info = {
        "HostConfig": {"Mounts": [mount]},
        "Mounts": [
            {
                "Type": "volume",
                "Name": volume["Name"],
                "Source": volume["Mountpoint"],
                "Destination": "/data",
                "RW": True,
                "Driver": "local",
            }
        ],
    }
    controller.validate_mounts(info, job, job.storage.epoch_id)
    info["HostConfig"]["Mounts"].append({"Type": "bind", "Source": "/etc", "Target": "/other"})
    with pytest.raises(StorageError):
        controller.validate_mounts(info, job, job.storage.epoch_id)


@pytest.mark.parametrize("defect", ["labels", "driver", "options", "mountpoint", "scope"])
def test_existing_foreign_or_host_backed_volume_cannot_be_adopted(controller, job, defect):
    value = controller.volume(job, job.storage.epoch_id, create=True)
    if defect == "labels":
        value["Labels"]["io.xarionix.storage.installation"] = str(uuid4())
    elif defect == "driver":
        value["Driver"] = "other"
    elif defect == "options":
        value["Options"] = {"type": "none", "device": "/var/lib/postgresql", "o": "bind"}
    elif defect == "scope":
        value["Scope"] = "global"
    else:
        value["Mountpoint"] = "/host/foreign"
    with pytest.raises(StorageError, match="ownership"):
        controller.volume(job, job.storage.epoch_id)


@pytest.mark.parametrize(
    "mutation", ["symlink", "owner", "mode", "path", "unknown", "duplicate", "directory"]
)
def test_storage_archive_rejects_escape_and_insecure_files(controller, job, source, tmp_path, mutation):
    controller.engine.archive = data_archive(source, mutation=mutation)
    target = tmp_path.resolve() / "extracted"
    target.mkdir(mode=0o700)
    with pytest.raises(StorageError):
        controller.read("a" * 64, job, target)
    assert not (tmp_path / "outside").exists()


def test_snapshot_and_backup_use_real_sqlite_and_private_destination(controller, job):
    observed = controller.inspect("a" * 64, job, job.storage.epoch_id)
    assert observed.data_schema_version == 1
    backup = controller.backup("a" * 64, job)
    assert backup.backup.id == job.storage.backup_id
    assert backup.backup.size > 0 and len(backup.backup.sha256) == 64
    assert controller.backup_metadata(job) == backup.backup
    root = controller._cache(job)
    assert root.stat().st_mode & 0o777 == 0o700
    with (root / f"{job.storage.backup_id}.json").open() as file:
        assert json.load(file)["installation_id"] == str(job.installation_id)
    assert controller.backup("a" * 64, job) == backup


def test_active_writer_prevents_offline_backup(controller, job):
    controller.engine.active = True
    with pytest.raises(StorageError, match="writer"):
        controller.backup("a" * 64, job)
    assert list(controller._cache(job).iterdir()) == []


def test_corrupted_backup_cannot_be_used_for_migration_or_restore(controller, job):
    report = controller.backup("a" * 64, job)
    binding = job.storage.model_copy(update={"backup_sha256": report.backup.sha256, "allow_migration": True})
    update = job.model_copy(update={"storage": binding})
    controller.validate_migration_backup(update)
    (controller._cache(job) / f"{binding.backup_id}.sqlite3").write_bytes(b"corrupted")
    with pytest.raises(StorageError):
        controller.validate_migration_backup(update)


@pytest.mark.parametrize("defect", ["source", "type", "extra", "readonly"])
def test_only_exact_owned_volume_mount_is_accepted(controller, job, defect):
    volume = controller.volume(job, job.storage.epoch_id, create=True)
    info = {
        "HostConfig": {"Mounts": [controller.mount(job, job.storage.epoch_id)]},
        "Mounts": [
            {
                "Type": "volume",
                "Name": volume["Name"],
                "Source": volume["Mountpoint"],
                "Destination": "/data",
                "RW": True,
                "Driver": "local",
            }
        ],
    }
    controller.validate_mounts(info, job, job.storage.epoch_id)
    if defect == "source":
        info["Mounts"][0]["Source"] = "/var/lib/postgresql"
    elif defect == "type":
        info["Mounts"][0]["Type"] = "bind"
    elif defect == "readonly":
        info["Mounts"][0]["RW"] = False
    else:
        info["Mounts"].append(copy.deepcopy(info["Mounts"][0]))
    with pytest.raises(StorageError, match="mount"):
        controller.validate_mounts(info, job, job.storage.epoch_id)
