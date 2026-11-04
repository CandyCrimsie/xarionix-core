import copy
import hashlib
import io
import json
import tarfile
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from runtime_helpers import docker_archive, mutate_contract, runtime_package

from app.domains.deployments import artifacts
from app.domains.deployments.artifacts import (
    PREFIX,
    RUNTIME,
    RuntimeContract,
    validate_runtime,
    write_oci_archive,
)
from app.domains.installations.policy import runtime_mode
from app.domains.packages.archive import verify
from app.domains.packages.codec import PackageError


def test_signed_offline_oci_inventory_roundtrip_without_extraction(tmp_path):
    path, trust, report, contract = runtime_package(tmp_path / "package")
    checked = verify(path, trust)
    assert runtime_mode(checked.manifest) == "oci_v1"
    assert validate_runtime(path, checked.manifest).model_dump() == contract
    target = tmp_path / "oci.tar"
    write_oci_archive(path, checked.manifest, target)
    with tarfile.open(target) as archive:
        names = set(archive.getnames())
        assert "oci-layout" in names and "index.json" in names
        assert "manifest.json" not in names and RUNTIME not in names
        for entry in archive:
            assert entry.isfile() and not entry.name.startswith("/") and ".." not in entry.name
            if entry.name.startswith("blobs/"):
                assert (
                    hashlib.sha256(archive.extractfile(entry).read()).hexdigest()
                    == entry.name.rsplit("/", 1)[1]
                )
    assert report["package_sha256"] == checked.package_sha256


@pytest.mark.parametrize("compressed", [False, True])
def test_docker_save_uncompressed_and_containerd_gzip_layers_are_not_double_compressed(tmp_path, compressed):
    source = docker_archive(tmp_path / "docker.tar", compressed=compressed)
    path, trust, _, _ = runtime_package(tmp_path / "package", source=source)
    validate_runtime(path, verify(path, trust).manifest)


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": 2},
        {"schema_version": True},
        {"image_digest": "example:latest"},
        {"platform": "linux/386"},
        {"platform": "https://registry/image"},
        {"engine": "shell"},
        {"command": "rm -rf /"},
        {"privileged": True},
        {"mounts": ["/var/run/docker.sock"]},
        {"health_port": 5432},
        {"health_contract": "http://169.254.169.254/latest"},
        {"image_url": "https://registry/image"},
        {"env": {"DB_PASSWORD": "private-payload"}},
    ],
)
def test_runtime_contract_rejects_arbitrary_authority(tmp_path, changes):
    path, trust, _, contract = runtime_package(tmp_path / "package", transform=mutate_contract(changes))
    with pytest.raises(ValidationError):
        RuntimeContract.model_validate(contract | changes)
    checked = verify(path, trust)  # still a valid inert V1 package, never silently executable
    with pytest.raises(PackageError):
        validate_runtime(path, checked.manifest)


@pytest.mark.parametrize(
    "changes",
    [
        {"image_digest": "sha256:" + "0" * 64},
        {"config_digest": "sha256:" + "0" * 64},
        {"platform": "linux/arm64"},
    ],
)
def test_signed_but_inconsistent_runtime_binding_is_rejected(tmp_path, changes):
    path, trust, _, _ = runtime_package(tmp_path / "package", transform=mutate_contract(changes))
    with pytest.raises(PackageError):
        validate_runtime(path, verify(path, trust).manifest)


@pytest.mark.parametrize(
    "kind", ["url", "multiple", "unreferenced", "missing", "config", "layer", "layout", "index-type"]
)
def test_nested_oci_inventory_is_closed_and_hash_checked(tmp_path, kind):
    def transform(root):
        oci = root / PREFIX
        index_path = oci / "index.json"
        index = json.loads(index_path.read_text())
        if kind == "url":
            index["manifests"][0]["urls"] = ["http://169.254.169.254/"]
        elif kind == "multiple":
            index["manifests"].append(copy.deepcopy(index["manifests"][0]))
        elif kind == "unreferenced":
            (root / "payload/resources/extra.txt").write_text("extra")
        elif kind == "missing":
            (oci / ("blobs/sha256/" + index["manifests"][0]["digest"][7:])).unlink()
        elif kind in {"config", "layer"}:
            manifest = json.loads((oci / ("blobs/sha256/" + index["manifests"][0]["digest"][7:])).read_text())
            digest = manifest["config"]["digest"] if kind == "config" else manifest["layers"][0]["digest"]
            (oci / ("blobs/sha256/" + digest[7:])).write_bytes(b"modified")
        elif kind == "layout":
            (oci / "oci-layout").write_text('{"imageLayoutVersion":"2.0.0"}')
        index_path.write_text(json.dumps([] if kind == "index-type" else index))

    path, trust, _, _ = runtime_package(tmp_path / "package", transform=transform)
    with pytest.raises(PackageError):
        validate_runtime(path, verify(path, trust).manifest)


def test_oci_gzip_expansion_has_a_separate_bound(tmp_path, monkeypatch):
    path, trust, _, _ = runtime_package(tmp_path / "package")
    checked = verify(path, trust)
    monkeypatch.setattr(artifacts, "Limits", lambda: SimpleNamespace(file=33554432, total=100))
    with pytest.raises(PackageError, match="oci_expansion_limit"):
        validate_runtime(path, checked.manifest)


@pytest.mark.parametrize(
    "raw", [b"[]", b'{"a":1,"a":2}', b'{"float":0.2}', b'{"x":NaN}', b"[" * 20 + b"0" + b"]" * 20]
)
def test_oci_json_is_bounded_and_unambiguous(raw):
    with pytest.raises((PackageError, ValueError)):
        artifacts.oci_json(raw)


def test_oci_escaped_newline_history_does_not_change_xpkg_canonical_contract():
    assert (
        artifacts.oci_json(b'{"history":[{"created_by":"RUN a\\nb"}]}')["history"][0]["created_by"]
        == "RUN a\nb"
    )
    from app.domains.packages.codec import load_json

    with pytest.raises(PackageError):
        load_json(b'{"x":"a\\nb"}')


def test_converter_refuses_nonregular_docker_archive_entries(tmp_path):
    from scripts.runtime_artifact import convert

    path = tmp_path / "evil.tar"
    with tarfile.open(path, "w") as archive:
        entry = tarfile.TarInfo("link")
        entry.type, entry.linkname = tarfile.SYMTYPE, "/etc/shadow"
        archive.addfile(entry, io.BytesIO())
    with pytest.raises(PackageError):
        convert(path, tmp_path / "out")


@pytest.mark.parametrize("kind", ["huge", "device", "traversal"])
def test_layer_logical_size_and_special_tar_members_are_rejected(kind):
    import io
    import tarfile

    from app.domains.deployments.artifacts import layer_structure
    from app.domains.packages.codec import PackageError

    member = tarfile.TarInfo("../escape" if kind == "traversal" else "file")
    if kind == "huge":
        member.size = 2**40
    elif kind == "device":
        member.type = tarfile.CHRTYPE
    stream = io.BytesIO(member.tobuf() + b"\0" * 10240)
    with pytest.raises(PackageError):
        layer_structure(stream)
