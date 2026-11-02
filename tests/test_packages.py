import base64
import copy
import hashlib
import json
import stat
import subprocess
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from package_helpers import manifest_data, package
from pydantic import ValidationError

from app.domains.packages.archive import Limits, verify
from app.domains.packages.codec import PackageError, canonical, decode, load_json, sign, verify_signature
from app.domains.packages.reports import dependencies, diff
from app.domains.packages.schema import Manifest, TrustStore, safe_path
from app.domains.packages.semver import Range, Version
from app.domains.packages.storage import Storage
from scripts.xpkg import info, keygen, load_key, pack


def rewrite(path, transform):
    with zipfile.ZipFile(path) as archive:
        entries = [(entry.filename, archive.read(entry)) for entry in archive.infolist()]
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in transform(entries):
            archive.writestr(info(name), data)


@pytest.mark.parametrize("value", ["0.1.0", "10.20.30", "1.0.0-alpha.1", "1.0.0+build.007", "1.2.3-0+abc"])
def test_semver_accepts_real_versions(value):
    Version.parse(value)


@pytest.mark.parametrize(
    "value", ["1", "1.2", "v1.2.3", "01.2.3", "1.02.3", "1.2.3-01", "1.2.3-", "1.2.3+", " 1.2.3", "1.2.3.4"]
)
def test_semver_rejects_non_semver(value):
    with pytest.raises(ValueError):
        Version.parse(value)


def test_semver_spec_precedence_and_build_metadata():
    ordered = "1.0.0-alpha 1.0.0-alpha.1 1.0.0-alpha.beta 1.0.0-beta 1.0.0-beta.2 1.0.0-beta.11 1.0.0-rc.1 1.0.0 2.0.0 10.0.0".split()
    assert sorted(reversed([Version.parse(value) for value in ordered])) == [
        Version.parse(v) for v in ordered
    ]
    assert Version.parse("1.0.0+one") == Version.parse("1.0.0+two")


@pytest.mark.parametrize(
    "value",
    [
        "*",
        "^1.0.0",
        "~1.0.0",
        ">=2.0.0 <1.0.0",
        ">1.0.0 <=1.0.0",
        "=1.0.0 =2.0.0",
        ">=1.0.0 || <2.0.0",
        ">=1.0.0  <2.0.0",
        "",
    ],
)
def test_ranges_are_unambiguous_and_noncontradictory(value):
    with pytest.raises(ValueError):
        Range.parse(value)


def test_ranges_do_not_select_prereleases_implicitly():
    assert Range.parse(">=1.0.0 <2.0.0").contains("1.9.9")
    assert not Range.parse(">=1.0.0 <2.0.0").contains("1.1.0-beta")
    assert Range.parse(">=1.1.0-alpha <1.2.0").contains("1.1.0-beta")
    assert Range.parse(">1.0.0 <1.0.1-beta").contains("1.0.1-alpha")
    with pytest.raises(ValueError, match="empty_version_range"):
        Range.parse(">1.0.0 <1.0.1")


@pytest.mark.parametrize(
    "changes", [{"extra": True}, {"schema_version": 2}, {"schema_version": True}, {"schema_version": "1"}]
)
def test_manifest_is_strict(changes):
    with pytest.raises(ValidationError):
        Manifest.model_validate(manifest_data() | changes)


def test_required_fields_semantics_and_protected_namespaces():
    data = manifest_data()
    del data["artifacts"]
    with pytest.raises(ValidationError):
        Manifest.model_validate(data)
    data = manifest_data(namespace="core")
    with pytest.raises(ValidationError):
        Manifest.model_validate(data)
    data = manifest_data()
    data["permissions"]["definitions"][0]["key"] = "billing.money.read"
    with pytest.raises(ValidationError):
        Manifest.model_validate(data)
    data = manifest_data()
    data["dependencies"] = [
        {"module_id": "test-module", "publisher_id": "test-publisher", "version": "=1.0.0"}
    ]
    with pytest.raises(ValidationError):
        Manifest.model_validate(data)


@pytest.mark.parametrize(
    "value",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":0.1}',
        b'{"a":9007199254740992}',
        b'"\\ud800"',
        b'"a\\n"',
        b'"e\\u0301"',
        b"[" * 30 + b"0" + b"]" * 30,
    ],
)
def test_canonical_json_rejects_ambiguous_or_unbounded_values(value):
    with pytest.raises(PackageError):
        load_json(value)


def test_canonical_has_fixed_utf8_bytes_and_stable_key_order():
    assert canonical({"z": 2, "a": "Тест"}) == b'{"a":"\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82","z":2}'
    with pytest.raises(PackageError):
        load_json(b"x" * 4097, 4096)


def test_fixed_public_rfc8032_seed_vector_is_not_a_production_trust_anchor():
    from app.domains.packages.codec import signed_bytes
    from app.domains.packages.schema import Envelope

    vector = json.loads((Path(__file__).parent / "fixtures/xpkg-v1-vector.json").read_text())
    manifest = vector["manifest"]
    assert canonical(manifest).hex() == vector["canonical_utf8_hex"]
    assert hashlib.sha256(canonical(manifest)).hexdigest() == vector["manifest_sha256"]
    assert (
        hashlib.sha256(signed_bytes(manifest, "test-publisher", "test-key")).hexdigest()
        == vector["signed_bytes_sha256"]
    )
    envelope = Envelope.model_validate(vector["envelope"])
    verify_signature(manifest, envelope, vector["public_key"])
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["test_only_seed_rfc8032"]))
    assert sign(manifest, key, "test-publisher", "test-key") == envelope


def test_deflate_transport_is_verified_and_compressed_trailing_data_is_rejected(tmp_path):
    path, trust, _ = package(tmp_path)
    with zipfile.ZipFile(path) as archive:
        entries = [(entry.filename, archive.read(entry)) for entry in archive.infolist()]
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries:
            entry = info(name)
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    assert verify(path, trust).core_compatible

    # Insert bytes into the FINAL compressed member and update both directory and local lengths,
    # so this is not just a trivial inconsistent ZIP. zipfile normally ignores this unused data.
    import struct

    raw = bytearray(path.read_bytes())
    end_offset = len(raw) - 22
    directory = struct.unpack_from("<I", raw, end_offset + 16)[0]
    cursor = directory
    last = cursor
    while raw[cursor : cursor + 4] == b"PK\x01\x02":
        last = cursor
        name_length, extra_length, comment_length = struct.unpack_from("<3H", raw, cursor + 28)
        cursor += 46 + name_length + extra_length + comment_length
    local = struct.unpack_from("<I", raw, last + 42)[0]
    compressed = struct.unpack_from("<I", raw, last + 20)[0]
    struct.pack_into("<I", raw, local + 18, compressed + 4)
    struct.pack_into("<I", raw, last + 20, compressed + 4)
    struct.pack_into("<I", raw, end_offset + 16, directory + 4)
    raw[directory:directory] = b"junk"
    path.write_bytes(raw)
    with pytest.raises(PackageError, match="unused_compressed_data"):
        verify(path, trust)


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../file",
        "payload/../etc",
        "payload//x",
        "C:/x",
        "a\\b",
        "payload/a\x00b",
        "payload/a.",
        "payload/CON",
        "payload/é.txt",
        "payload/./a",
        "a/" * 13 + "b",
    ],
)
def test_paths_cannot_be_interpreted_differently(path):
    with pytest.raises(ValueError):
        safe_path(path)


def test_offline_pack_verify_deterministic_and_no_execution(tmp_path):
    path, trust, report = package(tmp_path)
    result = verify(path, trust)
    assert result.core_compatible and result.report()["execution_supported"] is False
    second = tmp_path / "second.xpkg"
    pack(
        tmp_path / "distribution",
        tmp_path / "manifest.json",
        tmp_path / "private.key",
        "test-publisher",
        "test-key",
        second,
    )
    assert second.read_bytes() == path.read_bytes()
    assert report["package_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert stat.S_IMODE((tmp_path / "private.key").stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        pack(
            tmp_path / "distribution",
            tmp_path / "manifest.json",
            tmp_path / "private.key",
            "test-publisher",
            "test-key",
            second,
        )


@pytest.mark.parametrize(
    "change", ["publisher", "key", "revoked_key", "revoked_publisher", "namespace", "wrong_key"]
)
def test_external_trust_is_mandatory(tmp_path, change):
    path, trust, _ = package(tmp_path)
    data = trust.model_dump()
    match change:
        case "publisher":
            data["keys"][0]["publisher_id"] = "foreign-publisher"
        case "key":
            data["keys"][0]["key_id"] = "unknown-key"
        case "revoked_key":
            data["keys"][0]["status"] = "revoked"
        case "revoked_publisher":
            data["keys"][0]["publisher_status"] = "revoked"
        case "namespace":
            data["keys"][0]["namespaces"] = ["other"]
        case "wrong_key":
            data["keys"][0]["public_key"] = base64.b64encode(
                Ed25519PrivateKey.generate().public_key().public_bytes_raw()
            ).decode()
    with pytest.raises(PackageError):
        verify(path, TrustStore.model_validate(data))


@pytest.mark.parametrize(
    "change",
    [
        "payload",
        "manifest",
        "missing",
        "extra",
        "duplicate",
        "case_collision",
        "traversal",
        "symlink",
        "unknown_compression",
        "appended",
        "prepended",
        "local_mismatch",
        "zip64_extra",
        "encryption",
    ],
)
def test_malicious_archives_are_rejected(tmp_path, change):
    path, trust, _ = package(tmp_path)
    if change in {"payload", "manifest", "missing", "extra", "duplicate", "case_collision", "traversal"}:

        def transform(entries):
            if change == "payload":
                return [(n, b"wrong" if n.startswith("payload/") else d) for n, d in entries]
            if change == "manifest":
                return [
                    (n, d.replace(b'"standard"', b'"autonomous"') if n == "manifest.json" else d)
                    for n, d in entries
                ]
            if change == "missing":
                return entries[:-1]
            name = {
                "extra": "payload/resources/hidden.py",
                "duplicate": entries[-1][0],
                "case_collision": entries[-1][0].upper(),
                "traversal": "../escape",
            }[change]
            return [*entries, (name, b"hello")]

        rewrite(path, transform)
    elif change == "symlink":
        with zipfile.ZipFile(path, "a") as archive:
            entry = info("payload/resources/link")
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, b"/etc/passwd")
    elif change == "unknown_compression":
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("payload/resources/hidden", b"hello", compress_type=zipfile.ZIP_BZIP2)
    else:
        raw = bytearray(path.read_bytes())
        if change == "appended":
            raw += b"unlisted"
        elif change == "prepended":
            raw = bytearray(b"executable" + raw)
        elif change == "local_mismatch":
            raw[8] = 8
        elif change == "zip64_extra":
            raw[28] = 20
        elif change == "encryption":
            raw[6] = 1
        path.write_bytes(raw)
    with pytest.raises(PackageError):
        verify(path, trust)
    assert not (tmp_path / "escape").exists()


def test_compression_bomb_and_actual_size_limits(tmp_path):
    path, trust, _ = package(tmp_path)
    with pytest.raises(PackageError):
        verify(path, trust, Limits(package=100))
    with pytest.raises(PackageError):
        verify(path, trust, Limits(file=1))
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", b"x" * 100000)
        archive.writestr("signatures/publisher.json", b"x")
    with pytest.raises(PackageError, match="expansion"):
        verify(path, trust)


@pytest.mark.parametrize("change", ["hash", "size", "extra", "publisher", "algorithm"])
def test_signed_but_inconsistent_inventory_or_envelope_is_rejected(tmp_path, change):
    path, trust, _ = package(tmp_path)
    with zipfile.ZipFile(path) as archive:
        data = load_json(archive.read("manifest.json"))
    if change == "hash":
        data["artifacts"][0]["sha256"] = "0" * 64
    elif change == "size":
        data["artifacts"][0]["size"] = 6
    elif change == "extra":
        data["artifacts"].append(
            {"path": "payload/resources/missing.txt", "size": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        )
    envelope = sign(data, load_key(tmp_path / "private.key"), "test-publisher", "test-key").model_dump()
    if change == "publisher":
        envelope["publisher_id"] = "foreign-publisher"
    elif change == "algorithm":
        envelope["algorithm"] = "HS256"
    rewrite(
        path,
        lambda entries: [
            (
                n,
                canonical(data)
                if n == "manifest.json"
                else canonical(envelope)
                if n == "signatures/publisher.json"
                else d,
            )
            for n, d in entries
        ],
    )
    with pytest.raises(PackageError):
        verify(path, trust)


@pytest.mark.parametrize(
    "field,value",
    [
        ("files", 2),
        ("file", 1),
        ("total", 2),
        ("path_depth", 2),
        ("path_bytes", 10),
        ("manifest", 10),
        ("envelope", 10),
    ],
)
def test_operator_can_reduce_every_archive_dimension(tmp_path, field, value):
    path, trust, _ = package(tmp_path)
    with pytest.raises(PackageError):
        verify(path, trust, Limits(**{field: value}))


@pytest.mark.parametrize(
    "field",
    ["package", "total", "file", "files", "ratio", "path_depth", "path_bytes", "manifest", "envelope"],
)
def test_archive_policy_cannot_raise_caps_or_coerce_types(field):
    maximum = getattr(Limits(), field)
    for value in (maximum + 1, True, 0, "1", 1.5):
        with pytest.raises(ValueError):
            Limits(**{field: value})


def test_settings_policy_and_proxy_contract(settings):
    from scripts.setup import DEFAULTS, nginx

    configured = settings.model_copy(update={"packages_max_path_depth": 3, "packages_max_ratio": 25})
    limits = Limits.configured(configured)
    assert limits.path_depth == 3 and limits.ratio == 25
    config = DEFAULTS | {
        "PUBLIC_URL": "https://core.example.test",
        "KEYCLOAK_PUBLIC_URL": "https://auth.example.test",
    }
    text = nginx(config)
    assert text.count("location = /api/v1/platform/packages") == 1
    assert "proxy_request_buffering off;" in text and "client_max_body_size 128m;" in text
    assert "client_max_body_size 2m;" in text


@pytest.mark.parametrize("worker_failure", [False, True])
async def test_native_cancellation_joins_file_worker_before_cleanup(worker_failure):
    import asyncio
    import threading

    from app.domains.packages.work import file_work

    started, release, cleaned = threading.Event(), threading.Event(), threading.Event()

    def worker():
        started.set()
        assert release.wait(5)
        if worker_failure:
            raise OSError("injected bounded worker failure")
        return 1

    async def operation():
        try:
            await file_work(worker)
        finally:
            cleaned.set()

    task = asyncio.create_task(operation())
    try:
        assert await asyncio.to_thread(started.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        assert not cleaned.is_set()
        task.cancel()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cleaned.is_set()


def test_verification_memory_does_not_scale_with_payload_size(tmp_path):
    import tracemalloc

    path, trust, _ = package(tmp_path, payload=b"x" * (16 * 1024 * 1024))
    tracemalloc.start()
    try:
        verify(path, trust)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 6 * 1024 * 1024


def test_bad_key_signature_and_domain_binding():
    key = Ed25519PrivateKey.generate()
    data = manifest_data()
    envelope = sign(data, key, "test-publisher", "test-key")
    public = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    verify_signature(data, envelope, public)
    with pytest.raises(PackageError, match="signature_invalid"):
        verify_signature(data, envelope.model_copy(update={"key_id": "other-key"}), public)
    with pytest.raises(PackageError):
        decode("!" * 44, 32)


def test_dependencies_do_not_silently_pick_another_publisher_or_newest_version():
    data = manifest_data(module="module-one")
    data["dependencies"] = [
        {"module_id": "module-two", "publisher_id": "test-publisher", "version": ">=1.0.0 <2.0.0"}
    ]
    a = Manifest.model_validate(data)
    bdata = manifest_data(module="module-two")
    b = Manifest.model_validate(bdata)
    assert dependencies(a, [])["items"][0]["state"] == "missing"
    assert dependencies(a, [b])["ready"]
    newer = Manifest.model_validate(manifest_data(module="module-two", version="1.1.0"))
    assert not dependencies(a, [b, newer])["ready"]
    bdata["dependencies"] = [
        {"module_id": "module-one", "publisher_id": "test-publisher", "version": "=1.0.0"}
    ]
    assert dependencies(a, [Manifest.model_validate(bdata)])["cycle_or_complexity_limit"]
    bdata["dependencies"] = [
        {"module_id": "module-three", "publisher_id": "test-publisher", "version": "=1.0.0"}
    ]
    report = dependencies(a, [Manifest.model_validate(bdata)])
    assert not report["ready"] and any(
        item["module_id"] == "module-three" and item["state"] == "missing" for item in report["items"]
    )


def test_packer_rejects_hardlinks_and_private_material_in_distribution(tmp_path):
    from scripts.xpkg import source_file

    root = tmp_path / "distribution"
    root.mkdir()
    original, linked = root / "original.txt", root / "linked.txt"
    original.write_text("test")
    linked.hardlink_to(original)
    with pytest.raises(PackageError, match="hardlink"):
        source_file(root, linked)
    data = manifest_data()
    data["artifacts"][0]["path"] = "payload/resources/publisher.key"
    with pytest.raises(ValidationError):
        Manifest.model_validate(data)


def test_reconcile_rejects_symlink_directory_without_deleting_external_files(tmp_path):
    storage = Storage(tmp_path / "registry")
    external = tmp_path / "external"
    external.mkdir()
    file = external / ("a" * 64 + ".xpkg")
    file.write_bytes(b"unrelated data")
    (storage.root / "sha256" / "aa").symlink_to(external)
    with pytest.raises(PackageError, match="storage_directory_invalid"):
        storage.reconcile(set(), remove=True)
    assert file.exists()


def test_special_input_or_staging_cannot_block_open_before_regular_file_check(tmp_path):
    import os

    from scripts.xpkg import read_file

    fifo = tmp_path / "not-an-archive"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(PackageError):
        verify(fifo, TrustStore(schema_version=1, keys=[]))
    with pytest.raises(PackageError, match="input_not_regular"):
        read_file(fifo, 1024)
    storage = Storage(tmp_path / "registry")
    with pytest.raises(PackageError, match="staging_type_changed"):
        storage.publish(fifo, "a" * 64)
    assert not list((storage.root / "staging").iterdir())


def test_permission_diff_is_informational_and_detects_changed_definitions():
    previous = manifest_data()
    current = copy.deepcopy(previous)
    current["permissions"]["definitions"].append(
        {"key": "testnet.objects.export", "description": "Экспорт", "scope": "company"}
    )
    current["module"]["type"] = "autonomous"
    report = diff(Manifest.model_validate(previous), Manifest.model_validate(current))
    assert report["permissions"]["added"] == ["testnet.objects.export"]
    assert report["runtime_type"]["after"] == "autonomous" and not report["activation_performed"]


def test_cas_dedup_corruption_and_staging_tamper(tmp_path):
    path, trust, report = package(tmp_path / "input")
    storage = Storage(tmp_path / "registry")
    digest = report["package_sha256"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: storage.publish(path, digest), range(2)))
    assert storage.check(digest)
    assert verify(storage.blob(digest), trust).package_sha256 == digest
    path.write_bytes(b"changed-after-validation")
    with pytest.raises(PackageError, match="staging_integrity_changed"):
        storage.publish(path, digest)
    storage.blob(digest).chmod(0o600)
    storage.blob(digest).write_bytes(b"bad")
    assert not storage.check(digest)


def test_cas_limits_concurrency_and_recovery(tmp_path):
    path, _, report = package(tmp_path / "input")
    storage = Storage(tmp_path / "registry")
    first, second = storage.lease(), storage.lease()
    try:
        with pytest.raises(PackageError, match="capacity_busy"):
            storage.lease()
        storage.publish(path, report["package_sha256"])
        stage, stream = storage.temporary()
        stream.close()
        assert stage.exists()
    finally:
        first.close()
        second.close()
    result = storage.reconcile(set(), remove=False)
    assert result["orphan_blobs"] == result["stale_staging"] == 1
    assert storage.reconcile(set(), remove=True)["removed"] == 2


def test_no_key_overwrite_unsafe_permissions_or_symlink_storage(tmp_path):
    private, public = tmp_path / "private.key", tmp_path / "public.txt"
    keygen(private, public)
    with pytest.raises(PackageError, match="exists"):
        keygen(private, public)
    private.chmod(0o644)
    with pytest.raises(PackageError, match="permissions"):
        load_key(private)
    target = tmp_path / "target"
    target.mkdir()
    symlink = tmp_path / "link"
    symlink.symlink_to(target)
    with pytest.raises(PackageError):
        Storage(symlink)


def test_cli_offline_verdict_nonzero_and_no_private_material(tmp_path):
    path, trust, _ = package(tmp_path)
    store = tmp_path / "trust.json"
    store.write_text(trust.model_dump_json())
    command = [
        sys.executable,
        "-m",
        "scripts.xpkg",
        "verify",
        "--package",
        str(path),
        "--trust-store",
        str(store),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0 and json.loads(result.stdout)["ok"]
    assert "PRIVATE KEY" not in result.stdout + result.stderr
    path.write_bytes(b"nope")
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode != 0 and not json.loads(result.stderr)["ok"]
