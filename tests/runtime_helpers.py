"""Signed disposable OCI fixtures. Real images can use the same Docker-save conversion path."""

import gzip
import hashlib
import io
import json
import tarfile

from package_helpers import manifest_data

from app.domains.deployments.artifacts import RUNTIME
from app.domains.packages.schema import TrustKey, TrustStore
from scripts.runtime_artifact import convert
from scripts.xpkg import keygen, pack


def docker_archive(path, *, compressed=False):
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as archive:
        info = tarfile.TarInfo("hello.txt")
        info.size = 5
        archive.addfile(info, io.BytesIO(b"hello"))
    data = layer.getvalue()
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {"User": "10001:10001", "Cmd": ["/app/hello"]},
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(data).hexdigest()]},
            "history": [{"created_by": "RUN example\n# build history, not executable Core input"}],
        }
    ).encode()
    with tarfile.open(path, "w") as archive:
        for name, content in {
            "config.json": config,
            "layer/layer.tar": gzip.compress(data, mtime=0) if compressed else data,
            "manifest.json": json.dumps(
                [{"Config": "config.json", "Layers": ["layer/layer.tar"], "RepoTags": ["example:1.0.0"]}]
            ).encode(),
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return path


def runtime_package(
    folder,
    *,
    source=None,
    transform=None,
    module="hello-runtime",
    namespace="hello",
    publisher="test-publisher",
    version="1.0.0",
    key=None,
    manifest=None,
):
    folder.mkdir(parents=True, exist_ok=True)
    source = source or docker_archive(folder / "image.tar")
    distribution = folder / "distribution"
    contract = convert(source, distribution)
    if transform:
        transform(distribution)
    data = manifest or manifest_data(module=module, namespace=namespace, publisher=publisher, version=version)
    template = folder / "manifest.json"
    template.write_text(json.dumps(data))
    if key is None:
        key = folder / "private.key"
        public = keygen(key, folder / "public.txt")["public_key"]
    else:
        import base64

        from scripts.xpkg import load_key

        public = base64.b64encode(load_key(key).public_key().public_bytes_raw()).decode()
    output = folder / "runtime.xpkg"
    report = pack(distribution / "payload", template, key, publisher, "test-key", output)
    trust = TrustStore(
        schema_version=1,
        keys=[TrustKey(publisher_id=publisher, key_id="test-key", public_key=public, namespaces=[namespace])],
    )
    return output, trust, report, contract


def mutate_contract(values):
    def transform(distribution):
        path = distribution / RUNTIME
        path.write_text(json.dumps(json.loads(path.read_text()) | values))

    return transform
