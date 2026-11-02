"""Disposable package fixtures; private keys never leave pytest's private temporary directory."""

import hashlib
import json

from app.domains.packages.schema import TrustKey, TrustStore
from scripts.xpkg import keygen, pack


def manifest_data(publisher="test-publisher", module="test-module", namespace="testnet", version="1.0.0"):
    return {
        "schema_version": 1,
        "module": {"id": module, "name": "Тестовый модуль", "version": version, "type": "standard"},
        "publisher": {"id": publisher},
        "compatibility": {"core": ">=0.1.0 <0.2.0", "module_protocol": 1},
        "permissions": {
            "namespace": namespace,
            "definitions": [
                {"key": namespace + ".objects.read", "description": "Чтение объектов", "scope": "company"}
            ],
        },
        "dependencies": [],
        "artifacts": [
            {
                "path": "payload/resources/example.txt",
                "size": 5,
                "sha256": hashlib.sha256(b"hello").hexdigest(),
            }
        ],
    }


def package(tmp_path, *, data=None, payload=b"hello"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "distribution"
    (source / "resources").mkdir(parents=True)
    (source / "resources/example.txt").write_bytes(payload)
    template = tmp_path / "manifest.json"
    data = data or manifest_data()
    template.write_text(json.dumps(data), encoding="utf-8")
    private, public = tmp_path / "private.key", tmp_path / "public.txt"
    keygen(private, public)
    output = tmp_path / "module.xpkg"
    report = pack(source, template, private, data["publisher"]["id"], "test-key", output)
    trust = TrustStore(
        schema_version=1,
        keys=[
            TrustKey(
                publisher_id=data["publisher"]["id"],
                key_id="test-key",
                public_key=public.read_text().strip(),
                namespaces=[data["permissions"]["namespace"]],
            )
        ],
    )
    return output, trust, report
