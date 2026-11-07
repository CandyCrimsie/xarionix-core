import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from package_helpers import manifest_data
from runtime_helpers import runtime_package
from xarionix_sdk import Module, ModuleContext, ModuleError
from xarionix_sdk.validation import check_schema, decode

from app.domains.deployments.artifacts import validate_runtime
from app.domains.module_gateway.contracts import APIContract
from app.domains.module_sdk.contracts import SDK_RESOURCE, SDKContract
from app.domains.packages.archive import verify
from app.domains.packages.schema import Manifest

SDK = Path(__file__).resolve().parents[1] / "sdk/python/src"


def context(**changes):
    return {
        "schema_version": 1,
        "request_id": str(uuid4()),
        "company_id": str(uuid4()),
        "actor_id": str(uuid4()),
        "operation_id": "objects-read",
        "permission": "testnet.objects.read",
        "installation_id": str(uuid4()),
        "installation_generation": 1,
        "deployment_generation": 2,
        "deadline": (datetime.now(UTC) + timedelta(seconds=10)).isoformat(),
    } | changes


def application():
    module = Module(id="test-module", namespace="testnet", version="1.0.0")

    @module.operation(
        "objects-read",
        permission="testnet.objects.read",
        response={
            "type": "object",
            "properties": {"company_id": {"type": "string", "maxLength": 36}},
            "required": ["company_id"],
            "additionalProperties": False,
        },
    )
    async def read(ctx, payload):
        assert isinstance(ctx, ModuleContext) and isinstance(ctx.company_id, UUID)
        return {"company_id": str(ctx.company_id)}

    return module


def test_sdk_is_compatible_with_signed_sprint_6a_contract():
    module = application()
    manifest = manifest_data(module="test-module", namespace="testnet")
    module.check(manifest)
    contract = APIContract.model_validate(module.contract())
    contract.bound(Manifest.model_validate(manifest))
    assert module.metadata()["api_contract"] == contract.model_dump()
    assert module.metadata()["package_version"] == "1.0.0"


async def test_sdk_context_and_company_data_are_exact():
    module = application()
    a, b = context(), context()
    assert await module.dispatch("objects-read", {"context": a, "body": {}}) == {
        "company_id": a["company_id"]
    }
    assert await module.dispatch("objects-read", {"context": b, "body": {}}) == {
        "company_id": b["company_id"]
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"actor_id": "bad"},
        {"company_id": "../other"},
        {"installation_generation": True},
        {"deployment_generation": 0},
        {"owner": True},
        {"operation_id": "../read"},
        {"permission": "core.users.read"},
        {"deadline": datetime.now(UTC).isoformat()},
        {"deadline": datetime.now().isoformat()},
        {"deadline": (datetime.now(UTC) + timedelta(seconds=60)).isoformat()},
    ],
)
async def test_sdk_rejects_untrusted_or_expired_context(changes):
    with pytest.raises(ModuleError):
        await application().dispatch("objects-read", {"context": context(**changes), "body": {}})


@pytest.mark.parametrize(
    "permission", ["core.users.read", "other.objects.read", "testnet.read", "testnet.admin.*"]
)
def test_sdk_cannot_declare_core_or_other_namespace(permission):
    with pytest.raises(ValueError):
        application().operation("bad", permission=permission)


def test_sdk_duplicate_registration_and_runtime_expansion_are_rejected():
    module = application()
    with pytest.raises(ValueError):
        module.operation("objects-read", permission="testnet.objects.read")
    module.contract()
    with pytest.raises(ValueError):
        module.operation("late", permission="testnet.objects.write")


@pytest.mark.parametrize("change", ["version", "namespace", "permission", "protocol", "handler"])
def test_sdk_rejects_manifest_and_registered_contract_drift(change):
    module = application()
    manifest = manifest_data(module="test-module", namespace="testnet")
    api = module.contract()
    if change == "version":
        manifest["module"]["version"] = "2.0.0"
    elif change == "namespace":
        manifest["permissions"]["namespace"] = "other"
    elif change == "permission":
        manifest["permissions"]["definitions"] = []
    elif change == "protocol":
        manifest["compatibility"]["module_protocol"] = True
    else:
        api["operations"][0]["id"] = "absent"
    with pytest.raises(ValueError, match="mismatch"):
        module.check(manifest, api)


@pytest.mark.parametrize(
    "schema",
    [
        {"$ref": "https://untrusted.invalid/schema"},
        {"type": "object", "additionalProperties": True},
        {"type": "string"},
        {"type": "array", "maxItems": 1000000},
        {"type": "object", "properties": {}, "additionalProperties": False, "required": ["absent"]},
    ],
)
def test_sdk_schemas_are_closed_and_bounded(schema):
    with pytest.raises(ValueError):
        check_schema(schema)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b"{}" * 40000])
def test_sdk_json_decoding_rejects_duplicates_and_invalid_bounds(raw):
    with pytest.raises(ValueError):
        decode(raw)


async def test_sdk_rejects_unknown_request_fields_and_sanitizes_handler_exception():
    module = application()
    with pytest.raises(ModuleError) as error:
        await module.dispatch("objects-read", {"context": context(), "body": {"private": "value"}})
    assert str(error.value) == "operation_failed"
    assert "value" not in str(error.value)


def test_sdk_metadata_is_detached_from_mutable_schema_inputs():
    module = application()
    metadata = module.metadata()
    metadata["schemas"]["objects-read"]["response"]["properties"].clear()
    assert module.metadata()["schemas"]["objects-read"]["response"]["properties"]


def test_sdk_cli_generates_real_metadata(tmp_path):
    source = tmp_path / "example.py"
    source.write_text(
        "from xarionix_sdk import Module\nmodule = Module(id='test-module', namespace='testnet', version='1.0.0')\n"
        "@module.operation('objects-read', permission='testnet.objects.read')\n"
        "async def read(ctx, payload): return {}\n"
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(manifest_data(module="test-module", namespace="testnet")))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "xarionix_sdk",
            "metadata",
            "example:module",
            "--manifest",
            str(manifest),
            "--output",
            str(tmp_path / "resources"),
        ],
        cwd=tmp_path,
        env=os.environ | {"PYTHONPATH": str(SDK)},
        capture_output=True,
        check=True,
    )
    assert b"Traceback" not in result.stderr
    api = json.loads((tmp_path / "resources/module-api-v1.json").read_text())
    assert APIContract.model_validate(api).operations[0].id == "objects-read"


def test_sdk_metadata_is_verified_by_real_signed_xpkg_and_oci_validator(tmp_path):
    module = application()

    def metadata(distribution):
        resources = distribution / "payload/resources"
        (resources / "module-api-v1.json").write_text(json.dumps(module.contract()))
        (resources / "module-sdk-v1.json").write_text(json.dumps(module.metadata()))

    path, trust, _, runtime = runtime_package(
        tmp_path, module="test-module", namespace="testnet", transform=metadata
    )
    result = verify(path, trust)
    assert result.sdk_contract == module.metadata()
    assert any(a.path == SDK_RESOURCE for a in result.manifest.artifacts)
    assert validate_runtime(path, result.manifest).image_digest == runtime["image_digest"]


@pytest.mark.parametrize("mutation", ["version", "namespace", "handler", "permission", "schema", "protocol"])
def test_signed_sdk_declaration_rejects_drift(mutation):
    module = application()
    metadata = module.metadata()
    if mutation == "version":
        metadata["package_version"] = "2.0.0"
    elif mutation == "namespace":
        metadata["namespace"] = "other"
    elif mutation == "handler":
        metadata["schemas"]["absent"] = metadata["schemas"].pop("objects-read")
    elif mutation == "permission":
        metadata["api_contract"]["operations"][0]["permission"] = "core.users.read"
    elif mutation == "schema":
        metadata["schemas"]["objects-read"]["request"] = {"$ref": "https://untrusted.invalid"}
    else:
        metadata["gateway_protocol"] = "unknown"
    with pytest.raises(ValueError):
        value = SDKContract.model_validate(metadata)
        value.bound(
            Manifest.model_validate(manifest_data(module="test-module", namespace="testnet")),
            APIContract.model_validate(module.contract()),
        )
