"""XPKG-CJSON-1: explicitly restricted canonical JSON, not an RFC8785 claim."""

import base64
import hashlib
import json
import unicodedata
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.domains.packages.schema import Envelope

DOMAIN = b"XARIONIX-XPKG\x00SIGNATURE\x00V1\x00"


class PackageError(ValueError):
    """Only stable bounded codes, never untrusted input or paths, cross the API/log boundary."""


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise PackageError("duplicate_json_key")
        result[key] = value
    return result


def check_json(value: Any, depth: int = 0) -> None:
    if depth > 16:
        raise PackageError("json_depth_limit")
    if isinstance(value, str):
        if (
            len(value) > 4096
            or unicodedata.normalize("NFC", value) != value
            or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
        ):
            raise PackageError("invalid_json_string")
    elif isinstance(value, bool) or value is None:
        pass
    elif isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise PackageError("json_integer_limit")
    elif isinstance(value, list):
        if len(value) > 2048:
            raise PackageError("json_collection_limit")
        for item in value:
            check_json(item, depth + 1)
    elif isinstance(value, dict):
        if len(value) > 1024:
            raise PackageError("json_collection_limit")
        for key, item in value.items():
            check_json(key, depth + 1)
            check_json(item, depth + 1)
    else:
        raise PackageError("json_type_forbidden")


def canonical(value: Any) -> bytes:
    check_json(value)
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def load_json(data: bytes, limit: int = 256 * 1024) -> Any:
    if len(data) > limit:
        raise PackageError("json_size_limit")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
        check_json(value)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        if isinstance(error, PackageError):
            raise
        raise PackageError("invalid_json") from None


def decode(value: str, size: int) -> bytes:
    try:
        result = base64.b64decode(value, validate=True)
    except ValueError:
        raise PackageError("invalid_base64") from None
    if len(result) != size or base64.b64encode(result).decode() != value:
        raise PackageError("invalid_key_or_signature_size")
    return result


def fingerprint(public_key: str) -> str:
    return hashlib.sha256(decode(public_key, 32)).hexdigest()


def signed_bytes(manifest: Any, publisher: str, key_id: str) -> bytes:
    return DOMAIN + canonical(
        {
            "schema_version": 1,
            "algorithm": "Ed25519",
            "publisher_id": publisher,
            "key_id": key_id,
            "manifest": manifest,
        }
    )


def sign(manifest: Any, key: Ed25519PrivateKey, publisher: str, key_id: str) -> Envelope:
    signature = key.sign(signed_bytes(manifest, publisher, key_id))
    return Envelope(
        schema_version=1,
        algorithm="Ed25519",
        publisher_id=publisher,
        key_id=key_id,
        signature=base64.b64encode(signature).decode(),
    )


def verify_signature(manifest: Any, envelope: Envelope, public_key: str) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(decode(public_key, 32)).verify(
            decode(envelope.signature, 64), signed_bytes(manifest, envelope.publisher_id, envelope.key_id)
        )
    except (InvalidSignature, ValueError):
        raise PackageError("signature_invalid") from None
