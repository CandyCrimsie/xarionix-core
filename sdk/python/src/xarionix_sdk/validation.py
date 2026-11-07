"""Bounded JSON and a deliberately closed JSON-schema subset, with no remote refs."""

import json
import math
from typing import Any


def json_bytes(value: Any, maximum: int = 65536) -> bytes:
    budget = 10000

    def visit(item: Any, depth: int) -> None:
        nonlocal budget
        budget -= 1
        if budget < 0 or depth > 16:
            raise ValueError("json_limit")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("json_invalid")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif item is not None and type(item) not in {str, int, float, bool}:
            raise ValueError("json_invalid")
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("json_invalid")

    visit(value, 0)
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    if len(raw) > maximum:
        raise ValueError("json_limit")
    return raw


def decode(raw: bytes, maximum: int = 65536) -> Any:
    if not 1 <= len(raw) <= maximum:
        raise ValueError("json_limit")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=pairs)
    json_bytes(value, maximum)
    return value


def check_schema(schema: Any, depth: int = 0) -> None:
    if depth > 8 or not isinstance(schema, dict):
        raise ValueError("schema_invalid")
    allowed = {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "minimum",
        "maximum",
        "enum",
    }
    kind = schema.get("type")
    if set(schema) - allowed or kind not in {
        "object",
        "array",
        "string",
        "integer",
        "number",
        "boolean",
        "null",
    }:
        raise ValueError("schema_unsupported")
    json_bytes(schema, 16384)
    if kind == "object":
        props = schema.get("properties", {})
        required = schema.get("required", [])
        if (
            schema.get("additionalProperties") is not False
            or not isinstance(props, dict)
            or len(props) > 64
            or not isinstance(required, list)
            or len(required) != len(set(required))
            or not set(required) <= set(props)
        ):
            raise ValueError("schema_object_must_be_closed")
        for child in props.values():
            check_schema(child, depth + 1)
    if kind == "array":
        if type(schema.get("maxItems")) is not int or not 0 <= schema["maxItems"] <= 1000:
            raise ValueError("schema_array_bound_required")
        check_schema(schema.get("items"), depth + 1)
    if kind == "string" and (
        type(schema.get("maxLength")) is not int or not 0 <= schema["maxLength"] <= 65536
    ):
        raise ValueError("schema_string_bound_required")
    for key in {"minLength", "maxLength", "minItems", "maxItems"} & set(schema):
        if type(schema[key]) is not int or schema[key] < 0:
            raise ValueError("schema_bound_invalid")
    for key in {"minimum", "maximum"} & set(schema):
        if type(schema[key]) is not int:
            raise ValueError("schema_bound_invalid")
    if "enum" in schema and (not isinstance(schema["enum"], list) or not 1 <= len(schema["enum"]) <= 64):
        raise ValueError("schema_enum_invalid")


def validate(value: Any, schema: dict[str, Any]) -> None:
    kind = schema["type"]
    types: dict[str, type[Any] | tuple[type[Any], ...]] = {
        "object": dict,
        "array": list,
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "null": type(None),
    }
    expected = types[kind]
    if not isinstance(value, expected) or (kind in {"integer", "number"} and isinstance(value, bool)):
        raise ValueError("schema_type")
    if "enum" in schema and not any(type(value) is type(item) and value == item for item in schema["enum"]):
        raise ValueError("schema_enum")
    if kind == "object":
        props = schema.get("properties", {})
        if set(value) - set(props) or not set(schema.get("required", [])) <= set(value):
            raise ValueError("schema_fields")
        for key, item in value.items():
            validate(item, props[key])
    elif kind == "array":
        if not schema.get("minItems", 0) <= len(value) <= schema["maxItems"]:
            raise ValueError("schema_bound")
        for item in value:
            validate(item, schema["items"])
    elif kind == "string":
        if not schema.get("minLength", 0) <= len(value) <= schema["maxLength"]:
            raise ValueError("schema_bound")
    elif kind in {"number", "integer"}:
        if (
            not math.isfinite(value)
            or value < schema.get("minimum", -math.inf)
            or value > schema.get("maximum", math.inf)
        ):
            raise ValueError("schema_bound")
