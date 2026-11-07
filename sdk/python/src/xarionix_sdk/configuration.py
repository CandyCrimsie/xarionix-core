"""A closed, non-secret configuration for the stateful V1 example."""

import os
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from .validation import decode, json_bytes


@dataclass(frozen=True)
class Configuration:
    installation_id: UUID
    installation_generation: int
    module_id: str
    package_version: str
    title: str
    max_items_per_company: int
    storage_max_bytes: int
    expected_schema_version: int = 0
    target_schema_version: int = 1
    allow_migration: bool = False

    @classmethod
    def parse(cls, value: Any) -> "Configuration":
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "installation_id",
            "installation_generation",
            "module_id",
            "package_version",
            "public",
            "approved",
            "runtime",
        }:
            raise ValueError("configuration_invalid")
        json_bytes(value, 4096)
        public, approved, runtime = value["public"], value["approved"], value["runtime"]
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or type(value["installation_generation"]) is not int
            or value["installation_generation"] < 1
            or not isinstance(value["module_id"], str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", value["module_id"])
            or not isinstance(value["package_version"], str)
            or not re.fullmatch(r"\d+\.\d+\.\d+", value["package_version"])
            or not isinstance(public, dict)
            or set(public) != {"title"}
            or not isinstance(public["title"], str)
            or not 1 <= len(public["title"]) <= 80
            or not isinstance(approved, dict)
            or set(approved) != {"max_items_per_company"}
            or type(approved["max_items_per_company"]) is not int
            or not 1 <= approved["max_items_per_company"] <= 1000
            or not isinstance(runtime, dict)
            or not {"storage_max_bytes"} <= set(runtime)
            or set(runtime)
            - {"storage_max_bytes", "expected_schema_version", "target_schema_version", "allow_migration"}
            or type(runtime["storage_max_bytes"]) is not int
            or not 1048576 <= runtime["storage_max_bytes"] <= 67108864
        ):
            raise ValueError("configuration_invalid")
        expected, target, migration = (
            runtime.get("expected_schema_version", 0),
            runtime.get("target_schema_version", 1),
            runtime.get("allow_migration", False),
        )
        if (
            type(expected) is not int
            or not 0 <= expected <= 128
            or type(target) is not int
            or not 1 <= target <= 128
            or type(migration) is not bool
            or (migration and not expected < target)
        ):
            raise ValueError("configuration_schema_invalid")
        return cls(
            UUID(value["installation_id"]),
            value["installation_generation"],
            value["module_id"],
            value["package_version"],
            public["title"],
            approved["max_items_per_company"],
            runtime["storage_max_bytes"],
            expected,
            target,
            migration,
        )

    @classmethod
    def load(cls) -> "Configuration":
        raw = os.environ.get("XARIONIX_MODULE_CONFIGURATION", "").encode()
        return cls.parse(decode(raw, 4096))
