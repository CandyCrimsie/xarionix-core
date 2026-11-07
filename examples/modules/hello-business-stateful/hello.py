"""Persistent company-scoped example, using the public SDK and owned SQLite only."""

import os
from pathlib import Path
from uuid import uuid4

from xarionix_sdk import Module, ModuleContext, ModuleError
from xarionix_sdk.configuration import Configuration
from xarionix_sdk.storage import Migration, SQLiteStorage, StorageError, StorageSchema
from xarionix_sdk.validation import decode

VERSION = os.environ.get("HELLO_VERSION", "1.1.0")
SCHEMA = int(os.environ.get("HELLO_DATA_SCHEMA", "1"))
MIGRATIONS = (
    Migration(
        1,
        (
            "CREATE TABLE items(id TEXT PRIMARY KEY,company_id TEXT NOT NULL,name TEXT NOT NULL,request_id TEXT NOT NULL UNIQUE)",
            "CREATE INDEX items_company ON items(company_id,id)",
        ),
    ),
    Migration(2, ("ALTER TABLE items ADD COLUMN category TEXT NOT NULL DEFAULT 'general'",)),
)
if SCHEMA not in {1, 2}:
    raise ValueError("unsupported_example_schema")
module = Module(
    id="hello-business",
    namespace="hello",
    version=VERSION,
    storage=StorageSchema(SCHEMA, SCHEMA, SCHEMA, MIGRATIONS[:SCHEMA]),
)
database: SQLiteStorage | None = None
settings: Configuration | None = None
TEXT = {"type": "string", "maxLength": 36}
ITEM = {
    "type": "object",
    "properties": {"id": TEXT, "name": {"type": "string", "maxLength": 100}},
    "required": ["id", "name"],
    "additionalProperties": False,
}
ITEMS = {
    "type": "object",
    "properties": {
        "company_id": TEXT,
        "version": {"type": "string", "maxLength": 120},
        "items": {"type": "array", "items": ITEM, "maxItems": 100},
    },
    "required": ["company_id", "version", "items"],
    "additionalProperties": False,
}


def store() -> SQLiteStorage:
    if database is None:
        raise ModuleError("storage_not_ready")
    return database


@module.operation("items-read", permission="hello.items.read", response=ITEMS)
async def read(ctx: ModuleContext, payload: dict) -> dict:
    with store().transaction() as connection:
        rows = connection.execute(
            "SELECT id,name FROM items WHERE company_id=? ORDER BY id LIMIT 100", (str(ctx.company_id),)
        ).fetchall()
    return {
        "company_id": str(ctx.company_id),
        "version": VERSION,
        "items": [{"id": row[0], "name": row[1]} for row in rows],
    }


@module.operation(
    "items-create",
    permission="hello.items.create",
    request={
        "type": "object",
        "properties": {"name": {"type": "string", "minLength": 1, "maxLength": 100}},
        "required": ["name"],
        "additionalProperties": False,
    },
    response=ITEMS,
)
async def create(ctx: ModuleContext, payload: dict) -> dict:
    if settings is None:
        raise ModuleError("configuration_not_ready")
    with store().transaction() as connection:
        count = connection.execute(
            "SELECT count(*) FROM items WHERE company_id=?", (str(ctx.company_id),)
        ).fetchone()[0]
        if count >= settings.max_items_per_company:
            raise ModuleError("company_item_limit")
        # A repeated transport request cannot insert twice; human retry with a new
        # Core request ID remains an explicit new operation.
        connection.execute(
            "INSERT OR IGNORE INTO items(id,company_id,name,request_id) VALUES(?,?,?,?)",
            (str(uuid4()), str(ctx.company_id), payload["name"], str(ctx.request_id)),
        )
    return await read(ctx, {})


@module.operation(
    "status-read",
    permission="hello.status.read",
    response={
        "type": "object",
        "properties": {
            "company_id": TEXT,
            "version": {"type": "string", "maxLength": 120},
            "data_schema_version": {"type": "integer", "minimum": 1, "maximum": 128},
            "count": {"type": "integer", "minimum": 0, "maximum": 100},
        },
        "required": ["company_id", "version", "data_schema_version", "count"],
        "additionalProperties": False,
    },
)
async def status(ctx: ModuleContext, payload: dict) -> dict:
    with store().transaction() as connection:
        count = connection.execute(
            "SELECT count(*) FROM items WHERE company_id=?", (str(ctx.company_id),)
        ).fetchone()[0]
        version = store().schema_version
    return {
        "company_id": str(ctx.company_id),
        "version": VERSION,
        "data_schema_version": version,
        "count": count,
    }


def main() -> None:
    global database, settings
    settings = Configuration.load()
    module.configure(settings)
    # The same metadata is shipped inside the exact signed OCI image and xpkg inventory.
    if module.metadata() != decode(Path("/app/module-sdk-v1.json").read_bytes()):
        raise StorageError("compiled_sdk_metadata_mismatch")
    database = SQLiteStorage(
        Path("/data/storage"), settings.installation_id, maximum_bytes=settings.storage_max_bytes
    )
    try:
        actual = database.schema_version
        if settings.target_schema_version != SCHEMA:
            raise StorageError("schema_target_mismatch")
        if actual < SCHEMA:
            if actual != settings.expected_schema_version or (actual > 0 and not settings.allow_migration):
                raise StorageError("migration_approval_required")
            database.migrate(MIGRATIONS, SCHEMA, expected=actual)
        database.compatible(SCHEMA, SCHEMA)

        def ready() -> bool:
            with store().transaction():
                store().integrity()
            return True

        module.readiness = ready
        module.storage_version = lambda: store().schema_version
        module.shutdown = database.close
        module.serve()
    finally:
        database.close()


if __name__ == "__main__":
    main()
