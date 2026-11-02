"""Read-only operator audit. Never changes existing database credentials/ownership."""

import asyncio
import json

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.core.config import Settings
from app.core.database import create_database


async def inspect(connection: AsyncConnection) -> dict[str, bool]:
    result = await connection.execute(
        text("""SELECT
        (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AS superuser,
        has_schema_privilege(current_user,'public','CREATE') AS schema_create,
        EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tableowner=current_user) AS owns_tables,
        has_table_privilege(current_user,'audit_events','DELETE') AS audit_delete,
        has_table_privilege(current_user,'permissions','UPDATE') AS catalog_update,
        has_table_privilege(current_user,'module_instances','UPDATE') AS instance_update
    """)
    )
    value = result.mappings().one()
    return {key: bool(item) for key, item in value.items()}


async def main() -> int:
    try:
        engine, _ = create_database(Settings())
        try:
            async with engine.connect() as connection:
                print(json.dumps(await inspect(connection)))
        finally:
            await engine.dispose()
        return 0
    except Exception:
        print('{"event":"database_privilege_audit_failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
