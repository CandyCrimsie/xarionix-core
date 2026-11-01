import asyncio

from alembic import context
from sqlalchemy.engine import Connection

from app.core.config import Settings
from app.core.database import Base, create_database
from app.domains.identity.model import Identity  # noqa: F401
from app.domains.registry import load_models

load_models()

target_metadata = Base.metadata


def run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def online() -> None:
    engine, _ = create_database(Settings())
    async with engine.connect() as connection:
        # Serialize deployment migrations; app requests use a different pool.
        await connection.exec_driver_sql("SELECT pg_advisory_lock(881701)")
        await connection.commit()
        try:
            await connection.run_sync(run)
            await connection.commit()
        finally:
            await connection.exec_driver_sql("SELECT pg_advisory_unlock(881701)")
            await connection.commit()
    await engine.dispose()


if context.is_offline_mode():
    context.configure(url="postgresql+psycopg://", target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(online())
