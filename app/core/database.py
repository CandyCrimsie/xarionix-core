import asyncio

from sqlalchemy import URL, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import Settings


class Base(DeclarativeBase):
    pass


def create_database(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    url = URL.create(
        "postgresql+psycopg",
        username=settings.db_user,
        password=settings.db_password.get_secret_value(),
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
    )
    engine = create_async_engine(
        url,
        pool_pre_ping=True,
        hide_parameters=True,
        echo=False,
        pool_timeout=5,
        connect_args={"connect_timeout": 5, "options": "-c statement_timeout=10000 -c lock_timeout=5000"},
    )
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def database_ready(engine: AsyncEngine) -> bool:
    try:
        async with asyncio.timeout(6), engine.connect() as connection:
            revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
            return bool(revision == "0004_rbac")
    except Exception:
        return False
