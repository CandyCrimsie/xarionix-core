"""Transaction locks shared with PostgreSQL guards; never process-local mutexes."""

from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.platform.model import PlatformSettings


async def policy(session: AsyncSession, *, exclusive: bool = False) -> PlatformSettings:
    value = await session.scalar(
        select(PlatformSettings)
        .where(PlatformSettings.id == 1)
        .with_for_update(read=not exclusive)
        .execution_options(populate_existing=True)
    )
    if value is None:
        from app.core.access import fail

        fail(503, "platform_migration_required")
    return value


async def company(session: AsyncSession, identifier: UUID, *, shared: bool = False) -> None:
    await session.execute(
        text("SELECT core_lock(:scope, :identifier, :shared)"),
        {"scope": "company", "identifier": str(identifier), "shared": shared},
    )


async def quota(session: AsyncSession, *users: UUID) -> None:
    for identifier in sorted(set(users)):
        await session.execute(
            text("SELECT core_lock('quota', :identifier, false)"), {"identifier": str(identifier)}
        )


async def administration(session: AsyncSession, *, shared: bool = False) -> None:
    await session.execute(
        text("SELECT core_lock('administration', 'singleton', :shared)"), {"shared": shared}
    )
