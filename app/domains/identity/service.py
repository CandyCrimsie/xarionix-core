import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.identity.model import Identity


async def resolve_identity(session: AsyncSession, issuer: str, subject: str) -> uuid.UUID:
    # PostgreSQL handles simultaneous first requests; no email matching, no roles.
    statement = insert(Identity).values(id=uuid.uuid4(), issuer=issuer, subject=subject)
    await session.execute(statement.on_conflict_do_nothing(constraint="uq_identity_issuer_subject"))
    identifier = await session.scalar(
        select(Identity.id).where(Identity.issuer == issuer, Identity.subject == subject)
    )
    if identifier is None:
        raise RuntimeError("Identity resolution failed")
    await session.commit()
    return identifier
