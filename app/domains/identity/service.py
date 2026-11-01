import hashlib
import uuid

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.identity.model import Identity
from app.domains.users.model import User


async def identity_in_transaction(session: AsyncSession, issuer: str, subject: str) -> Identity:
    # Identity JIT takes the SAME mutation gate before the keyed lock. This avoids
    # lock-order inversions with first login + company/admin mutations.
    query = select(Identity).where(Identity.issuer == issuer, Identity.subject == subject)
    existing = await session.scalar(query)
    if existing is not None:
        return existing
    await session.execute(text("SELECT id FROM platform_settings WHERE id=1 FOR UPDATE"))
    key = int.from_bytes(hashlib.sha256((issuer + "\0" + subject).encode()).digest()[:8], signed=True)
    await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
    identity = await session.scalar(
        select(Identity).where(Identity.issuer == issuer, Identity.subject == subject)
    )
    if identity is None:
        user = User(id=uuid.uuid4(), status="active")
        session.add(user)
        await session.flush()
        identity = Identity(
            id=uuid.uuid4(), issuer=issuer, subject=subject, user_id=user.id, principal_type="unclassified"
        )
        session.add(identity)
        await session.flush()
    return identity


async def resolve_identity(session: AsyncSession, issuer: str, subject: str) -> uuid.UUID:
    identity = await identity_in_transaction(session, issuer, subject)
    await session.commit()
    return identity.id
