from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Query, Request
from sqlalchemy.exc import IntegrityError

from app.core.access import Context, fail, mutation_gate
from app.core.authentication import verified_claims
from app.domains.identity.service import identity_in_transaction
from app.domains.users.model import User


async def context(
    request: Request, claims: Annotated[dict[str, Any], Depends(verified_claims)]
) -> AsyncIterator[Context]:
    try:
        async with request.app.state.sessions() as session, session.begin():
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                await mutation_gate(session)
            identity = await identity_in_transaction(session, claims["iss"], claims["sub"])
            user = await session.get(User, identity.user_id)
            if user is None:
                fail(503, "identity_user_missing")
            if user.status != "active":
                fail(403, "user_suspended")
            yield Context(
                session, identity, user, request.app.state.settings, claims, request.state.request_id
            )
    except IntegrityError:
        # No SQL/constraint/payload echo. Includes deferred checks at COMMIT.
        raise HTTPException(409, detail={"code": "data_conflict"}) from None


# Function scope is essential: COMMIT/deferred constraints must run BEFORE HTTP success.
Ctx = Annotated[Context, Depends(context, scope="function")]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=100000)]
