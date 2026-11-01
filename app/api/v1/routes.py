from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.domains.identity.service import resolve_identity
from app.integrations.keycloak.oidc import InvalidToken

router = APIRouter(prefix="/api/v1")
bearer = HTTPBearer(auto_error=False)


async def verified_claims(
    request: Request, credential: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]
) -> dict[str, Any]:
    if credential is not None:
        try:
            return await request.app.state.oidc.verify(credential.credentials)  # type: ignore[no-any-return]
        except InvalidToken:
            pass
    raise HTTPException(401, "Invalid or missing access token", headers={"WWW-Authenticate": "Bearer"})


class MeResponse(BaseModel):
    id: UUID
    issuer: str
    subject: str


@router.get("/me", response_model=MeResponse)
async def me(request: Request, claims: Annotated[dict[str, Any], Depends(verified_claims)]) -> MeResponse:
    async with request.app.state.sessions() as session:
        identifier = await resolve_identity(session, claims["iss"], claims["sub"])
    return MeResponse(id=identifier, issuer=claims["iss"], subject=claims["sub"])


@router.get("/system/info")
async def system_info(claims: Annotated[dict[str, Any], Depends(verified_claims)]) -> dict[str, str]:
    return {"product": "Xarionix Core", "version": "0.1.0", "api_version": "v1"}
