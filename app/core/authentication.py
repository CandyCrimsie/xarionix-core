from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.integrations.keycloak.oidc import InvalidToken

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
