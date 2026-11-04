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
            claims = await request.app.state.oidc.verify(credential.credentials)
            audiences = claims.get("aud", [])
            if isinstance(audiences, str):
                audiences = [audiences]
            if (
                claims.get("xarionix_principal") in {"machine", "deployment"}
                or request.app.state.settings.modules_audience in audiences
                or request.app.state.settings.deployment_audience in audiences
            ):
                raise InvalidToken()
            return claims  # type: ignore[no-any-return]
        except InvalidToken:
            pass
    raise HTTPException(401, "Invalid or missing access token", headers={"WWW-Authenticate": "Bearer"})


async def verified_machine_claims(
    request: Request, credential: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]
) -> dict[str, Any]:
    if credential is not None:
        try:
            claims = await request.app.state.oidc.verify(
                credential.credentials, audience=request.app.state.settings.modules_audience
            )
            if claims.get("xarionix_principal") != "machine":
                raise InvalidToken()
            return claims  # type: ignore[no-any-return]
        except InvalidToken:
            pass
    raise HTTPException(401, "Invalid or missing machine token", headers={"WWW-Authenticate": "Bearer"})


async def verified_deployment_claims(
    request: Request, credential: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]
) -> dict[str, Any]:
    if credential is not None:
        try:
            audience = request.app.state.settings.deployment_audience
            claims = await request.app.state.oidc.verify(credential.credentials, audience=audience)
            audiences = claims.get("aud")
            if claims.get("xarionix_principal") != "deployment" or audiences not in (audience, [audience]):
                raise InvalidToken()
            if (
                not isinstance(claims.get("azp"), str)
                or not claims["azp"]
                or claims.get("client_id", claims["azp"]) != claims["azp"]
            ):
                raise InvalidToken()
            return claims  # type: ignore[no-any-return]
        except InvalidToken:
            pass
    raise HTTPException(401, "Invalid or missing deployment token", headers={"WWW-Authenticate": "Bearer"})
