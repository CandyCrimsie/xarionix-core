from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.api.v1.dependencies import Ctx
from app.api.v1.schemas import Profile, ProfilePatch
from app.core.access import audit, require_human
from app.core.authentication import verified_claims

router = APIRouter(prefix="/api/v1")


def profile(ctx: Ctx) -> Profile:
    return Profile(
        id=ctx.identity.id,
        issuer=ctx.identity.issuer,
        subject=ctx.identity.subject,
        user_id=ctx.user.id,
        principal_type=ctx.identity.principal_type,
        display_name=ctx.user.display_name,
        status=ctx.user.status,
        created_at=ctx.user.created_at,
        updated_at=ctx.user.updated_at,
    )


@router.get("/me")
async def me(ctx: Ctx) -> Profile:
    return profile(ctx)


@router.patch("/me")
async def update_me(payload: ProfilePatch, ctx: Ctx) -> Profile:
    require_human(ctx)
    ctx.user.display_name = payload.display_name
    audit(ctx, "user.profile_changed", "user", ctx.user.id)
    await ctx.session.flush()
    await ctx.session.refresh(ctx.user)
    return profile(ctx)


@router.get("/system/info")
async def system_info(claims: Annotated[dict[str, Any], Depends(verified_claims)]) -> dict[str, str]:
    return {"product": "Xarionix Core", "version": "0.1.0", "api_version": "v1"}
