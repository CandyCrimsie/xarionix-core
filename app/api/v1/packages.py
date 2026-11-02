import asyncio
import os
from contextlib import asynccontextmanager
from functools import partial
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from starlette.requests import ClientDisconnect

from app.api.v1.dependencies import Ctx, Limit, Offset, context
from app.api.v1.package_schemas import KeyCreate, KeyView, NamespacePut, PublisherCreate, PublisherView
from app.api.v1.schemas import Page
from app.api.v1.tenants import page
from app.core.access import audit, fail, require_platform
from app.core.authentication import bearer, verified_claims
from app.domains.packages import service
from app.domains.packages.archive import Limits, verify
from app.domains.packages.codec import PackageError, fingerprint
from app.domains.packages.model import (
    ModulePackage,
    PackagePublisher,
    PublisherNamespaceGrant,
    PublisherSigningKey,
)
from app.domains.packages.reports import diff
from app.domains.packages.schema import Manifest
from app.domains.packages.storage import Storage
from app.domains.packages.work import file_work

router = APIRouter(prefix="/api/v1/platform")
Claims = Annotated[dict[str, Any], Depends(verified_claims)]
transaction = asynccontextmanager(context)


async def live_claims(request: Request) -> dict[str, Any]:
    # JWT expiry, signature/issuer and purpose are checked AGAIN after potentially long processing.
    return await verified_claims(request, await bearer(request))


@router.post("/package-publishers", response_model=PublisherView, status_code=201)
async def publisher_create(payload: PublisherCreate, ctx: Ctx) -> PackagePublisher:
    await require_platform(ctx)
    value = PackagePublisher(**payload.model_dump())
    ctx.session.add(value)
    await ctx.session.flush()
    audit(ctx, "package.publisher_created", "package_publisher", value.id)
    return value


@router.get("/package-publishers", response_model=Page[PublisherView])
async def publishers(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx)
    return await page(ctx, select(PackagePublisher).order_by(PackagePublisher.publisher_id), limit, offset)


@router.get("/package-publishers/{publisher_id}", response_model=PublisherView)
async def publisher_detail(publisher_id: UUID, ctx: Ctx) -> PackagePublisher:
    await require_platform(ctx)
    return await service.publisher(ctx, publisher_id)


@router.post("/package-publishers/{publisher_id}/revoke", response_model=PublisherView)
async def publisher_revoke(publisher_id: UUID, ctx: Ctx) -> PackagePublisher:
    await require_platform(ctx)
    value = await service.publisher(ctx, publisher_id)
    value.status = "revoked"
    audit(ctx, "package.publisher_revoked", "package_publisher", value.id)
    await ctx.session.flush()
    return value


@router.post("/package-publishers/{publisher_id}/keys", response_model=KeyView, status_code=201)
async def key_create(publisher_id: UUID, payload: KeyCreate, ctx: Ctx) -> PublisherSigningKey:
    await require_platform(ctx)
    parent = await service.publisher(ctx, publisher_id)
    if parent.status != "active":
        fail(409, "publisher_revoked")
    if (await ctx.session.scalar(select(func.count()).select_from(PublisherSigningKey)) or 0) >= 1024:
        fail(409, "trust_store_capacity_exceeded")
    value = PublisherSigningKey(
        publisher_id=publisher_id, **payload.model_dump(), fingerprint=fingerprint(payload.public_key)
    )
    ctx.session.add(value)
    await ctx.session.flush()
    audit(
        ctx,
        "package.signing_key_registered",
        "publisher_signing_key",
        value.id,
        fingerprint=value.fingerprint,
    )
    return value


@router.get("/package-publishers/{publisher_id}/keys", response_model=Page[KeyView])
async def keys(publisher_id: UUID, ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx)
    await service.publisher(ctx, publisher_id)
    return await page(
        ctx,
        select(PublisherSigningKey)
        .where(PublisherSigningKey.publisher_id == publisher_id)
        .order_by(PublisherSigningKey.key_id),
        limit,
        offset,
    )


@router.post("/package-publishers/{publisher_id}/keys/{key_id}/revoke", response_model=KeyView)
async def key_revoke(publisher_id: UUID, key_id: UUID, ctx: Ctx) -> PublisherSigningKey:
    await require_platform(ctx)
    return await service.revoke_key(ctx, publisher_id, key_id)


@router.get("/package-publishers/{publisher_id}/namespaces")
async def namespaces(publisher_id: UUID, ctx: Ctx) -> list[dict[str, str]]:
    await require_platform(ctx)
    await service.publisher(ctx, publisher_id)
    rows = list(
        (
            await ctx.session.scalars(
                select(PublisherNamespaceGrant)
                .where(PublisherNamespaceGrant.publisher_id == publisher_id)
                .order_by(PublisherNamespaceGrant.namespace)
                .limit(64)
            )
        ).all()
    )
    return [{"namespace": row.namespace, "status": row.status} for row in rows]


@router.put("/package-publishers/{publisher_id}/namespaces", response_model=NamespacePut)
async def namespaces_put(publisher_id: UUID, payload: NamespacePut, ctx: Ctx) -> NamespacePut:
    await require_platform(ctx)
    if (await service.publisher(ctx, publisher_id)).status != "active":
        fail(409, "publisher_revoked")
    existing = list(
        (
            await ctx.session.scalars(
                select(PublisherNamespaceGrant).where(PublisherNamespaceGrant.publisher_id == publisher_id)
            )
        ).all()
    )
    if len({value.namespace for value in existing} | set(payload.namespaces)) > 64:
        fail(409, "publisher_namespace_capacity_exceeded")
    for name in payload.namespaces:
        value = await ctx.session.get(PublisherNamespaceGrant, name)
        if value is not None and (value.publisher_id != publisher_id or value.status != "active"):
            fail(409, "namespace_owned_or_revoked")
        if value is None:
            ctx.session.add(PublisherNamespaceGrant(namespace=name, publisher_id=publisher_id))
    for value in existing:
        if value.namespace not in payload.namespaces:
            value.status = "revoked"
    audit(
        ctx,
        "package.namespaces_updated",
        "package_publisher",
        publisher_id,
        namespace_count=len(payload.namespaces),
    )
    await ctx.session.flush()
    return payload


@router.post("/packages", status_code=201)
async def upload(request: Request, response: Response, claims: Claims) -> dict[str, Any]:
    # No multipart filename, no body parsing/buffering before platform authentication.
    async with transaction(request, claims) as ctx:
        await require_platform(ctx)
        trust = await service.trust_store(ctx)
    if request.headers.get("content-type", "").split(";")[0] not in {
        "application/octet-stream",
        "application/vnd.xarionix.package+zip",
    }:
        fail(415, "package_content_type_required")
    settings = request.app.state.settings
    length = request.headers.get("content-length")
    if length is not None and (
        not length.isascii()
        or not length.isdecimal()
        or len(length) > 10
        or int(length) > settings.packages_max_bytes
    ):
        fail(413, "package_body_limit")
    storage = Storage(settings.packages_storage_root)
    lease = storage.lease()
    try:
        stage, stream = storage.temporary()
    except BaseException:
        lease.close()
        raise
    try:
        count = 0
        async with asyncio.timeout(settings.packages_upload_seconds):
            async for chunk in request.stream():
                count += len(chunk)
                if count > settings.packages_max_bytes:
                    fail(413, "package_body_limit")
                await file_work(stream.write, chunk)
        if length is not None and int(length) != count:
            fail(400, "package_body_length_mismatch")
        await file_work(stream.flush)
        await file_work(os.fsync, stream.fileno())
        os.fchmod(stream.fileno(), 0o400)
        stream.close()
        verified = await file_work(partial(verify, stage, trust, Limits.configured(settings)))
        if not verified.core_compatible:
            fail(422, "core_incompatible")
        await file_work(storage.publish, stage, verified.package_sha256)
        async with transaction(request, await live_claims(request)) as ctx:
            await require_platform(ctx)
            value, created = await service.publish(ctx, verified)
            result = await service.view(ctx, value, await service.trust_store(ctx))
        response.status_code = 201 if created else 200
        result["blob_integrity"] = "verified"
        return result
    except TimeoutError:
        fail(408, "package_upload_timeout")
    except ClientDisconnect:
        fail(400, "package_upload_disconnected")
    finally:
        stream.close()
        stage.unlink(missing_ok=True)
        lease.close()


@router.get("/packages")
async def packages(ctx: Ctx, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
    await require_platform(ctx)
    values = await page(
        ctx, select(ModulePackage).order_by(ModulePackage.created_at, ModulePackage.id), limit, offset
    )
    trust = await service.trust_store(ctx)
    values["items"] = [await service.view(ctx, value, trust) for value in values["items"]]
    return values


@router.get("/packages/{package_id}")
async def package_detail(package_id: UUID, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx)
    value, trust = await service.package(ctx, package_id), await service.trust_store(ctx)
    result = await service.view(ctx, value, trust)
    result["dependency_report"] = await service.dependency_report(ctx, value, trust)
    return result


@router.get("/packages/{package_id}/manifest")
async def manifest(package_id: UUID, request: Request, claims: Claims) -> dict[str, Any]:
    async with transaction(request, claims) as ctx:
        await require_platform(ctx)
        value = await service.package(ctx, package_id)
        digest, data = value.package_sha256, value.manifest
    storage = Storage(request.app.state.settings.packages_storage_root)
    lease = storage.lease()
    try:
        if not await file_work(storage.check, digest):
            fail(409, "package_blob_missing_or_corrupt")
        return data
    finally:
        lease.close()


@router.post("/packages/{package_id}/verify")
async def reverify(package_id: UUID, request: Request, claims: Claims) -> dict[str, Any]:
    async with transaction(request, claims) as ctx:
        await require_platform(ctx)
        value = await service.package(ctx, package_id)
        digest, trust = value.package_sha256, await service.trust_store(ctx)
    storage = Storage(request.app.state.settings.packages_storage_root)
    lease = storage.lease()
    try:
        try:
            verified = await file_work(
                verify, storage.blob(digest), trust, Limits.configured(request.app.state.settings)
            )
            if verified.package_sha256 != digest:
                raise PackageError("package_blob_missing_or_corrupt")
        except PackageError as error:
            # Trust revocation is dynamic policy, not evidence of byte corruption.
            if str(error) in {"signing_trust_revoked", "publisher_namespace_denied", "signing_key_unknown"}:
                raise
            async with transaction(request, await live_claims(request)) as ctx:
                await require_platform(ctx)
                value = await service.package(ctx, package_id)
                value.state = "quarantined"
                audit(ctx, "package.quarantined", "module_package", value.id)
            raise HTTPException(
                409, detail={"code": "package_reverification_failed", "reason": str(error)}
            ) from None
        async with transaction(request, await live_claims(request)) as ctx:
            await require_platform(ctx)
            if not service.current_trust(
                verified.manifest,
                verified.envelope.key_id,
                await service.trust_store(ctx),
                expected_fingerprint=verified.key_fingerprint,
            ):
                fail(409, "package_trust_changed")
            if not await service.namespace_owner(ctx, verified.manifest):
                fail(409, "package_namespace_owner_mismatch")
            from datetime import UTC, datetime

            value = await service.package(ctx, package_id)
            value.state, value.verified_at = "available", datetime.now(UTC)
            audit(ctx, "package.reverified", "module_package", value.id)
            report = verified.report()
            report["dependency_report"] = await service.dependency_report(
                ctx, value, await service.trust_store(ctx)
            )
            return report
    finally:
        lease.close()


@router.get("/packages/{package_id}/diff")
async def package_diff(package_id: UUID, previous_id: UUID, ctx: Ctx) -> dict[str, Any]:
    await require_platform(ctx)
    current, previous = await service.package(ctx, package_id), await service.package(ctx, previous_id)
    if (current.module_id, current.publisher_id) != (previous.module_id, previous.publisher_id):
        fail(422, "package_lineage_mismatch")
    return diff(Manifest.model_validate(previous.manifest), Manifest.model_validate(current.manifest))
