from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select

from app.core.access import Context, audit, fail
from app.domains.packages.archive import Verified
from app.domains.packages.codec import fingerprint
from app.domains.packages.model import (
    ModulePackage,
    PackagePublisher,
    PublisherNamespaceGrant,
    PublisherSigningKey,
)
from app.domains.packages.reports import dependencies
from app.domains.packages.schema import Manifest, TrustKey, TrustStore
from app.domains.packages.semver import Range
from app.domains.rbac.model import PermissionNamespace
from app.version import VERSION


async def publisher(ctx: Context, publisher_id: UUID) -> PackagePublisher:
    value = await ctx.session.get(PackagePublisher, publisher_id)
    if value is None:
        fail(404, "publisher_not_found")
    return value


async def package(ctx: Context, package_id: UUID) -> ModulePackage:
    value = await ctx.session.get(ModulePackage, package_id)
    if value is None:
        fail(404, "package_not_found")
    return value


async def trust_store(ctx: Context) -> TrustStore:
    query = (
        select(PublisherSigningKey, PackagePublisher)
        .join(PackagePublisher, PublisherSigningKey.publisher_id == PackagePublisher.id)
        .limit(1025)
    )
    grants_query = (
        select(PublisherNamespaceGrant).where(PublisherNamespaceGrant.status == "active").limit(65537)
    )
    # Operator installation snapshots hold administration SHARE; all trust mutations
    # hold administration EX. FOR SHARE would unnecessarily require UPDATE authority
    # on the trust catalog for the separate read-only installer identity.
    if not ctx.operator:
        query = query.with_for_update(read=True)
        grants_query = grants_query.with_for_update(read=True)
    rows = (await ctx.session.execute(query)).all()
    if len(rows) > 1024:
        fail(503, "trust_store_capacity_exceeded")
    grants = list((await ctx.session.scalars(grants_query)).all())
    if len(grants) > 65536:
        fail(503, "namespace_capacity_exceeded")
    by_publisher: dict[UUID, list[str]] = {}
    for grant in grants:
        by_publisher.setdefault(grant.publisher_id, []).append(grant.namespace)
    return TrustStore(
        schema_version=1,
        keys=[
            TrustKey(
                publisher_id=p.publisher_id,
                key_id=k.key_id,
                public_key=k.public_key,
                status=k.status,
                publisher_status=p.status,
                namespaces=by_publisher.get(p.id, []),
            )
            for k, p in rows
        ],
    )


def current_trust(
    manifest: Manifest, key_id: str, store: TrustStore, *, expected_fingerprint: str | None = None
) -> bool:
    key = next(
        (k for k in store.keys if k.publisher_id == manifest.publisher.id and k.key_id == key_id), None
    )
    return bool(
        key
        and key.status == "active"
        and key.publisher_status == "active"
        and manifest.permissions.namespace in key.namespaces
        and (expected_fingerprint is None or fingerprint(key.public_key) == expected_fingerprint)
    )


async def publish(ctx: Context, verified: Verified) -> tuple[ModulePackage, bool]:
    # Caller holds short administration lock and has rechecked live JWT/MFA/admin status.
    store = await trust_store(ctx)
    if not current_trust(
        verified.manifest, verified.envelope.key_id, store, expected_fingerprint=verified.key_fingerprint
    ):
        fail(409, "package_trust_changed")
    if not verified.core_compatible:
        fail(422, "core_incompatible")
    if not await namespace_owner(ctx, verified.manifest):
        fail(422, "package_namespace_owner_mismatch")
    parent = await ctx.session.scalar(
        select(PackagePublisher).where(PackagePublisher.publisher_id == verified.manifest.publisher.id)
    )
    if parent is None:
        fail(409, "package_trust_changed")
    key = await ctx.session.scalar(
        select(PublisherSigningKey).where(
            PublisherSigningKey.publisher_id == parent.id,
            PublisherSigningKey.key_id == verified.envelope.key_id,
        )
    )
    if key is None:
        fail(409, "package_trust_changed")
    previous = await ctx.session.scalar(
        select(ModulePackage).where(
            ModulePackage.module_id == verified.manifest.module.id,
            ModulePackage.version == verified.manifest.module.version,
            ModulePackage.publisher_id == parent.id,
        )
    )
    if previous is not None:
        if previous.package_sha256 != verified.package_sha256:
            fail(409, "package_version_conflict")
        return previous, False
    value = ModulePackage(
        module_id=verified.manifest.module.id,
        version=verified.manifest.module.version,
        publisher_id=parent.id,
        signing_key_id=key.id,
        package_sha256=verified.package_sha256,
        manifest_sha256=verified.manifest_sha256,
        size=verified.size,
        manifest=verified.manifest_data,
        state="available",
        imported_by_user_id=ctx.user.id,
    )
    ctx.session.add(value)
    await ctx.session.flush()
    if verified.api_contract is not None:
        from app.domains.module_gateway.contracts import APIContract
        from app.domains.module_gateway.model import ModuleAPIContract

        api = APIContract.model_validate(verified.api_contract)
        ctx.session.add(
            ModuleAPIContract(package_id=value.id, sha256=api.digest(), document=api.model_dump())
        )
        await ctx.session.flush()
    if verified.sdk_contract is not None:
        from app.domains.module_sdk.contracts import SDKContract
        from app.domains.module_sdk.model import ModuleSDKContract

        sdk = SDKContract.model_validate(verified.sdk_contract)
        ctx.session.add(ModuleSDKContract(package_id=value.id, sha256=sdk.digest(), document=sdk.document()))
        await ctx.session.flush()
    audit(ctx, "package.imported", "module_package", value.id, package_sha256=value.package_sha256)
    return value, True


async def view(ctx: Context, value: ModulePackage, store: TrustStore) -> dict[str, Any]:
    key = await ctx.session.get(PublisherSigningKey, value.signing_key_id)
    if key is None:
        fail(503, "package_signing_key_missing")
    manifest = Manifest.model_validate(value.manifest)
    trusted = current_trust(manifest, key.key_id, store, expected_fingerprint=key.fingerprint)
    trusted = trusted and await namespace_owner(ctx, manifest)
    return {
        "id": str(value.id),
        "module_id": value.module_id,
        "version": value.version,
        "publisher_id": manifest.publisher.id,
        "key_id": key.key_id,
        "key_fingerprint": key.fingerprint,
        "package_sha256": value.package_sha256,
        "manifest_sha256": value.manifest_sha256,
        "size": value.size,
        "state": value.state,
        "current_trust": trusted,
        "cryptographic_validity_at_import": True,
        "blob_integrity": "not_checked",
        "core_compatible": Range.parse(manifest.compatibility.core).contains(VERSION),
        "deployment_ready": False,
        "created_at": value.created_at,
        "verified_at": value.verified_at,
    }


async def namespace_owner(ctx: Context, manifest: Manifest) -> bool:
    # Existing active/reserved catalog ownership is not superseded by a publisher grant.
    value = await ctx.session.get(PermissionNamespace, manifest.permissions.namespace)
    if value is None:
        return True
    if value.owner != manifest.module.id:
        return False
    if value.state != "disabled":
        return True
    # A managed disabled installation must still accept trusted update packages.
    from app.domains.installations.model import ModuleInstallation

    return (
        await ctx.session.scalar(
            select(ModuleInstallation.id).where(
                ModuleInstallation.module_id == manifest.module.id,
                ModuleInstallation.namespace == manifest.permissions.namespace,
            )
        )
        is not None
    )


async def dependency_report(ctx: Context, value: ModulePackage, store: TrustStore) -> dict[str, Any]:
    # Bounded report rather than a potentially exponential/unbounded global resolver.
    rows = list(
        (
            await ctx.session.scalars(
                select(ModulePackage)
                .where(ModulePackage.state == "available")
                .order_by(ModulePackage.id)
                .limit(257)
            )
        ).all()
    )
    if len(rows) > 256:
        return {"ready": False, "registry_report_limit": True, "automatic_selection": False}
    keys = {k.id: k for k in (await ctx.session.scalars(select(PublisherSigningKey).limit(1024))).all()}
    known = []
    for row in rows:
        manifest = Manifest.model_validate(row.manifest)
        key = keys.get(row.signing_key_id)
        if (
            key
            and current_trust(manifest, key.key_id, store)
            and Range.parse(manifest.compatibility.core).contains(VERSION)
            and await namespace_owner(ctx, manifest)
        ):
            known.append(manifest)
    report = dependencies(Manifest.model_validate(value.manifest), known)
    report["blob_integrity"] = "not_checked"
    report["deployment_ready"] = False
    return report


async def revoke_key(ctx: Context, publisher_id: UUID, key_id: UUID) -> PublisherSigningKey:
    value = await ctx.session.get(PublisherSigningKey, key_id)
    if value is None or value.publisher_id != publisher_id:
        fail(404, "signing_key_not_found")
    if value.status != "revoked":
        value.status, value.revoked_at = "revoked", datetime.now(UTC)
        audit(ctx, "package.signing_key_revoked", "publisher_signing_key", value.id)
        await ctx.session.flush()
    return value
