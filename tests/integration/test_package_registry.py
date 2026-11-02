"""Real PostgreSQL + native Keycloak JWTs + actual CAS; fault injection never substitutes the DB."""

import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx
import psycopg
import pytest
import test_managed_stack as managed
from package_helpers import manifest_data, package

from app.api.v1 import packages as api
from app.core.config import Settings
from app.domains.packages import service
from app.domains.packages.storage import Storage
from app.main import create_app
from scripts.xpkg import pack

stack, actors = managed.stack, managed.actors
pytestmark = pytest.mark.integration


def admin(actors, method, path, **kwargs):
    return actors["request"]("admin", method, "/platform" + path, **kwargs)


@pytest.fixture
def bundle(actors, tmp_path):
    name = "publisher-" + uuid.uuid4().hex[:12]
    namespace = "pkg" + uuid.uuid4().hex[:12]
    data = manifest_data(publisher=name, namespace=namespace)
    path, trust, report = package(tmp_path / "bundle", data=data)
    response = admin(
        actors,
        "POST",
        "/package-publishers",
        json={"publisher_id": name, "display_name": "Тестовый издатель"},
    )
    assert response.status_code == 201, response.text
    publisher = response.json()["id"]
    response = admin(
        actors,
        "POST",
        f"/package-publishers/{publisher}/keys",
        json={"key_id": "test-key", "public_key": trust.keys[0].public_key},
    )
    assert response.status_code == 201, response.text
    key = response.json()["id"]
    response = admin(
        actors, "PUT", f"/package-publishers/{publisher}/namespaces", json={"namespaces": [namespace]}
    )
    assert response.status_code == 200, response.text
    return {
        "path": path,
        "trust": trust,
        "report": report,
        "publisher": publisher,
        "key": key,
        "manifest": data,
    }


def upload(actors, bundle):
    return admin(
        actors,
        "POST",
        "/packages",
        content=bundle["path"].read_bytes(),
        headers={"Content-Type": "application/octet-stream"},
    )


def test_real_upload_metadata_manifest_reverify_and_transactional_audit(actors, stack, bundle):
    response = upload(actors, bundle)
    assert response.status_code == 201, response.text
    value = response.json()
    assert value["blob_integrity"] == "verified" and value["current_trust"]
    prefix = "/packages/" + value["id"]
    assert admin(actors, "GET", prefix + "/manifest").json()["module"]["id"] == "test-module"
    verified = admin(actors, "POST", prefix + "/verify")
    assert verified.status_code == 200 and verified.json()["cryptographic_validity"]
    assert not verified.json()["deployment_ready"]
    assert admin(actors, "GET", prefix).json()["dependency_report"]["ready"]
    with managed.sql_connection(stack) as db:
        assert db.execute("SELECT count(*) FROM module_packages WHERE id=%s", (value["id"],)).fetchone() == (
            1,
        )
        assert db.execute(
            "SELECT count(*) FROM audit_events WHERE resource_id=%s AND action='package.imported'",
            (value["id"],),
        ).fetchone() == (1,)
        assert db.execute(
            "SELECT count(*) FROM permissions WHERE key LIKE %s",
            (bundle["manifest"]["permissions"]["namespace"] + ".%",),
        ).fetchone() == (0,)


def test_concurrent_duplicate_import_is_idempotent_and_repacked_version_conflicts(actors, stack, bundle):
    # actors.request already sets Authorization; combine content-type without replacing it.
    def post(_):
        token = managed.token(stack, "integration-admin")
        return httpx.post(
            stack["config"]["PUBLIC_URL"] + "/api/v1/platform/packages",
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream"},
            content=bundle["path"].read_bytes(),
            timeout=30,
            trust_env=False,
        )

    with ThreadPoolExecutor(2) as pool:
        responses = list(pool.map(post, range(2)))
    assert sorted(r.status_code for r in responses) == [200, 201], [r.text for r in responses]
    assert len({r.json()["id"] for r in responses}) == 1
    folder = bundle["path"].parent
    (folder / "distribution/resources/example.txt").write_bytes(b"changed")
    alternate = folder / "changed.xpkg"
    pack(
        folder / "distribution",
        folder / "manifest.json",
        folder / "private.key",
        bundle["manifest"]["publisher"]["id"],
        "test-key",
        alternate,
    )
    bundle["path"] = alternate
    response = upload(actors, bundle)
    assert response.status_code == 409 and response.json()["detail"]["code"] == "package_version_conflict"


def test_revocation_changes_current_verdict_without_losing_history(actors, stack, bundle):
    value = upload(actors, bundle).json()
    path = f"/package-publishers/{bundle['publisher']}/keys/{bundle['key']}/revoke"
    assert admin(actors, "POST", path).status_code == 200
    assert not admin(actors, "GET", "/packages/" + value["id"]).json()["current_trust"]
    assert admin(actors, "POST", "/packages/" + value["id"] + "/verify").status_code == 422
    assert upload(actors, bundle).status_code == 422
    with managed.sql_connection(stack) as db:
        with pytest.raises(psycopg.errors.CheckViolation):
            db.execute(
                "UPDATE publisher_signing_keys SET status='active',revoked_at=NULL WHERE id=%s",
                (bundle["key"],),
            )
        db.rollback()
        assert db.execute("SELECT count(*) FROM module_packages WHERE id=%s", (value["id"],)).fetchone() == (
            1,
        )


def test_namespace_ownership_core_protection_and_key_immutability(actors, stack, bundle):
    prefix = f"/package-publishers/{bundle['publisher']}"
    assert admin(actors, "PUT", prefix + "/namespaces", json={"namespaces": ["core"]}).status_code == 422
    assert (
        admin(
            actors,
            "POST",
            prefix + "/keys",
            json={"key_id": "test-key", "public_key": bundle["trust"].keys[0].public_key},
        ).status_code
        == 409
    )
    with managed.sql_connection(stack) as db:
        with pytest.raises(psycopg.errors.CheckViolation):
            db.execute("UPDATE publisher_signing_keys SET key_id='rebound-key' WHERE id=%s", (bundle["key"],))
        db.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute("TRUNCATE publisher_namespace_grants")
        db.rollback()


def test_namespace_grant_cannot_override_existing_module_owner_or_another_publisher(actors, bundle):
    import json

    namespace = bundle["manifest"]["permissions"]["namespace"]
    other = admin(
        actors,
        "POST",
        "/package-publishers",
        json={"publisher_id": "other-" + uuid.uuid4().hex[:12], "display_name": "Other publisher"},
    ).json()["id"]
    response = admin(
        actors, "PUT", f"/package-publishers/{other}/namespaces", json={"namespaces": [namespace]}
    )
    assert response.status_code == 409
    parent = f"/package-publishers/{bundle['publisher']}"
    assert (
        admin(actors, "PUT", parent + "/namespaces", json={"namespaces": [namespace, "billing"]}).status_code
        == 200
    )
    data = bundle["manifest"]
    data["permissions"] = {
        "namespace": "billing",
        "definitions": [
            {
                "key": "billing.orders.read",
                "description": "Attempt to override reserved owner",
                "scope": "company",
            }
        ],
    }
    folder = bundle["path"].parent
    (folder / "manifest.json").write_text(json.dumps(data))
    path = folder / "foreign-namespace.xpkg"
    pack(
        folder / "distribution",
        folder / "manifest.json",
        folder / "private.key",
        data["publisher"]["id"],
        "test-key",
        path,
    )
    bundle["path"] = path
    response = upload(actors, bundle)
    assert (
        response.status_code == 422
        and response.json()["detail"]["code"] == "package_namespace_owner_mismatch"
    )


@pytest.mark.parametrize("label", ["alice", "bob", "machine"])
def test_non_platform_actors_cannot_manage_packages(actors, label):
    assert actors["request"](label, "GET", "/platform/packages").status_code == 403
    assert (
        actors["request"](
            label,
            "POST",
            "/platform/package-publishers",
            json={"publisher_id": "forbidden-publisher", "display_name": "Denied"},
        ).status_code
        == 403
    )


@pytest.fixture
async def local_app(stack, actors, tmp_path):
    config = Settings(
        environment="development",
        keycloak_mode="managed",
        public_url="http://localhost:8000",
        oidc_issuer=stack["issuer"],
        db_host="localhost",
        db_port=stack["postgres_port"],
        db_password=stack["config"]["DB_PASSWORD"],
        admin_acr_values=["test-step-up"],
        packages_storage_root=tmp_path / "registry",
    )
    app = create_app(config)
    token = managed.token(stack, "integration-admin")
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost:8000",
            headers={"Authorization": "Bearer " + token},
        ) as client:
            yield app, client, Storage(config.packages_storage_root)


async def local_upload(client, bundle):
    return await client.post(
        "/api/v1/platform/packages",
        content=bundle["path"].read_bytes(),
        headers={"Content-Type": "application/octet-stream"},
    )


@pytest.mark.parametrize("phase", ["before_link", "after_link", "before_commit"])
async def test_real_db_and_storage_fault_recovery(local_app, bundle, stack, monkeypatch, phase):
    app, client, storage = local_app
    original_publish, original_metadata = Storage.publish, service.publish

    def failure(self, stage, digest):
        original_publish(self, stage, digest)
        raise RuntimeError("injected crash after atomic link")

    def fail_link(*args, **kwargs):
        raise OSError("injected filesystem error after copy/fsync before atomic link")

    async def metadata_failure(ctx, verified):
        await original_metadata(ctx, verified)
        raise RuntimeError("injected DB rollback after flush")

    with monkeypatch.context() as patch:
        if phase == "before_commit":
            patch.setattr(service, "publish", metadata_failure)
        elif phase == "before_link":
            patch.setattr("app.domains.packages.storage.os.link", fail_link)
        else:
            patch.setattr(Storage, "publish", failure)
        response = await local_upload(client, bundle)
    assert response.status_code == 500
    with managed.sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM module_packages WHERE package_sha256=%s",
            (bundle["report"]["package_sha256"],),
        ).fetchone() == (0,)
        assert db.execute(
            "SELECT count(*) FROM audit_events WHERE action='package.imported' AND details->>'package_sha256'=%s",
            (bundle["report"]["package_sha256"],),
        ).fetchone() == (0,)
    assert not list((storage.root / "staging").iterdir())
    assert storage.reconcile(set())["orphan_blobs"] == (0 if phase == "before_link" else 1)
    retry = await local_upload(client, bundle)
    assert retry.status_code == 201, retry.text


async def test_trust_revoked_during_verification_is_rechecked_before_commit(
    local_app, bundle, actors, stack, monkeypatch
):
    app, client, storage = local_app
    original = api.verify

    def verifying(path, trust, limits):
        result = original(path, trust, limits)
        response = admin(
            actors, "POST", f"/package-publishers/{bundle['publisher']}/keys/{bundle['key']}/revoke"
        )
        assert response.status_code == 200  # would block if upload retained global administration lock
        return result

    monkeypatch.setattr(api, "verify", verifying)
    response = await local_upload(client, bundle)
    assert response.status_code == 409 and response.json()["detail"]["code"] == "package_trust_changed"
    with managed.sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM module_packages WHERE package_sha256=%s",
            (bundle["report"]["package_sha256"],),
        ).fetchone() == (0,)
    assert storage.reconcile(set())["orphan_blobs"] == 1


async def test_blob_corruption_quarantines_and_never_returns_manifest(local_app, bundle):
    _, client, storage = local_app
    response = await local_upload(client, bundle)
    assert response.status_code == 201, response.text
    value = response.json()
    path = storage.blob(value["package_sha256"])
    path.chmod(0o600)
    path.write_bytes(b"corrupt")
    prefix = "/api/v1/platform/packages/" + value["id"]
    assert (await client.get(prefix + "/manifest")).status_code == 409
    assert (await client.post(prefix + "/verify")).status_code == 409
    assert (await client.get(prefix)).json()["state"] == "quarantined"


async def test_upload_authentication_mfa_and_native_machine_rejected_before_body(local_app, stack):
    _, client, storage = local_app
    consumed = False

    async def body():
        nonlocal consumed
        consumed = True
        yield b"must not be consumed before authorization"

    # Native service-account JWT with the separate signed machine audience/purpose.
    async with httpx.AsyncClient(timeout=10, trust_env=False) as oidc:
        response = await oidc.post(
            stack["issuer"] + "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "module-a",
                "client_secret": stack["module_secrets"]["module-a"],
            },
        )
        machine = response.json()["access_token"]
    import time

    stale = managed.token(stack, "integration-admin", authentication_time=int(time.time()) - 1000)
    for token, expected in (("", 401), (machine, 401), (stale, 403)):
        response = await client.post(
            "/api/v1/platform/packages",
            content=body(),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream"},
        )
        assert response.status_code == expected, response.text
        assert not consumed
    assert not list((storage.root / "staging").iterdir())


async def test_chunked_limit_content_length_mismatch_disconnect_and_slot_cleanup(local_app, bundle):
    from starlette.requests import ClientDisconnect

    app, client, storage = local_app
    app.state.settings.packages_max_bytes = 2048

    async def large():
        yield b"x" * 1500
        yield b"x" * 1500

    response = await client.post(
        "/api/v1/platform/packages", content=large(), headers={"Content-Type": "application/octet-stream"}
    )
    assert response.status_code == 413
    response = await client.post(
        "/api/v1/platform/packages",
        content=b"short",
        headers={"Content-Type": "application/octet-stream", "Content-Length": "100"},
    )
    assert response.status_code == 400

    async def disconnected():
        yield b"partial upload"
        raise ClientDisconnect()

    response = await client.post(
        "/api/v1/platform/packages",
        content=disconnected(),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 400
    assert not list((storage.root / "staging").iterdir())
    leases = [storage.lease(), storage.lease()]
    try:
        response = await local_upload(client, bundle)
        assert response.status_code == 503
    finally:
        for lease in leases:
            lease.close()
    assert (await local_upload(client, bundle)).status_code == 201


def test_module_instance_terminal_revoke_direct_dml(stack):
    service_id, instance_id = uuid.uuid4(), uuid.uuid4()
    with managed.sql_connection(stack) as db:
        user = db.execute("SELECT id FROM users LIMIT 1").fetchone()[0]
        db.execute(
            "INSERT INTO module_services(id,module_key,name,issuer,subject,client_id,operations,registered_by_user_id) VALUES (%s,'test-module','Test','https://example.test',%s,%s,'[]',%s)",
            (service_id, str(service_id), str(service_id), user),
        )
        db.execute(
            "INSERT INTO module_instances(id,service_id,installation_key,status) VALUES (%s,%s,'test-instance','revoked')",
            (instance_id, service_id),
        )
    with managed.sql_connection(stack) as db:
        with pytest.raises(psycopg.errors.CheckViolation):
            db.execute("UPDATE module_instances SET status='active' WHERE id=%s", (instance_id,))
        db.rollback()
        with pytest.raises(psycopg.errors.CheckViolation):
            db.execute("DELETE FROM module_instances WHERE id=%s", (instance_id,))
        db.rollback()
        with pytest.raises(psycopg.errors.CheckViolation):
            db.execute("TRUNCATE module_instances CASCADE")
