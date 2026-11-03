"""Real PostgreSQL/Keycloak, real package bytes, separate non-owner installation credentials."""

import asyncio
import copy
import secrets
import uuid
from pathlib import Path

import psycopg
import pytest
import test_managed_stack as managed
from fastapi import HTTPException
from package_helpers import manifest_data, package
from psycopg import sql

from app.core.config import Settings
from app.core.database import create_database
from app.domains.installations import executor
from app.domains.packages.storage import Storage

stack, actors = managed.stack, managed.actors
tenants = managed.tenants
pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]


def admin(actors, method, path, **kwargs):
    return actors["request"]("admin", method, "/platform" + path, **kwargs)


@pytest.fixture(scope="module")
def installer(stack):
    name, secret = "installer_" + uuid.uuid4().hex[:12], secrets.token_hex(32)
    with psycopg.connect(
        host="localhost",
        port=stack["postgres_port"],
        dbname="xarionix_core",
        user="core_bootstrap",
        password=stack["config"]["DB_BOOTSTRAP_PASSWORD"],
    ) as db:
        db.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(name), sql.Literal(secret))
        )
        source = "\n".join(
            line
            for line in (ROOT / "deploy/postgres/module-executor.sql").read_text().splitlines()
            if not line.startswith("\\")
        )
        for variable, value in (("runtime_role", "core_app"), ("installer_role", name)):
            source = source.replace(':"' + variable + '"', sql.Identifier(value).as_string(db)).replace(
                ":'" + variable + "'", sql.Literal(value).as_string(db)
            )
        db.execute(source, prepare=False)
    return Settings(
        environment="development",
        keycloak_mode="managed",
        public_url=stack["config"]["PUBLIC_URL"],
        oidc_issuer=stack["issuer"],
        admin_acr_values=["test-step-up"],
        db_host="localhost",
        db_port=stack["postgres_port"],
        db_user=name,
        db_password=secret,
    )


@pytest.fixture
def bundles(actors, tmp_path):
    storage = Storage(tmp_path / "cas")

    def create(*, module=None, namespace=None, dependencies=None, version="1.0.0", module_type="standard"):
        suffix = uuid.uuid4().hex[:12]
        data = manifest_data(
            publisher="pub-" + suffix,
            module=module or "module-" + suffix,
            namespace=namespace or "mod" + suffix,
            version=version,
        )
        data["module"]["type"] = module_type
        data["dependencies"] = dependencies or []
        path, trust, report = package(tmp_path / suffix, data=data)
        publisher = admin(
            actors,
            "POST",
            "/package-publishers",
            json={"publisher_id": data["publisher"]["id"], "display_name": "Test"},
        )
        assert publisher.status_code == 201, publisher.text
        pid = publisher.json()["id"]
        key = admin(
            actors,
            "POST",
            f"/package-publishers/{pid}/keys",
            json={"key_id": "test-key", "public_key": trust.keys[0].public_key},
        )
        assert key.status_code == 201, key.text
        assert (
            admin(
                actors,
                "PUT",
                f"/package-publishers/{pid}/namespaces",
                json={"namespaces": [data["permissions"]["namespace"]]},
            ).status_code
            == 200
        )
        response = admin(
            actors,
            "POST",
            "/packages",
            content=path.read_bytes(),
            headers={"Content-Type": "application/octet-stream"},
        )
        assert response.status_code == 201, response.text
        storage.publish(path, response.json()["package_sha256"])
        return {
            "package": response.json(),
            "manifest": data,
            "path": path,
            "storage": storage,
            "publisher": pid,
            "key": key.json()["id"],
        }

    return create


def prepare(actors, bundle, action="install", generation=0, *, ready=True):
    response = admin(
        actors,
        "POST",
        "/module-install-plans",
        json={"action": action, "package_id": bundle["package"]["id"], "expected_generation": generation},
    )
    assert response.status_code == 201, response.text
    plan = response.json()
    assert plan["plan"]["ready"] is ready, plan["plan"]["blockers"]
    return plan


def approve(actors, plan):
    response = admin(
        actors, "POST", f"/module-install-plans/{plan['id']}/approve", json={"digest": plan["digest"]}
    )
    assert response.status_code == 200, response.text
    return response.json()


async def apply(installer, bundle, plan, *, fault=executor.no_fault):
    engine, sessions = create_database(installer)
    try:
        return await executor.apply(
            sessions, installer, bundle["storage"], uuid.UUID(plan["id"]), plan["digest"], fault=fault
        )
    finally:
        await engine.dispose()


def installed(actors, module):
    response = admin(actors, "GET", "/module-installations?limit=100")
    assert response.status_code == 200, response.text
    return next(item for item in response.json()["items"] if item["module_id"] == module)


async def test_install_enable_disable_update_rollback_uninstall_and_inert_rbac(
    installer, actors, stack, bundles, tenants
):
    bundle = bundles()
    p = prepare(actors, bundle)
    assert admin(actors, "GET", f"/module-install-plans/{p['id']}").json()["digest"] == p["digest"]
    approve(actors, p)
    first = await apply(installer, bundle, p)
    assert first["state"] == "succeeded" and (await apply(installer, bundle, p))["id"] == first["id"]
    value = installed(actors, bundle["manifest"]["module"]["id"])
    assert value["status"] == "installed_disabled" and value["runtime"]["state"] == "not_provisioned"
    ns = bundle["manifest"]["permissions"]["namespace"]
    with managed.sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM role_permissions WHERE permission_key LIKE %s", (ns + ".%",)
        ).fetchone() == (0,)
        assert db.execute("SELECT state FROM permission_namespaces WHERE name=%s", (ns,)).fetchone() == (
            "disabled",
        )
    # Explicit owner grant, never part of installation. Existing tenant UUID survives.
    company = {"id": tenants["alice"]}
    role = actors["request"](
        "alice",
        "POST",
        f"/companies/{company['id']}/roles",
        json={"code": "module_role", "name": "Module", "permissions": []},
    )
    assert role.status_code == 201, role.text
    for action in ("enable", "disable", "enable"):
        plan = prepare(actors, bundle, action, value["generation"])
        approve(actors, plan)
        await apply(installer, bundle, plan)
        value = installed(actors, value["module_id"])
        with managed.sql_connection(stack) as db:
            assert db.execute("SELECT core_module_available(%s,90)", (ns,)).fetchone() == (
                action == "enable",
            )
    # Same publisher's signed new version, changed definition bumps epoch without deleting grants.
    import json

    from scripts.setup import atomic_write
    from scripts.xpkg import pack

    new = copy.deepcopy(bundle["manifest"])
    new["module"]["version"] = "1.1.0"
    new["permissions"]["definitions"][0]["description"] = "Updated meaning"
    folder = bundle["path"].parent
    atomic_write(folder / "new.json", json.dumps(new))
    alternate = folder / "new.xpkg"
    pack(
        folder / "distribution",
        folder / "new.json",
        folder / "private.key",
        new["publisher"]["id"],
        "test-key",
        alternate,
    )
    response = admin(
        actors,
        "POST",
        "/packages",
        content=alternate.read_bytes(),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 201, response.text
    newer = bundle | {"package": response.json(), "manifest": new, "path": alternate}
    bundle["storage"].publish(alternate, response.json()["package_sha256"])
    for target, action in ((newer, "update"), (bundle, "rollback")):
        if action == "rollback":
            denied = admin(
                actors,
                "POST",
                "/module-install-plans",
                json={
                    "action": "update",
                    "package_id": bundle["package"]["id"],
                    "expected_generation": value["generation"],
                },
            )
            assert (
                denied.status_code == 409
                and denied.json()["detail"]["code"] == "installation_update_requires_newer_version"
            )
        plan = prepare(actors, target, action, value["generation"])
        approve(actors, plan)
        await apply(installer, target, plan)
        value = installed(actors, value["module_id"])
        assert value["package_id"] == target["package"]["id"] and value["status"] == "installed_disabled"
    plan = prepare(actors, bundle, "uninstall", value["generation"])
    approve(actors, plan)
    await apply(installer, bundle, plan)
    value = installed(actors, value["module_id"])
    assert value["status"] == "removed"
    history = admin(actors, "GET", f"/module-installations/{value['id']}/history").json()
    assert history["total"] == 7 and len({h["generation"] for h in history["items"]}) == 7
    with managed.sql_connection(stack) as db:
        assert db.execute(
            "SELECT active,definition_generation FROM permissions WHERE namespace=%s", (ns,)
        ).fetchone() == (False, 4)
        assert db.execute("SELECT count(*) FROM companies WHERE id=%s", (company["id"],)).fetchone() == (1,)


@pytest.mark.parametrize("phase", ["before_catalog", "after_catalog", "before_commit", "after_commit"])
async def test_transactional_failure_and_retry_have_one_history_event(
    phase, installer, actors, stack, bundles
):
    bundle = bundles()
    plan = prepare(actors, bundle)
    approve(actors, plan)

    def fault(current):
        if current == phase:
            raise RuntimeError("injected failure")

    with pytest.raises(RuntimeError):
        await apply(installer, bundle, plan, fault=fault)
    with managed.sql_connection(stack) as db:
        count = db.execute(
            "SELECT count(*) FROM module_installations WHERE module_id=%s",
            (bundle["manifest"]["module"]["id"],),
        ).fetchone()[0]
        assert count == (1 if phase == "after_commit" else 0)
        assert (
            db.execute(
                "SELECT count(*) FROM permissions WHERE namespace=%s",
                (bundle["manifest"]["permissions"]["namespace"],),
            ).fetchone()[0]
            == count
        )
    assert (await apply(installer, bundle, plan))["state"] == "succeeded"
    value = installed(actors, bundle["manifest"]["module"]["id"])
    assert admin(actors, "GET", f"/module-installations/{value['id']}/history").json()["total"] == 1


async def test_concurrent_plans_and_executor_cannot_duplicate_installation(installer, actors, stack, bundles):
    bundle = bundles()
    plans = [prepare(actors, bundle) for _ in range(2)]
    for plan in plans:
        approve(actors, plan)
    results = await asyncio.gather(
        *(apply(installer, bundle, plan) for plan in plans), return_exceptions=True
    )
    assert sum(isinstance(item, dict) for item in results) == 1
    with managed.sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM module_installations WHERE module_id=%s",
            (bundle["manifest"]["module"]["id"],),
        ).fetchone() == (1,)


@pytest.mark.parametrize("revocation", ["publisher", "key", "grant"])
async def test_current_trust_rechecked_between_approval_and_apply(revocation, installer, actors, bundles):
    bundle = bundles()
    plan = prepare(actors, bundle)
    approve(actors, plan)
    prefix = "/package-publishers/" + bundle["publisher"]
    if revocation == "grant":
        response = admin(actors, "PUT", prefix + "/namespaces", json={"namespaces": []})
    else:
        response = admin(
            actors,
            "POST",
            prefix + ("/revoke" if revocation == "publisher" else f"/keys/{bundle['key']}/revoke"),
        )
    assert response.status_code == 200
    with pytest.raises((HTTPException, ValueError)):
        await apply(installer, bundle, plan)
    assert admin(actors, "GET", f"/module-install-operations/{plan['id']}").json()["state"] == "failed"


def test_plan_auth_digest_immutability_and_cancellation(actors, stack, bundles):
    bundle = bundles()
    plan = prepare(actors, bundle)
    for label in ("alice", "machine"):
        response = actors["request"](
            label,
            "POST",
            f"/platform/module-install-plans/{plan['id']}/approve",
            json={"digest": plan["digest"]},
        )
        assert response.status_code == 403
    assert (
        admin(
            actors, "POST", f"/module-install-plans/{plan['id']}/approve", json={"digest": "a" * 64}
        ).status_code
        == 409
    )
    with managed.sql_connection(stack) as db:
        with pytest.raises(psycopg.errors.CheckViolation):
            db.execute("UPDATE module_install_plans SET body='{}' WHERE id=%s", (plan["id"],))
        db.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute(
                "SELECT core_apply_module_catalog(%s,%s,%s)", (plan["id"], plan["digest"], uuid.uuid4())
            )
        db.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute(
                "INSERT INTO module_install_operations(id,plan_id,correlation_id) VALUES (%s,%s,%s)",
                (uuid.uuid4(), plan["id"], uuid.uuid4()),
            )
    assert (
        admin(
            actors, "POST", f"/module-install-plans/{plan['id']}/cancel", json={"digest": plan["digest"]}
        ).json()["state"]
        == "cancelled"
    )
    assert (
        admin(
            actors, "POST", f"/module-install-plans/{plan['id']}/approve", json={"digest": plan["digest"]}
        ).status_code
        == 409
    )


async def test_missing_dependency_is_reported_but_not_automatically_installed(installer, actors, bundles):
    bundle = bundles(
        dependencies=[
            {"module_id": "absent-module", "publisher_id": "absent-publisher", "version": ">=1.0.0 <2.0.0"}
        ]
    )
    plan = prepare(actors, bundle, ready=False)
    assert "dependencies_unresolved" in plan["plan"]["blockers"]
    assert (
        admin(
            actors, "POST", f"/module-install-plans/{plan['id']}/approve", json={"digest": plan["digest"]}
        ).status_code
        == 409
    )


async def test_terminal_namespace_revocation_and_revocation_during_verification_invalidate_approval(
    installer, actors, bundles
):
    bundle = bundles()
    plan = prepare(actors, bundle)
    approve(actors, plan)
    prefix = f"/package-publishers/{bundle['publisher']}"
    assert admin(actors, "PUT", prefix + "/namespaces", json={"namespaces": []}).status_code == 200
    assert (
        admin(
            actors,
            "PUT",
            prefix + "/namespaces",
            json={"namespaces": [bundle["manifest"]["permissions"]["namespace"]]},
        ).status_code
        == 409
    )
    with pytest.raises((HTTPException, ValueError)):
        await apply(installer, bundle, plan)
    bundle = bundles()
    prefix = f"/package-publishers/{bundle['publisher']}"
    fresh = prepare(actors, bundle)
    approve(actors, fresh)

    def revoke(phase):
        if phase == "after_verification":
            assert admin(actors, "POST", prefix + f"/keys/{bundle['key']}/revoke").status_code == 200

    with pytest.raises(HTTPException, match="installation_package_untrusted_or_incompatible"):
        await apply(installer, bundle, fresh, fault=revoke)


async def test_same_plan_two_executors_and_expired_lease_fencing(installer, actors, stack, bundles):
    bundle = bundles()
    plan = prepare(actors, bundle)
    approve(actors, plan)
    engine, sessions = create_database(installer)
    try:
        # Simulate a terminated worker: only its durable claim is committed.
        _, _, old_fence, _ = await executor.claim(sessions, installer, uuid.UUID(plan["id"]), plan["digest"])
        with psycopg.connect(
            host="localhost",
            port=stack["postgres_port"],
            dbname="xarionix_core",
            user=installer.db_user,
            password=installer.db_password.get_secret_value(),
        ) as db:
            db.execute(
                "UPDATE module_install_operations SET lease_until=now()-interval '1 second' WHERE id=%s",
                (plan["id"],),
            )
        outcomes = await asyncio.gather(
            apply(installer, bundle, plan), apply(installer, bundle, plan), return_exceptions=True
        )
        assert any(isinstance(value, dict) and value["state"] == "succeeded" for value in outcomes)
        assert (await apply(installer, bundle, plan))["state"] == "succeeded"
        with psycopg.connect(
            host="localhost",
            port=stack["postgres_port"],
            dbname="xarionix_core",
            user=installer.db_user,
            password=installer.db_password.get_secret_value(),
        ) as db:
            new_fence = db.execute(
                "SELECT fence FROM module_install_operations WHERE id=%s", (plan["id"],)
            ).fetchone()[0]
            assert new_fence != old_fence
            assert db.execute(
                "SELECT count(*) FROM module_installation_history WHERE operation_id=%s", (plan["id"],)
            ).fetchone() == (1,)
    finally:
        await engine.dispose()


async def test_corrupt_cas_and_expired_approval_never_mutate_catalog(
    installer, actors, stack, bundles, monkeypatch
):
    from datetime import UTC, datetime, timedelta

    from app.domains.installations import service
    from app.domains.packages.codec import PackageError

    bundle = bundles()
    plan = prepare(actors, bundle)
    approve(actors, plan)
    blob = bundle["storage"].blob(bundle["package"]["package_sha256"])
    blob.chmod(0o600)
    blob.write_bytes(b"corrupt")
    with pytest.raises(PackageError):
        await apply(installer, bundle, plan)
    # Restore only this deliberately corrupted disposable CAS object for the expiry test.
    blob.write_bytes(bundle["path"].read_bytes())
    blob.chmod(0o400)
    monkeypatch.setattr(service, "now", lambda ctx: datetime.now(UTC) + timedelta(seconds=601))
    with pytest.raises(HTTPException, match="installation_approval_expired"):
        await apply(installer, bundle, plan)
    with managed.sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM module_installations WHERE module_id=%s",
            (bundle["manifest"]["module"]["id"],),
        ).fetchone() == (0,)


def test_separate_executor_cannot_write_catalog_or_take_ownership(installer, stack):
    config = dict(
        host="localhost",
        port=stack["postgres_port"],
        dbname="xarionix_core",
        user=installer.db_user,
        password=installer.db_password.get_secret_value(),
    )
    for command in (
        "UPDATE permissions SET active=false",
        "ALTER TABLE permissions DISABLE TRIGGER ALL",
        "SET ROLE xarionix_module_catalog",
        "TRUNCATE audit_events",
        "ALTER FUNCTION core_apply_module_catalog(uuid,text,uuid) SECURITY INVOKER",
        "CREATE TABLE unsafe_installation(id integer)",
    ):
        with psycopg.connect(**config) as db:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                db.execute(command)
    with managed.sql_connection(stack) as db:
        db.execute("SET xarionix.deployment_context='trusted'")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute(
                "INSERT INTO permission_namespaces(name,owner,state) VALUES ('forgednamespace','forged-module','active')"
            )
