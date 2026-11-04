"""Real PostgreSQL/Keycloak/package/approval protocol, not a substitute for the engine E2E test."""

import hashlib
import secrets
import subprocess
import uuid

import httpx
import jwt
import pytest
import test_managed_stack as managed
from runtime_helpers import runtime_package
from test_module_installations import admin, apply, approve, installed, prepare
from test_module_installations import installer as installer

from app.domains.packages.storage import Storage

stack, actors = managed.stack, managed.actors
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def image_archive(stack, tmp_path_factory):
    root = tmp_path_factory.mktemp("runtime-image")
    tag = "xarionix-hello:test-" + uuid.uuid4().hex[:12]
    command = ["docker", "build", "--tag", tag, "examples/modules/hello-runtime"]
    subprocess.run(command, cwd=managed.ROOT, check=True, capture_output=True, timeout=300)
    path = root / "image.tar"
    subprocess.run(
        ["docker", "image", "save", "--output", str(path), tag], check=True, capture_output=True, timeout=120
    )
    yield path
    subprocess.run(["docker", "image", "rm", tag], check=False, capture_output=True, timeout=30)


@pytest.fixture
def deployment_identity(stack, actors):
    name = "deployment-" + uuid.uuid4().hex[:12]
    secret = secrets.token_hex(32)
    with httpx.Client(timeout=20, trust_env=False) as client:
        managed.refresh_test_authentication(stack, client, "integration-admin", None)
        configuration = {
            "clientId": name,
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": secret,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "defaultClientScopes": [],
            "optionalClientScopes": [],
            "protocolMappers": [
                {
                    "name": "sub",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-sub-mapper",
                    "config": {"access.token.claim": "true"},
                },
                {
                    "name": "deployment-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {
                        "included.custom.audience": "xarionix-core-deployment",
                        "access.token.claim": "true",
                        "id.token.claim": "false",
                    },
                },
                {
                    "name": "deployment-purpose",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-hardcoded-claim-mapper",
                    "config": {
                        "claim.name": "xarionix_principal",
                        "claim.value": "deployment",
                        "jsonType.label": "String",
                        "access.token.claim": "true",
                        "id.token.claim": "false",
                    },
                },
            ],
        }
        result = client.post(
            stack["config"]["KEYCLOAK_PUBLIC_URL"] + "/admin/realms/xarionix/clients",
            headers={"Authorization": "Bearer " + stack["admin_token"]},
            json=configuration,
        )
        assert result.status_code == 201

    def token():
        response = httpx.post(
            stack["issuer"] + "/protocol/openid-connect/token",
            data={"grant_type": "client_credentials", "client_id": name, "client_secret": secret},
            timeout=10,
            trust_env=False,
        )
        assert response.status_code == 200
        return response.json()["access_token"]

    # Test registration attests an explicit service-account subject; Core independently verifies every JWT.
    subject = jwt.decode(token(), options={"verify_signature": False})["sub"]
    return managed.IsolatedStack({"client_id": name, "secret": secret, "subject": subject, "token": token})


@pytest.fixture
def runtime_bundle(actors, image_archive, tmp_path):
    suffix = uuid.uuid4().hex[:10]
    module, namespace, publisher = "runtime-" + suffix, "rt" + suffix, "publisher-" + suffix
    path, trust, report, contract = runtime_package(
        tmp_path / "package", source=image_archive, module=module, namespace=namespace, publisher=publisher
    )
    registered = admin(
        actors,
        "POST",
        "/package-publishers",
        json={"publisher_id": publisher, "display_name": "Runtime test"},
    )
    assert registered.status_code == 201, registered.text
    pid = registered.json()["id"]
    key = admin(
        actors,
        "POST",
        f"/package-publishers/{pid}/keys",
        json={"key_id": "test-key", "public_key": trust.keys[0].public_key},
    )
    assert key.status_code == 201, key.text
    assert (
        admin(
            actors, "PUT", f"/package-publishers/{pid}/namespaces", json={"namespaces": [namespace]}
        ).status_code
        == 200
    )
    uploaded = admin(
        actors,
        "POST",
        "/packages",
        headers={"Content-Type": "application/octet-stream"},
        content=path.read_bytes(),
    )
    assert uploaded.status_code == 201, uploaded.text
    storage = Storage(tmp_path / "cas")
    storage.publish(path, report["package_sha256"])
    return {
        "package": uploaded.json(),
        "manifest": {"module": {"id": module}},
        "storage": storage,
        "path": path,
        "contract": contract,
        "publisher": pid,
        "key": key.json()["id"],
        "namespace": namespace,
    }


def host(actors, stack, identity, bundle):
    identifier = str(uuid.uuid4())
    registered = admin(
        actors,
        "POST",
        "/deployment-hosts",
        json={
            "id": identifier,
            "name": "Disposable runtime host",
            "issuer": stack["issuer"],
            "subject": identity["subject"],
            "client_id": identity["client_id"],
            "engine_id": "test-engine-" + uuid.uuid4().hex,
            "platform": bundle["contract"]["platform"],
        },
    )
    assert registered.status_code == 201, registered.text
    return registered.json()


def machine(stack, identity, host_id, method, path, **kwargs):
    with httpx.Client(base_url=stack["config"]["PUBLIC_URL"], timeout=30, trust_env=False) as client:
        return client.request(
            method,
            f"/api/v1/deployment-agent/hosts/{host_id}" + path,
            headers={"Authorization": "Bearer " + identity["token"]()},
            **kwargs,
        )


def runtime_plan(actors, installation, host_id, *, operation="start", generation=0):
    result = admin(
        actors,
        "POST",
        "/deployment-plans",
        json={
            "idempotency_key": str(uuid.uuid4()),
            "installation_id": installation["id"],
            "host_id": host_id,
            "operation": operation,
            "expected_installation_generation": installation["generation"],
            "expected_deployment_generation": generation,
        },
    )
    assert result.status_code == 201, result.text
    return result.json()


def test_install_plan_refresh_creates_new_unapproved_record_without_extending_old_approval(
    actors, runtime_bundle
):
    old = prepare(actors, runtime_bundle)
    approved = approve(actors, old)
    refreshed = admin(actors, "POST", f"/module-install-plans/{old['id']}/refresh")
    assert refreshed.status_code == 201, refreshed.text
    fresh = refreshed.json()
    assert fresh["id"] != old["id"] and fresh["state"] == "pending"
    assert fresh["approved_until"] is None
    previous = admin(actors, "GET", f"/module-install-plans/{old['id']}").json()
    assert previous["state"] == "approved" and previous["approved_until"] == approved["approved_until"]
    assert previous["expires_at"] == old["expires_at"]


@pytest.mark.parametrize("revocation", ["publisher", "key", "namespace"])
async def test_real_control_protocol_and_safe_retirement_without_restoring_trust(
    stack, actors, installer, runtime_bundle, deployment_identity, revocation
):
    bundle, identity = runtime_bundle, deployment_identity
    plan = prepare(actors, bundle)
    approve(actors, plan)
    await apply(installer, bundle, plan)
    installation = installed(actors, bundle["manifest"]["module"]["id"])
    assert installation["runtime"]["mode"] == "oci_v1"
    assert not prepare(actors, bundle, "enable", installation["generation"], ready=False)["plan"]["ready"]
    target = host(actors, stack, identity, bundle)
    plan = runtime_plan(actors, installation, target["id"])
    approved = admin(
        actors, "POST", f"/deployment-plans/{plan['id']}/approve", json={"digest": plan["digest"]}
    )
    assert approved.status_code == 200, approved.text
    received = machine(stack, identity, target["id"], "POST", "/check-in", json={"sequence": 1})
    assert received.status_code == 200, received.text
    job = received.json()["jobs"][0]
    assert (
        job["id"] == approved.json()["job_id"]
        and job["package_sha256"] == bundle["package"]["package_sha256"]
    )
    download = machine(
        stack, identity, target["id"], "GET", f"/jobs/{job['id']}/artifact", params={"fence": job["fence"]}
    )
    assert download.status_code == 200
    assert hashlib.sha256(download.content).hexdigest() == job["package_sha256"]
    assert (
        machine(
            stack,
            identity,
            str(uuid.uuid4()),
            "GET",
            f"/jobs/{job['id']}/artifact",
            params={"fence": job["fence"]},
        ).status_code
        == 403
    )
    assert (
        machine(stack, identity, target["id"], "POST", "/check-in", json={"sequence": 1}).status_code == 409
    )
    with managed.sql_connection(stack) as db:
        db.execute(
            "UPDATE deployment_jobs SET lease_until=now()-interval '1 second' WHERE id=%s", (job["id"],)
        )
    redelivered = machine(stack, identity, target["id"], "POST", "/check-in", json={"sequence": 2})
    assert redelivered.status_code == 200, redelivered.text
    new_job = redelivered.json()["jobs"][0]
    assert new_job["id"] == job["id"] and new_job["fence"] != job["fence"]
    report = {
        "installation_id": installation["id"],
        "generation": job["generation"],
        "image_digest": bundle["contract"]["image_digest"],
        "state": "running",
        "container_id": "f" * 64,  # Protocol attestation fixture, not an actual engine container.
        "health": "healthy",
        "live": True,
        "ready": True,
    }
    assert (
        machine(
            stack,
            identity,
            target["id"],
            "POST",
            f"/jobs/{job['id']}/ack",
            json={"fence": job["fence"], "success": True, "report": report},
        ).status_code
        == 409
    )
    receipt = {"fence": new_job["fence"], "success": True, "report": report}
    acknowledged = machine(stack, identity, target["id"], "POST", f"/jobs/{job['id']}/ack", json=receipt)
    assert acknowledged.status_code == 200, acknowledged.text
    assert (
        machine(stack, identity, target["id"], "POST", f"/jobs/{job['id']}/ack", json=receipt).status_code
        == 200
    )
    enable = prepare(actors, bundle, "enable", installation["generation"])
    approve(actors, enable)
    await apply(installer, bundle, enable)
    installation = installed(actors, bundle["manifest"]["module"]["id"])
    with managed.sql_connection(stack) as db:
        assert db.execute("SELECT core_module_available(%s,90)", (bundle["namespace"],)).fetchone() == (True,)
    if revocation == "publisher":
        result = admin(actors, "POST", f"/package-publishers/{bundle['publisher']}/revoke")
    elif revocation == "key":
        result = admin(
            actors, "POST", f"/package-publishers/{bundle['publisher']}/keys/{bundle['key']}/revoke"
        )
    else:
        result = admin(
            actors, "PUT", f"/package-publishers/{bundle['publisher']}/namespaces", json={"namespaces": []}
        )
    assert result.status_code == 200, result.text
    with managed.sql_connection(stack) as db:
        assert db.execute("SELECT core_module_available(%s,90)", (bundle["namespace"],)).fetchone() == (
            False,
        )
    stopped = machine(
        stack, identity, target["id"], "POST", "/check-in", json={"sequence": 3, "reports": [report]}
    )
    assert stopped.status_code == 200, stopped.text
    safety = stopped.json()["jobs"][0]
    assert safety["operation"] == "quarantine" and safety["generation"] > job["generation"]
    assert (
        machine(
            stack,
            identity,
            target["id"],
            "GET",
            f"/jobs/{safety['id']}/artifact",
            params={"fence": safety["fence"]},
        ).status_code
        == 403
    )
    stopped_report = report | {
        "generation": safety["generation"],
        "state": "stopped",
        "health": "unknown",
        "live": False,
        "ready": False,
    }
    result = machine(
        stack,
        identity,
        target["id"],
        "POST",
        f"/jobs/{safety['id']}/ack",
        json={"fence": safety["fence"], "success": True, "report": stopped_report},
    )
    assert result.status_code == 200, result.text
    retired = admin(
        actors,
        "POST",
        f"/module-installations/{installation['id']}/retire",
        json={"expected_installation_generation": installation["generation"], "state": "retired"},
    )
    assert retired.status_code == 200, retired.text
    # Safe removal needs no new signature/trust approval and cannot regain availability.
    removal = runtime_plan(
        actors, installation, target["id"], operation="deprovision", generation=safety["generation"]
    )
    assert removal["body"]["operation"] == "deprovision"
    with managed.sql_connection(stack) as db:
        assert (
            db.execute(
                "SELECT count(*) FROM module_installation_history WHERE installation_id=%s",
                (installation["id"],),
            ).fetchone()[0]
            >= 2
        )
        assert db.execute("SELECT core_module_available(%s,90)", (bundle["namespace"],)).fetchone() == (
            False,
        )


def test_deployment_tokens_have_no_human_or_business_authority(stack, actors, deployment_identity):
    token = deployment_identity["token"]()
    with httpx.Client(base_url=stack["config"]["PUBLIC_URL"], timeout=10, trust_env=False) as client:
        headers = {"Authorization": "Bearer " + token}
        assert client.get("/api/v1/me", headers=headers).status_code == 401
        assert client.post("/api/v1/module-agent/check-in", headers=headers, json={}).status_code == 401
        assert (
            client.post(
                f"/api/v1/deployment-agent/hosts/{uuid.uuid4()}/check-in", json={"sequence": 1}
            ).status_code
            == 401
        )
    result = actors["request"](
        "admin", "POST", f"/deployment-agent/hosts/{uuid.uuid4()}/check-in", json={"sequence": 1}
    )
    assert result.status_code == 401
