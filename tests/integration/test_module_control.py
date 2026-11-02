"""Real service-account JWTs, PostgreSQL transactions and an outbound-only Docker agent."""

import copy
import json
import secrets
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx
import jwt
import psycopg
import pytest
import test_managed_stack as managed
import yaml

from app.core.config import Settings
from app.domains.modules.model import OPERATIONS
from app.integrations.keycloak.oidc import OIDCVerifier
from scripts import setup
from scripts.module_benchmark import run as benchmark

actors, stack, tenants = managed.actors, managed.stack, managed.tenants
sql_connection = managed.sql_connection
pytestmark = pytest.mark.integration


def machine_request(stack, token, method, path, **kwargs):
    with httpx.Client(base_url=stack["config"]["PUBLIC_URL"], timeout=15, trust_env=False) as client:
        return client.request(
            method, "/api/v1/module-agent" + path, headers={"Authorization": "Bearer " + token}, **kwargs
        )


def heartbeat(module):
    return {
        "instance_id": module["instance"]["id"],
        "protocol_version": 1,
        "health": "healthy",
        "agent_version": "0.1.0",
    }


def ready_for_poll(stack, module):
    with sql_connection(stack) as db:
        db.execute(
            "UPDATE module_instances SET next_check_in_at=NULL WHERE id=%s", (module["instance"]["id"],)
        )


def admin(actors, method, path, **kwargs):
    response = actors["request"]("admin", method, "/platform" + path, **kwargs)
    return response


@pytest.fixture
def modules(actors, stack):
    def create(*, operations=None):
        name, secret = "module-" + uuid.uuid4().hex, secrets.token_hex(32)
        managed.token(
            stack, "integration-admin"
        )  # renew disposable Admin API credentials, never Core runtime
        base = stack["config"]["KEYCLOAK_PUBLIC_URL"]
        with httpx.Client(timeout=15, trust_env=False) as client:
            headers = {"Authorization": "Bearer " + stack["admin_token"]}
            response = client.get(
                base + "/admin/realms/xarionix/clients", params={"clientId": "module-a"}, headers=headers
            )
            assert response.status_code == 200
            template = copy.deepcopy(response.json()[0])
            template.pop("id", None)
            template["clientId"], template["secret"] = name, secret
            for mapper in template["protocolMappers"]:
                mapper.pop("id", None)
            response = client.post(base + "/admin/realms/xarionix/clients", json=template, headers=headers)
            assert response.status_code == 201
            response = client.post(
                stack["issuer"] + "/protocol/openid-connect/token",
                data={"grant_type": "client_credentials", "client_id": name, "client_secret": secret},
            )
            assert response.status_code == 200
            token = response.json()["access_token"]
        # Registration is through the real MFA-protected Platform Admin API.
        claims = jwt.decode(token, options={"verify_signature": False})
        response = admin(
            actors,
            "POST",
            "/module-services",
            json={
                "module_key": "test-autonomous-module",
                "name": "Тестовый модуль",
                "issuer": claims["iss"],
                "subject": claims["sub"],
                "client_id": name,
                "operations": sorted(OPERATIONS if operations is None else operations),
            },
        )
        assert response.status_code == 201, response.json().get("detail")
        service = response.json()
        response = admin(
            actors,
            "POST",
            f"/module-services/{service['id']}/instances",
            json={"installation_key": "installation-" + uuid.uuid4().hex[:12]},
        )
        assert response.status_code == 201, response.json().get("detail")
        return managed.IsolatedStack(
            {
                "token": token,
                "client_id": name,
                "client_secret": secret,
                "service": service,
                "instance": response.json(),
                "claims": claims,
            }
        )

    return create


async def test_real_keycloak_machine_claims_and_no_jit_users(stack, modules):
    module = modules()
    settings = Settings(
        environment="development",
        keycloak_mode="external",
        public_url=stack["config"]["PUBLIC_URL"],
        oidc_issuer=stack["issuer"],
        db_password=stack["config"]["DB_PASSWORD"],
    )
    async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
        claims = await OIDCVerifier(settings, client).verify(
            module["token"], audience=settings.modules_audience
        )
    assert claims["azp"] == module["client_id"] and claims["sub"] != claims["azp"]
    assert claims["typ"] == "Bearer" and claims["xarionix_principal"] == "machine"
    assert UUID_or_none(claims["sub"])
    response = machine_request(stack, module["token"], "POST", "/check-in", json=heartbeat(module))
    assert response.status_code == 200 and response.json()["connection_state"] == "connected"
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM identities WHERE issuer=%s AND subject=%s", (claims["iss"], claims["sub"])
        ).fetchone() == (0,)
        assert (
            db.execute(
                "SELECT last_seen,protocol_version FROM module_instances WHERE id=%s",
                (module["instance"]["id"],),
            ).fetchone()[1]
            == 1
        )


def UUID_or_none(value):
    return uuid.UUID(value)


def test_unknown_account_human_machine_separation_and_no_jit(stack, actors, modules):
    module = modules()
    with httpx.Client(timeout=10, trust_env=False) as client:
        response = client.post(
            stack["issuer"] + "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "module-unknown",
                "client_secret": stack["module_secrets"]["module-unknown"],
            },
        )
        unknown = response.json()["access_token"]
        for path in (
            "/api/v1/me",
            "/api/v1/companies",
            "/api/v1/system/info",
            "/api/v1/platform/module-services",
        ):
            assert (
                client.get(
                    stack["config"]["PUBLIC_URL"] + path,
                    headers={"Authorization": "Bearer " + module["token"]},
                ).status_code
                == 401
            )
    assert machine_request(stack, unknown, "POST", "/check-in", json=heartbeat(module)).status_code == 403
    human = managed.token(stack, "integration-admin")
    assert machine_request(stack, human, "POST", "/check-in", json=heartbeat(module)).status_code == 401
    assert (
        actors["request"](
            "alice",
            "POST",
            "/platform/module-services",
            json={
                key: module["service"][key]
                for key in ("module_key", "name", "issuer", "subject", "client_id", "operations")
            },
        ).status_code
        == 403
    )
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM identities WHERE subject=%s", (module["claims"]["sub"],)
        ).fetchone() == (0,)


def test_registration_cannot_import_human_identity_or_grant_namespaces(stack, actors, modules):
    module = modules()
    payload = {
        key: module["service"][key]
        for key in ("module_key", "name", "issuer", "subject", "client_id", "operations")
    }
    assert admin(actors, "POST", "/module-services", json=payload).status_code == 409
    for changes in (
        {"operations": ["core.platform.admin"]},
        {"operations": ["core.employees.manage"]},
        {"module_key": "core"},
        {"client_secret": "not-accepted"},
        {"callback_url": "http://postgres:5432"},
    ):
        assert admin(actors, "POST", "/module-services", json=payload | changes).status_code == 422
    alice = actors["identities"]["alice"]
    assert (
        admin(
            actors,
            "POST",
            "/module-services",
            json=payload | {"subject": alice["subject"], "client_id": "would-rebind-human"},
        ).status_code
        == 409
    )
    with sql_connection(stack) as db:
        with pytest.raises(psycopg.errors.CheckViolation):
            db.execute(
                "INSERT INTO identities(id,issuer,subject,user_id,principal_type) VALUES (%s,%s,%s,%s,'human')",
                (uuid.uuid4(), module["claims"]["iss"], module["claims"]["sub"], alice["user_id"]),
            )
        db.rollback()
        assert db.execute(
            "SELECT count(*) FROM identities WHERE subject=%s", (module["claims"]["sub"],)
        ).fetchone() == (0,)
        assert db.execute(
            "SELECT count(*) FROM permissions WHERE namespace IN ('erp','billing','oss') OR key LIKE 'core.modules.%'"
        ).fetchone() == (0,)


def test_unknown_instance_other_binding_and_protocol_fail_closed(stack, modules):
    first, second = modules(), modules()
    assert (
        machine_request(stack, first["token"], "POST", "/check-in", json=heartbeat(second)).status_code == 404
    )
    assert (
        machine_request(
            stack,
            first["token"],
            "POST",
            "/check-in",
            json=heartbeat(first) | {"instance_id": str(uuid.uuid4())},
        ).status_code
        == 404
    )
    for changes in (
        {"protocol_version": 2},
        {"protocol_version": True},
        {"company_id": str(uuid.uuid4())},
        {"user_id": str(uuid.uuid4())},
    ):
        assert (
            machine_request(
                stack, first["token"], "POST", "/check-in", json=heartbeat(first) | changes
            ).status_code
            == 422
        )
    assert (
        machine_request(stack, first["token"], "POST", "/check-in", content=b"x" * 17000).status_code == 413
    )
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT last_seen FROM module_instances WHERE id=%s", (first["instance"]["id"],)
        ).fetchone() == (None,)


@pytest.mark.parametrize("scenario", ["wrong_audience", "wrong_issuer", "expired", "signature"])
def test_real_keycloak_tokens_rejected_for_wrong_trust_context(stack, modules, scenario):
    module = modules()
    managed.token(stack, "integration-admin")
    base = stack["config"]["KEYCLOAK_PUBLIC_URL"]
    with httpx.Client(timeout=15, trust_env=False) as client:
        headers = {"Authorization": "Bearer " + stack["admin_token"]}
        response = client.get(
            base + "/admin/realms/xarionix/clients", params={"clientId": module["client_id"]}, headers=headers
        )
        template = response.json()[0]
        issuer = stack["issuer"]
        if scenario == "wrong_audience":
            mapper = next(item for item in template["protocolMappers"] if item["name"] == "machine-audience")
            mapper["config"]["included.custom.audience"] = "not-xarionix-core"
            assert (
                client.put(
                    base
                    + f"/admin/realms/xarionix/clients/{template['id']}/protocol-mappers/models/{mapper['id']}",
                    headers=headers,
                    json=mapper,
                ).status_code
                == 204
            )
        elif scenario == "expired":
            template.setdefault("attributes", {})["access.token.lifespan"] = "1"
            assert (
                client.put(
                    base + f"/admin/realms/xarionix/clients/{template['id']}", headers=headers, json=template
                ).status_code
                == 204
            )
        elif scenario == "wrong_issuer":
            realm = "untrusted-" + uuid.uuid4().hex[:10]
            template.pop("id", None)
            for mapper in template["protocolMappers"]:
                mapper.pop("id", None)
            template["secret"] = module["client_secret"]
            assert (
                client.post(
                    base + "/admin/realms",
                    headers=headers,
                    json={"realm": realm, "enabled": True, "clients": [template]},
                ).status_code
                == 201
            )
            issuer = base + "/realms/" + realm
        response = client.post(
            issuer + "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": module["client_id"],
                "client_secret": module["client_secret"],
            },
        )
        assert response.status_code == 200
        token = response.json()["access_token"]
    claims = jwt.decode(token, options={"verify_signature": False})
    if scenario == "wrong_audience":
        assert "xarionix-core-modules" not in claims["aud"]
    elif scenario == "wrong_issuer":
        assert claims["iss"] != stack["issuer"]
    elif scenario == "expired":
        assert claims["exp"] - claims["iat"] == 1

        def expired():
            assert (
                machine_request(
                    stack, token, "GET", f"/instances/{module['instance']['id']}/companies/{uuid.uuid4()}"
                ).status_code
                == 401
            )

        managed.poll(expired, timeout=25)
    else:
        parts = token.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        token = ".".join(parts)
    assert machine_request(stack, token, "POST", "/check-in", json=heartbeat(module)).status_code == 401
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT last_seen FROM module_instances WHERE id=%s", (module["instance"]["id"],)
        ).fetchone() == (None,)


def test_company_scope_is_explicit_revocable_and_not_human_permissions(stack, actors, tenants, modules):
    module = modules()
    iid, cid = module["instance"]["id"], tenants["alice"]
    path = f"/instances/{iid}/companies/{cid}"
    assert machine_request(stack, module["token"], "GET", path).status_code == 404
    scope_path = f"/module-instances/{iid}/companies/{cid}"
    assert (
        admin(
            actors, "PUT", scope_path, json={"status": "active", "operations": ["core.modules.metadata.read"]}
        ).status_code
        == 200
    )
    response = machine_request(stack, module["token"], "GET", path)
    assert response.status_code == 200 and response.json()["company_id"] == cid
    assert (
        machine_request(
            stack, module["token"], "GET", f"/instances/{iid}/companies/{tenants['bob']}"
        ).status_code
        == 404
    )
    assert (
        admin(
            actors, "PUT", scope_path, json={"status": "active", "operations": ["core.employees.manage"]}
        ).status_code
        == 422
    )
    assert admin(actors, "PUT", scope_path, json={"status": "revoked", "operations": []}).status_code == 200
    assert machine_request(stack, module["token"], "GET", path).status_code == 404


@pytest.mark.parametrize("operation", ["connect", "heartbeat", "metadata.read"])
def test_missing_service_capability_does_not_fall_back_to_realm_roles(stack, modules, operation):
    module = modules(operations=OPERATIONS - {"core.modules." + operation})
    response = machine_request(stack, module["token"], "POST", "/check-in", json=heartbeat(module))
    assert response.status_code == (200 if operation == "metadata.read" else 403)
    if operation == "metadata.read":
        assert (
            machine_request(
                stack,
                module["token"],
                "GET",
                f"/instances/{module['instance']['id']}/companies/{uuid.uuid4()}",
            ).status_code
            == 403
        )


def test_disable_reenable_revoke_and_current_jwt_denial(stack, actors, modules):
    module = modules()
    sid, iid = module["service"]["id"], module["instance"]["id"]
    assert (
        machine_request(stack, module["token"], "POST", "/check-in", json=heartbeat(module)).status_code
        == 200
    )
    for target in (f"/module-instances/{iid}", f"/module-services/{sid}"):
        assert admin(actors, "POST", target + "/disable").status_code == 200
        assert (
            machine_request(stack, module["token"], "POST", "/check-in", json=heartbeat(module)).status_code
            == 403
        )
        assert admin(actors, "POST", target + "/enable").status_code == 200
    assert admin(actors, "POST", f"/module-services/{sid}/revoke").status_code == 200
    assert module["claims"]["exp"] > time.time()
    assert (
        machine_request(stack, module["token"], "POST", "/check-in", json=heartbeat(module)).status_code
        == 403
    )
    assert admin(actors, "POST", f"/module-services/{sid}/enable").status_code == 409
    assert admin(actors, "GET", f"/module-instances/{iid}").json()["connection_state"] == "revoked"


def test_ping_ack_idempotence_foreign_command_and_lease_redelivery(stack, actors, modules):
    first, second = modules(), modules()
    iid = first["instance"]["id"]
    response = admin(actors, "POST", f"/module-instances/{iid}/commands/ping", json={})
    assert response.status_code == 201
    command = response.json()
    response = machine_request(stack, first["token"], "POST", "/check-in", json=heartbeat(first))
    assert [item["id"] for item in response.json()["commands"]] == [command["id"]]
    ready_for_poll(stack, first)
    assert (
        machine_request(stack, first["token"], "POST", "/check-in", json=heartbeat(first)).json()["commands"]
        == []
    )
    with sql_connection(stack) as db:
        db.execute(
            "UPDATE module_commands SET lease_until=now()-interval '1 second' WHERE id=%s", (command["id"],)
        )
    ready_for_poll(stack, first)
    response = machine_request(stack, first["token"], "POST", "/check-in", json=heartbeat(first))
    assert response.json()["commands"][0]["attempt"] == 2
    ack = {"instance_id": iid, "result": {"kind": "pong"}}
    assert (
        machine_request(
            stack,
            second["token"],
            "POST",
            f"/commands/{command['id']}/ack",
            json={**ack, "instance_id": second["instance"]["id"]},
        ).status_code
        == 404
    )
    # Simulate the lost response after COMMIT: sending the same ACK again must not create another effect.
    assert (
        machine_request(stack, first["token"], "POST", f"/commands/{command['id']}/ack", json=ack).status_code
        == 200
    )
    assert (
        machine_request(stack, first["token"], "POST", f"/commands/{command['id']}/ack", json=ack).status_code
        == 200
    )
    assert (
        machine_request(
            stack,
            first["token"],
            "POST",
            f"/commands/{command['id']}/ack",
            json={"instance_id": iid, "result": {"kind": "error", "code": "agent_error"}},
        ).status_code
        == 409
    )
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT state,attempts,result FROM module_commands WHERE id=%s", (command["id"],)
        ).fetchone() == ("completed", 2, {"kind": "pong"})
        assert db.execute(
            "SELECT count(*) FROM audit_events WHERE action='module.command_completed' AND details->>'command_id'=%s",
            (command["id"],),
        ).fetchone() == (1,)


def test_concurrent_pollers_only_claim_one_delivery_and_rate_limit(stack, actors, modules):
    module = modules()
    iid = module["instance"]["id"]
    command = admin(actors, "POST", f"/module-instances/{iid}/commands/ping", json={}).json()
    with ThreadPoolExecutor(2) as pool:
        responses = list(
            pool.map(
                lambda _: machine_request(
                    stack, module["token"], "POST", "/check-in", json=heartbeat(module)
                ),
                range(2),
            )
        )
    assert sorted(item.status_code for item in responses) == [200, 429]
    assert sum(len(item.json().get("commands", [])) for item in responses) == 1
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT attempts FROM module_commands WHERE id=%s", (command["id"],)
        ).fetchone() == (1,)


def test_expiry_bounded_attempts_and_unsupported_commands(stack, actors, modules):
    module = modules()
    iid = module["instance"]["id"]
    assert (
        admin(actors, "POST", f"/module-instances/{iid}/commands/execute_shell", json={}).status_code == 422
    )
    command = admin(actors, "POST", f"/module-instances/{iid}/commands/ping", json={}).json()
    with sql_connection(stack) as db:
        db.execute(
            "UPDATE module_commands SET created_at=now()-interval '30 seconds',expires_at=now()-interval '1 second' WHERE id=%s",
            (command["id"],),
        )
    response = machine_request(stack, module["token"], "POST", "/check-in", json=heartbeat(module))
    assert response.status_code == 200 and not response.json()["commands"]
    assert (
        machine_request(
            stack,
            module["token"],
            "POST",
            f"/commands/{command['id']}/ack",
            json={"instance_id": iid, "result": {"kind": "pong"}},
        ).status_code
        == 409
    )
    command2 = admin(actors, "POST", f"/module-instances/{iid}/commands/ping", json={}).json()
    with sql_connection(stack) as db:
        db.execute(
            "UPDATE module_commands SET state='delivered',attempts=5,lease_until=now()-interval '1 second' WHERE id=%s",
            (command2["id"],),
        )
    ready_for_poll(stack, module)
    assert not machine_request(stack, module["token"], "POST", "/check-in", json=heartbeat(module)).json()[
        "commands"
    ]
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT state FROM module_commands WHERE instance_id=%s ORDER BY created_at", (iid,)
        ).fetchall() == [("expired",), ("expired",)]


def test_command_queue_and_ttl_are_bounded(stack, actors, modules):
    module = modules()
    iid = module["instance"]["id"]
    with sql_connection(stack) as db:
        db.execute(
            "INSERT INTO module_commands(id,instance_id,operation,expires_at,request_id,created_by_user_id) SELECT gen_random_uuid(),%s,'ping',now()+interval '5 minutes','bounded-queue',%s FROM generate_series(1,100)",
            (iid, module["service"]["registered_by_user_id"]),
        )
    assert admin(actors, "POST", f"/module-instances/{iid}/commands/ping", json={}).status_code == 409
    assert (
        admin(
            actors, "POST", f"/module-instances/{iid}/commands/ping", json={"expires_in_seconds": 3601}
        ).status_code
        == 422
    )


def test_independent_heartbeats_do_not_wait_for_global_or_other_instance(stack, modules):
    first, second = modules(), modules()
    with sql_connection(stack) as blocker:
        blocker.execute("SELECT id FROM platform_settings WHERE id=1 FOR UPDATE")
        blocker.execute("SELECT id FROM module_instances WHERE id=%s FOR UPDATE", (first["instance"]["id"],))
        with ThreadPoolExecutor(1) as pool:
            response = pool.submit(
                machine_request, stack, second["token"], "POST", "/check-in", json=heartbeat(second)
            ).result(timeout=4)
        assert response.status_code == 200


def test_stale_and_error_state_is_server_computed(stack, actors, modules):
    module = modules()
    iid = module["instance"]["id"]
    assert admin(actors, "GET", f"/module-instances/{iid}").json()["connection_state"] == "stale"
    assert (
        machine_request(
            stack, module["token"], "POST", "/check-in", json=heartbeat(module) | {"health": "error"}
        ).status_code
        == 200
    )
    assert admin(actors, "GET", f"/module-instances/{iid}").json()["connection_state"] == "error"
    with sql_connection(stack) as db:
        db.execute("UPDATE module_instances SET last_seen=now()-interval '10 minutes' WHERE id=%s", (iid,))
    assert admin(actors, "GET", f"/module-instances/{iid}").json()["connection_state"] == "stale"


def test_machine_ack_and_audit_roll_back_together(stack, actors, modules):
    module = modules()
    iid = module["instance"]["id"]
    command = admin(actors, "POST", f"/module-instances/{iid}/commands/ping", json={}).json()
    assert (
        machine_request(stack, module["token"], "POST", "/check-in", json=heartbeat(module)).status_code
        == 200
    )
    with sql_connection(stack) as db:
        db.execute("""CREATE FUNCTION test_reject_machine_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF NEW.action='module.command_completed' THEN RAISE EXCEPTION 'test failure' USING ERRCODE='23514'; END IF;
            RETURN NULL; END $$""")
        db.execute(
            "CREATE CONSTRAINT TRIGGER test_reject_machine_audit AFTER INSERT ON audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION test_reject_machine_audit()"
        )
    try:
        response = machine_request(
            stack,
            module["token"],
            "POST",
            f"/commands/{command['id']}/ack",
            json={"instance_id": iid, "result": {"kind": "pong"}},
        )
        assert response.status_code == 409
        with sql_connection(stack) as db:
            assert db.execute(
                "SELECT state,result,completed_at FROM module_commands WHERE id=%s", (command["id"],)
            ).fetchone() == ("delivered", None, None)
            assert db.execute(
                "SELECT count(*) FROM audit_events WHERE action='module.command_completed' AND details->>'command_id'=%s",
                (command["id"],),
            ).fetchone() == (0,)
    finally:
        with sql_connection(stack) as db:
            db.execute("DROP TRIGGER test_reject_machine_audit ON audit_events")
            db.execute("DROP FUNCTION test_reject_machine_audit()")


def test_waiting_heartbeat_rechecks_committed_revocation(stack, modules):
    module = modules()
    with sql_connection(stack) as blocker, ThreadPoolExecutor(1) as pool:
        blocker.execute("UPDATE module_services SET status='revoked' WHERE id=%s", (module["service"]["id"],))
        future = pool.submit(
            machine_request, stack, module["token"], "POST", "/check-in", json=heartbeat(module)
        )

        def waiting():
            with sql_connection(stack) as db:
                assert (
                    db.execute(
                        "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%module_services%' "
                    ).fetchone()[0]
                    >= 1
                )

        managed.poll(waiting, timeout=4)
        assert not future.done()
        blocker.commit()
        assert future.result(timeout=4).status_code == 403
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT last_seen FROM module_instances WHERE id=%s", (module["instance"]["id"],)
        ).fetchone() == (None,)


def test_parallel_heartbeat_measurement_real_http(stack, modules):
    participants = [modules() for _ in range(12)]

    def request(module):
        response = machine_request(stack, module["token"], "POST", "/check-in", json=heartbeat(module))
        assert response.status_code == 200

    for module in participants:
        request(module)  # warm JWT/JWKS and connection paths before measurement

    def prepare():
        with sql_connection(stack) as db:
            db.execute(
                "UPDATE module_instances SET next_check_in_at=NULL WHERE id=ANY(%s::uuid[])",
                ([item["instance"]["id"] for item in participants],),
            )

    benchmark(
        [lambda module=item: request(module) for item in participants],
        prepare,
        managed.ROOT / "reports" / "module-heartbeat-benchmark.json",
    )


def test_autonomous_container_outbound_only_roundtrip_and_revocation(stack, actors, modules, tmp_path):
    module = modules()
    iid = module["instance"]["id"]
    project = "xarionix-agent-" + uuid.uuid4().hex[:12]
    compose = {
        "services": {
            "agent": {
                "image": stack["image"],
                "command": ["python", "-m", "scripts.module_agent"],
                "user": "10001:10001",
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "environment": {
                    "XARIONIX_AGENT_CORE_URL": "http://core:8000",
                    "XARIONIX_AGENT_ISSUER": stack["issuer"],
                    "XARIONIX_AGENT_CLIENT_ID": module["client_id"],
                    "XARIONIX_AGENT_CLIENT_SECRET": module["client_secret"],
                    "XARIONIX_AGENT_INSTANCE_ID": iid,
                    "XARIONIX_AGENT_ISOLATED_HTTP": "true",
                    "XARIONIX_AGENT_TEST_OIDC_TRANSPORT": "http://keycloak:8080/realms/xarionix",
                },
                "networks": ["control"],
            }
        },
        "networks": {"control": {"external": True, "name": stack["agent_network"]}},
    }
    path = tmp_path / "agent.yaml"
    setup.atomic_write(path, yaml.safe_dump(compose))
    command = ["docker", "compose", "-p", project, "-f", str(path)]

    def run(*args):
        result = subprocess.run(command + list(args), capture_output=True, timeout=60)
        assert result.returncode == 0, "Isolated outbound agent lifecycle operation failed"
        return result.stdout

    try:
        run("up", "-d")

        def connected():
            value = admin(actors, "GET", f"/module-instances/{iid}").json()
            assert value["connection_state"] == "connected"
            return value

        managed.poll(connected, timeout=45)
        ping = admin(actors, "POST", f"/module-instances/{iid}/commands/ping", json={}).json()
        status = admin(actors, "POST", f"/module-instances/{iid}/commands/get_status", json={}).json()

        def completed():
            with sql_connection(stack) as db:
                assert db.execute(
                    "SELECT count(*) FROM module_commands WHERE id=ANY(%s::uuid[]) AND state='completed'",
                    ([ping["id"], status["id"]],),
                ).fetchone() == (2,)

        managed.poll(completed, timeout=45)
        logs = run("logs", "--no-color", "agent").decode()
        assert (
            "agent_check_in_ok" in logs
            and module["token"] not in logs
            and module["client_secret"] not in logs
        )
        # No published ports/listener, no database or master-admin environment, no socket mount.
        identifier = run("ps", "-q", "agent").decode().strip()
        with sql_connection(stack) as db:
            previous = db.execute("SELECT last_seen FROM module_instances WHERE id=%s", (iid,)).fetchone()[0]
        disconnected = subprocess.run(
            ["docker", "network", "disconnect", stack["agent_network"], identifier],
            capture_output=True,
            timeout=15,
        )
        assert disconnected.returncode == 0

        def retrying():
            assert "agent_retry" in run("logs", "--no-color", "agent").decode()

        managed.poll(retrying, timeout=35)
        reconnected = subprocess.run(
            ["docker", "network", "connect", stack["agent_network"], identifier],
            capture_output=True,
            timeout=15,
        )
        assert reconnected.returncode == 0

        def recovered():
            with sql_connection(stack) as db:
                assert (
                    db.execute("SELECT last_seen FROM module_instances WHERE id=%s", (iid,)).fetchone()[0]
                    > previous
                )

        managed.poll(recovered, timeout=45)
        inspection = subprocess.run(["docker", "inspect", identifier], capture_output=True, timeout=15)
        details = json.loads(inspection.stdout)[0]
        assert not details["HostConfig"]["PortBindings"] and not details["Mounts"]
        assert set(details["NetworkSettings"]["Networks"]) == {stack["agent_network"]}
        assert all(
            not any(key in value.split("=", 1)[0] for key in ("DB_PASSWORD", "KC_ADMIN", "DOCKER_HOST"))
            for value in details["Config"]["Env"]
        )
        assert admin(actors, "POST", f"/module-services/{module['service']['id']}/revoke").status_code == 200

        def stopped():
            result = json.loads(run("ps", "--all", "--format", "json"))
            value = result[0] if isinstance(result, list) else result
            assert value["State"] == "exited" and value["ExitCode"] == 3

        managed.poll(stopped, timeout=30)
    finally:
        run("down", "--remove-orphans")
