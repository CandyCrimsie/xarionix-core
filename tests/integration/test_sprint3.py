"""Real PostgreSQL/Keycloak tests; all resources belong to disposable stacks."""

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest
import test_managed_stack as managed

actors, stack, tenants = managed.actors, managed.stack, managed.tenants
sql_connection = managed.sql_connection

pytestmark = pytest.mark.integration


async def test_sprint3_signed_authentication_context_preflight(stack):
    await managed.test_isolated_realm_authentication_context_is_consistent_for_every_principal(stack)


def new_role(actors, company_id, keys, *, actor="alice", **extra):
    response = actors["request"](
        actor,
        "POST",
        f"/companies/{company_id}/roles",
        json={"code": "role_" + uuid.uuid4().hex[:12], "name": "Инженер", "permissions": keys, **extra},
    )
    assert response.status_code == 201, response.json().get("detail")
    return response.json()


def join(actors, company_id, label="carol"):
    invitation = managed.invite(actors, company_id, recipient=label)
    response = actors["request"](
        label, "POST", "/invitations/accept", json={"company_id": company_id, "secret": invitation["secret"]}
    )
    assert response.status_code == 200, response.json().get("detail")
    return response.json()["id"]


def grant(actors, company_id, member_id, role_id, *, actor="alice"):
    return actors["request"](
        actor, "POST", f"/companies/{company_id}/members/{member_id}/roles", json={"role_id": role_id}
    )


def test_custom_roles_multiple_assignments_revocation_and_audit(actors, tenants, stack):
    call, cid = actors["request"], tenants["alice"]
    member_id = join(actors, cid)
    first = new_role(actors, cid, ["core.employees.manage"])
    second = new_role(actors, cid, ["core.invitations.read"])
    assert grant(actors, cid, member_id, first["id"]).status_code == 204
    assert grant(actors, cid, member_id, second["id"]).status_code == 204
    assert grant(actors, cid, member_id, first["id"]).status_code == 409
    effective = call("carol", "GET", f"/companies/{cid}/me/permissions")
    assert effective.status_code == 200
    assert {"core.employees.manage", "core.invitations.read"} <= set(effective.json()["permissions"])
    assert (
        call(
            "carol", "POST", f"/companies/{cid}/employees", json={"display_name": "Custom role allowed"}
        ).status_code
        == 201
    )
    assert call("alice", "DELETE", f"/companies/{cid}/roles/{first['id']}").status_code == 409
    assert (
        call("alice", "DELETE", f"/companies/{cid}/members/{member_id}/roles/{first['id']}").status_code
        == 204
    )
    assert (
        call(
            "carol", "POST", f"/companies/{cid}/employees", json={"display_name": "Denied after revoke"}
        ).status_code
        == 403
    )
    assert call("alice", "DELETE", f"/companies/{cid}/roles/{first['id']}").status_code == 204
    with sql_connection(stack) as db:
        actions = {
            row[0] for row in db.execute("SELECT action FROM audit_events WHERE company_id=%s", (cid,))
        }
        assert {"role.created", "role.assigned", "role.revoked", "role.deleted"} <= actions
        assert db.execute(
            "SELECT count(*) FROM employees WHERE display_name='Denied after revoke'"
        ).fetchone() == (0,)


@pytest.mark.parametrize(
    "keys,status",
    [
        (["core.unknown.read"], 422),
        (["billing.payments.refund"], 422),
        (["*"], 422),
        (["core.permissions.delegate"], 403),
        (["core.ownership.transfer"], 403),
        (["core.platform.admin"], 422),
    ],
)
def test_unknown_wildcard_and_protected_permissions_cannot_enter_custom_roles(
    actors, tenants, keys, status, stack
):
    cid = tenants["alice"]
    with sql_connection(stack) as db:
        before = db.execute("SELECT count(*) FROM roles WHERE company_id=%s", (cid,)).fetchone()
    response = actors["request"](
        "alice",
        "POST",
        f"/companies/{cid}/roles",
        json={"name": "Denied", "code": "denied_role", "permissions": keys},
    )
    assert response.status_code == status
    with sql_connection(stack) as db:
        assert db.execute("SELECT count(*) FROM roles WHERE company_id=%s", (cid,)).fetchone() == before
        assert db.execute(
            "SELECT count(*) FROM audit_events WHERE company_id=%s AND action='role.created'", (cid,)
        ).fetchone() == (0,)


def test_role_scope_and_composite_foreign_keys_do_not_cross_tenants(actors, tenants, stack):
    call, a, b = actors["request"], tenants["alice"], tenants["bob"]
    value = new_role(actors, a, ["core.employees.manage"])
    assert call("bob", "GET", f"/companies/{a}/roles/{value['id']}").status_code == 404
    assert call("bob", "GET", f"/companies/{b}/roles/{value['id']}").status_code == 404
    assert call("admin", "GET", f"/companies/{a}/roles").status_code == 404
    with sql_connection(stack) as db:
        member_id = db.execute("SELECT id FROM memberships WHERE company_id=%s LIMIT 1", (b,)).fetchone()[0]
    assert grant(actors, b, str(member_id), value["id"], actor="bob").status_code == 404
    with pytest.raises(psycopg.errors.ForeignKeyViolation), sql_connection(stack) as db:
        db.execute(
            "INSERT INTO membership_roles(company_id,membership_id,role_id,origin) VALUES (%s,%s,%s,'custom')",
            (b, member_id, value["id"]),
        )


def test_templates_are_independent_copies_and_system_roles_are_not_editable(actors, tenants, stack):
    call, cid = actors["request"], tenants["alice"]
    templates = call("alice", "GET", "/role-templates?limit=100")
    assert templates.status_code == 200
    selected = templates.json()["items"][0]
    value = new_role(actors, cid, [], template_key=selected["key"], template_version=selected["version"])
    actual = call("alice", "GET", f"/companies/{cid}/roles/{value['id']}/permissions").json()
    assert actual["permissions"] == sorted(selected["permissions"])
    assert (
        call(
            "alice",
            "PUT",
            f"/companies/{cid}/roles/{value['id']}/permissions",
            json={"permissions": [], "expected_version": 1},
        ).status_code
        == 200
    )
    assert call("alice", "GET", "/role-templates?limit=100").json() == templates.json()
    with sql_connection(stack) as db:
        system_id = db.execute(
            "SELECT id FROM roles WHERE company_id=%s AND code='admin'", (cid,)
        ).fetchone()[0]
    assert (
        call(
            "alice",
            "PATCH",
            f"/companies/{cid}/roles/{system_id}",
            json={"name": "Changed", "expected_version": 1},
        ).status_code
        == 403
    )
    assert call("alice", "DELETE", f"/companies/{cid}/roles/{system_id}").status_code == 403
    assert (
        call(
            "alice", "POST", f"/companies/{cid}/roles", json={"name": "Impersonation", "code": "owner"}
        ).status_code
        == 422
    )


def delegated_administrator(actors, cid):
    mid = join(actors, cid)
    capabilities = [
        "core.roles.read",
        "core.roles.create",
        "core.roles.manage",
        "core.roles.assign",
        "core.roles.revoke",
        "core.members.roles.assign",
        "core.employees.manage",
        "core.members.invite",
        "core.invitations.manage",
    ]
    role = new_role(actors, cid, capabilities)
    assert grant(actors, cid, mid, role["id"]).status_code == 204
    response = actors["request"](
        "alice",
        "PUT",
        f"/companies/{cid}/members/{mid}/delegation",
        json={"permissions": ["core.employees.manage", "core.roles.read"]},
    )
    assert response.status_code == 204
    return mid, role


def test_delegation_blocks_self_escalation_and_ungrantable_permissions(actors, tenants, stack):
    call, cid = actors["request"], tenants["alice"]
    mid, own_role = delegated_administrator(actors, cid)
    limited = new_role(actors, cid, ["core.employees.manage"], actor="carol")
    broad = new_role(actors, cid, ["core.company.read"])
    assert grant(actors, cid, mid, broad["id"], actor="carol").status_code == 403
    assert (
        call(
            "carol",
            "PUT",
            f"/companies/{cid}/members/{mid}/delegation",
            json={"permissions": ["core.roles.assign"]},
        ).status_code
        == 403
    )
    assert (
        call(
            "carol",
            "PUT",
            f"/companies/{cid}/roles/{limited['id']}/permissions",
            json={"permissions": ["core.employees.manage", "core.invitations.manage"], "expected_version": 1},
        ).status_code
        == 403
    )
    assert (
        call(
            "carol",
            "PUT",
            f"/companies/{cid}/roles/{own_role['id']}/permissions",
            json={"permissions": ["core.company.read"], "expected_version": 1},
        ).status_code
        == 403
    )
    with sql_connection(stack) as db:
        owner_role = db.execute(
            "SELECT id FROM roles WHERE company_id=%s AND code='owner'", (cid,)
        ).fetchone()[0]
        assert db.execute("SELECT version FROM roles WHERE id=%s", (own_role["id"],)).fetchone() == (1,)
    assert grant(actors, cid, mid, str(owner_role), actor="carol").status_code == 403
    assert (
        call(
            "carol", "POST", "/platform/admins", json={"user_id": actors["identities"]["carol"]["user_id"]}
        ).status_code
        == 403
    )


def test_self_role_expansion_is_rejected_even_when_every_permission_is_delegable(actors, tenants):
    call, cid = actors["request"], tenants["alice"]
    mid, own_role = delegated_administrator(actors, cid)
    current = call("alice", "GET", f"/companies/{cid}/roles/{own_role['id']}/permissions").json()[
        "permissions"
    ]
    # The new read permission is already effective via the protected Member role.
    assert (
        call(
            "alice",
            "PUT",
            f"/companies/{cid}/members/{mid}/delegation",
            json={"permissions": current + ["core.company.read"]},
        ).status_code
        == 204
    )
    response = call(
        "carol",
        "PUT",
        f"/companies/{cid}/roles/{own_role['id']}/permissions",
        json={"permissions": current + ["core.company.read"], "expected_version": 1},
    )
    assert response.status_code == 403 and response.json()["detail"]["code"] == "self_role_expansion_denied"


def test_role_editing_has_optimistic_version_and_transactional_concurrency(actors, tenants):
    call, cid = actors["request"], tenants["alice"]
    value = new_role(actors, cid, ["core.employees.manage"])
    with ThreadPoolExecutor(2) as pool:
        responses = list(
            pool.map(
                lambda name: call(
                    "alice",
                    "PATCH",
                    f"/companies/{cid}/roles/{value['id']}",
                    json={"name": name, "expected_version": 1},
                ),
                ["First", "Second"],
            )
        )
    assert sorted(response.status_code for response in responses) == [200, 409]
    assert call("alice", "GET", f"/companies/{cid}/roles/{value['id']}").json()["version"] == 2


def test_custom_invitation_cannot_grant_stale_or_undelegable_role(actors, tenants, stack):
    call, cid = actors["request"], tenants["alice"]
    _, _ = delegated_administrator(actors, cid)
    role = new_role(actors, cid, ["core.employees.manage"])
    # Member baseline must also be grantable; an invite cannot bypass policy.
    assert (
        call("carol", "POST", f"/companies/{cid}/invitations", json={"role_ids": [role["id"]]}).status_code
        == 403
    )
    issued = call(
        "alice",
        "POST",
        f"/companies/{cid}/invitations",
        json={"role_ids": [role["id"]], "recipient_user_id": actors["identities"]["dave"]["user_id"]},
    )
    assert issued.status_code == 201
    assert (
        call(
            "alice",
            "PUT",
            f"/companies/{cid}/roles/{role['id']}/permissions",
            json={"permissions": ["core.employees.manage", "core.invitations.manage"], "expected_version": 1},
        ).status_code
        == 200
    )
    rejected = call(
        "dave", "POST", "/invitations/accept", json={"company_id": cid, "secret": issued.json()["secret"]}
    )
    assert rejected.status_code == 409 and rejected.json()["detail"]["code"] == "invitation_roles_changed"
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM memberships WHERE company_id=%s AND user_id=%s",
            (cid, actors["identities"]["dave"]["user_id"]),
        ).fetchone() == (0,)


def test_successful_custom_invitation_has_real_assignments_and_revoked_issuer_is_denied(actors, tenants):
    call, cid = actors["request"], tenants["alice"]
    role = new_role(actors, cid, ["core.employees.manage"])
    issued = call("alice", "POST", f"/companies/{cid}/invitations", json={"role_ids": [role["id"]]})
    assert issued.status_code == 201
    assert (
        call(
            "carol",
            "POST",
            "/invitations/accept",
            json={"company_id": cid, "secret": issued.json()["secret"]},
        ).status_code
        == 200
    )
    assert (
        "core.employees.manage"
        in call("carol", "GET", f"/companies/{cid}/me/permissions").json()["permissions"]
    )
    suspended = call(
        "alice",
        "PATCH",
        f"/companies/{cid}/members/{call('carol', 'GET', f'/companies/{cid}/me/permissions').json()['membership_id']}",
        json={"status": "suspended"},
    )
    assert suspended.status_code == 200
    assert call("carol", "GET", f"/companies/{cid}/me/permissions").status_code == 404


def test_sprint2_backfill_preserves_ids_and_matches_protected_system_roles(stack):
    previous = stack["upgrade_snapshot"]
    with sql_connection(stack) as db:
        assert db.execute("SELECT name FROM companies WHERE id=%s", (previous["company"],)).fetchone() == (
            "Preserved company",
        )
        for role in ("owner", "admin", "member"):
            assert db.execute(
                "SELECT m.id,m.user_id,m.role,r.code,mr.origin FROM memberships m JOIN membership_roles mr ON mr.membership_id=m.id AND mr.company_id=m.company_id JOIN roles r ON r.id=mr.role_id AND r.company_id=mr.company_id WHERE m.id=%s",
                (previous[role + "_member"],),
            ).fetchone() == (previous[role + "_member"], previous[role], role, role, "system")
        assert db.execute(
            "SELECT display_name FROM employees WHERE id=%s", (previous["employee"],)
        ).fetchone() == ("Preserved employee",)
        assert db.execute(
            "SELECT status FROM invitations WHERE id=%s", (previous["invitation"],)
        ).fetchone() == ("pending",)
        assert db.execute("SELECT action FROM audit_events WHERE id=%s", (previous["audit"],)).fetchone() == (
            "migration.seed",
        )


def test_real_jwt_recent_iat_does_not_replace_old_authentication_time(actors, stack):
    import httpx

    stale = managed.token(stack, "integration-admin", authentication_time=int(time.time()) - 1000)
    with httpx.Client(base_url=stack["config"]["PUBLIC_URL"], timeout=15, trust_env=False) as client:
        response = client.get("/api/v1/platform/settings", headers={"Authorization": "Bearer " + stale})
        assert response.status_code == 403
        assert response.json() == {"detail": {"code": "configured_recent_mfa_required"}}
    assert actors["request"]("admin", "GET", "/platform/settings").status_code == 200


def test_system_roles_and_compatibility_assignments_are_protected_from_direct_dml(actors, tenants, stack):
    with sql_connection(stack) as db:
        role_id = db.execute(
            "SELECT id FROM roles WHERE company_id=%s AND code='owner'", (tenants["alice"],)
        ).fetchone()[0]
    with pytest.raises(psycopg.errors.InsufficientPrivilege), sql_connection(stack) as db:
        db.execute("UPDATE roles SET name='Tampered' WHERE id=%s", (role_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege), sql_connection(stack) as db:
        db.execute("DELETE FROM role_permissions WHERE role_id=%s", (role_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege), sql_connection(stack) as db:
        db.execute("DELETE FROM membership_roles WHERE role_id=%s", (role_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege), sql_connection(stack) as db:
        db.execute("UPDATE permissions SET protected=false WHERE key='core.ownership.transfer'")


def test_independent_company_mutations_do_not_wait_for_global_settings(actors, tenants, stack):
    with sql_connection(stack) as blocker, ThreadPoolExecutor(2) as pool:
        blocker.execute("SELECT id FROM platform_settings WHERE id=1 FOR UPDATE")
        future = pool.submit(
            actors["request"],
            "bob",
            "POST",
            f"/companies/{tenants['bob']}/employees",
            json={"display_name": "Independent write"},
        )
        try:
            response = future.result(timeout=4)
            assert response.status_code == 201
        finally:
            blocker.rollback()


def test_company_a_lock_does_not_block_company_b(actors, tenants, stack):
    with sql_connection(stack) as blocker, ThreadPoolExecutor(2) as pool:
        blocker.execute("SELECT core_lock('company', %s, false)", (tenants["alice"],))
        future = pool.submit(
            actors["request"],
            "bob",
            "POST",
            f"/companies/{tenants['bob']}/employees",
            json={"display_name": "Another tenant"},
        )
        try:
            assert future.result(timeout=4).status_code == 201
        finally:
            blocker.rollback()


def test_lock_timeout_rolls_back_and_has_safe_http_error(actors, tenants, stack):
    with sql_connection(stack) as blocker, ThreadPoolExecutor(1) as pool:
        blocker.execute("SELECT core_lock('company', %s, false)", (tenants["alice"],))
        future = pool.submit(
            actors["request"],
            "alice",
            "POST",
            f"/companies/{tenants['alice']}/employees",
            json={"display_name": "Must not persist"},
        )
        try:
            response = future.result(timeout=12)
            assert response.status_code == 409
            assert response.json() == {"detail": {"code": "transaction_conflict"}}
        finally:
            blocker.rollback()
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM employees WHERE company_id=%s AND display_name='Must not persist'",
            (tenants["alice"],),
        ).fetchone() == (0,)


def test_real_postgres_deadlock_aborts_one_transaction(stack):
    first, second = str(uuid.uuid4()), str(uuid.uuid4())
    barrier = threading.Barrier(2)

    def conflict(order):
        try:
            with sql_connection(stack) as db:
                db.execute("SELECT core_lock('company', %s, false)", (order[0],))
                barrier.wait(timeout=5)
                db.execute("SELECT core_lock('company', %s, false)", (order[1],))
            return "committed"
        except psycopg.errors.DeadlockDetected:
            return "40P01"

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(conflict, [(first, second), (second, first)]))
    assert sorted(results) == ["40P01", "committed"]


def test_direct_dml_cannot_suspend_last_owner(actors, tenants, stack):
    user_id = actors["identities"]["alice"]["user_id"]
    with pytest.raises(psycopg.errors.CheckViolation), sql_connection(stack) as db:
        db.execute("UPDATE users SET status='suspended' WHERE id=%s", (user_id,))
    with sql_connection(stack) as db:
        assert db.execute("SELECT status FROM users WHERE id=%s", (user_id,)).fetchone() == ("active",)


def test_policy_change_serializes_company_creation_without_global_employee_gate(actors, stack):
    started = threading.Event()

    def create():
        started.set()
        return actors["request"](
            "dave", "POST", "/companies", json={"name": "Policy race", "slug": "policy-race"}
        )

    try:
        with sql_connection(stack) as db, ThreadPoolExecutor(1) as pool:
            db.execute("UPDATE platform_settings SET company_creation_policy='closed' WHERE id=1")
            future = pool.submit(create)
            assert started.wait(timeout=3)
            db.commit()
            assert future.result(timeout=10).status_code == 403
        with sql_connection(stack) as db:
            assert db.execute("SELECT count(*) FROM companies WHERE slug='policy-race'").fetchone() == (0,)
    finally:
        with sql_connection(stack) as db:
            db.execute("UPDATE platform_settings SET company_creation_policy='open' WHERE id=1")


@pytest.mark.parametrize("revoke", ["role", "delegation"])
def test_waiting_role_grant_rechecks_revoked_authorization_at_transaction_time(
    actors, tenants, stack, revoke
):
    cid = tenants["alice"]
    actor_mid, actor_role = delegated_administrator(actors, cid)
    target_mid = join(actors, cid, "dave")
    target_role = new_role(actors, cid, ["core.employees.manage"])
    with sql_connection(stack) as blocker, ThreadPoolExecutor(1) as pool:
        blocker.execute("SELECT core_lock('company',%s,false)", (cid,))
        if revoke == "role":
            blocker.execute(
                "DELETE FROM membership_roles WHERE company_id=%s AND membership_id=%s AND role_id=%s",
                (cid, actor_mid, actor_role["id"]),
            )
        else:
            blocker.execute(
                "DELETE FROM permission_delegations WHERE company_id=%s AND membership_id=%s",
                (cid, actor_mid),
            )
        future = pool.submit(grant, actors, cid, target_mid, target_role["id"], actor="carol")
        deadline = time.monotonic() + 8
        waiting = False
        with sql_connection(stack) as observer:
            observer.autocommit = True
            while time.monotonic() < deadline:
                if observer.execute(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)"
                ).fetchone()[0]:
                    waiting = True
                    break
                threading.Event().wait(0.01)
        try:
            assert waiting, "The real API request must reach the held transaction lock"
        finally:
            blocker.commit()
        response = future.result(timeout=10)
        assert response.status_code == 403
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM membership_roles WHERE company_id=%s AND membership_id=%s AND role_id=%s",
            (cid, target_mid, target_role["id"]),
        ).fetchone() == (0,)
        assert db.execute(
            "SELECT count(*) FROM audit_events WHERE company_id=%s AND action='role.assigned' AND resource_id=%s",
            (cid, target_role["id"]),
        ).fetchone() == (0,)


def test_concurrent_assignments_are_unique_and_independent_company_roles_do_not_block(actors, tenants, stack):
    cid = tenants["alice"]
    mid = join(actors, cid)
    value = new_role(actors, cid, ["core.employees.manage"])
    with ThreadPoolExecutor(2) as pool:
        responses = list(pool.map(lambda _: grant(actors, cid, mid, value["id"]), range(2)))
    assert sorted(item.status_code for item in responses) == [204, 409]
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM membership_roles WHERE company_id=%s AND membership_id=%s AND role_id=%s",
            (cid, mid, value["id"]),
        ).fetchone() == (1,)
    with sql_connection(stack) as blocker, ThreadPoolExecutor(1) as pool:
        blocker.execute("SELECT core_lock('company',%s,false)", (cid,))
        future = pool.submit(new_role, actors, tenants["bob"], ["core.employees.read"], actor="bob")
        try:
            assert future.result(timeout=4)["company_id"] == tenants["bob"]
        finally:
            blocker.rollback()


@pytest.mark.parametrize("operation", ["demote", "suspend_user"])
def test_concurrent_direct_dml_keeps_a_usable_owner_in_affected_company(stack, operation):
    cid, first, second = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    with sql_connection(stack) as db:
        for uid in (first, second):
            db.execute("INSERT INTO users(id) VALUES (%s)", (uid,))
        db.execute(
            "INSERT INTO companies(id,name,slug,created_by_user_id) VALUES (%s,'DML race',%s,%s)",
            (cid, "race-" + cid.hex, first),
        )
        for uid in (first, second):
            db.execute(
                "INSERT INTO memberships(id,company_id,user_id,role) VALUES (%s,%s,%s,'owner')",
                (uuid.uuid4(), cid, uid),
            )
    barrier = threading.Barrier(2)

    def change(uid):
        try:
            with sql_connection(stack) as db:
                barrier.wait(timeout=5)
                if operation == "demote":
                    db.execute(
                        "UPDATE memberships SET role='member' WHERE company_id=%s AND user_id=%s", (cid, uid)
                    )
                else:
                    db.execute("UPDATE users SET status='suspended' WHERE id=%s", (uid,))
            return "committed"
        except psycopg.errors.CheckViolation:
            return "23514"

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(change, (first, second))) == ["23514", "committed"]
    with sql_connection(stack) as db:
        assert db.execute(
            "SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.company_id=%s AND m.role='owner' AND m.status='active' AND u.status='active'",
            (cid,),
        ).fetchone() == (1,)


def test_rbac_audit_commit_failure_rolls_back_role_and_permissions(actors, tenants, stack):
    cid = tenants["alice"]
    with sql_connection(stack) as db:
        before = db.execute("SELECT count(*) FROM roles WHERE company_id=%s", (cid,)).fetchone()
        db.execute("""CREATE FUNCTION test_reject_rbac_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF NEW.action='role.created' THEN RAISE EXCEPTION 'test failure' USING ERRCODE='23514'; END IF;
            RETURN NULL; END $$""")
        db.execute(
            "CREATE CONSTRAINT TRIGGER test_reject_rbac_audit AFTER INSERT ON audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION test_reject_rbac_audit()"
        )
    try:
        response = actors["request"](
            "alice",
            "POST",
            f"/companies/{cid}/roles",
            json={"name": "Rollback", "code": "rollback_role", "permissions": ["core.employees.read"]},
        )
        assert response.status_code == 409
        with sql_connection(stack) as db:
            assert db.execute("SELECT count(*) FROM roles WHERE company_id=%s", (cid,)).fetchone() == before
            assert db.execute(
                "SELECT count(*) FROM audit_events WHERE company_id=%s AND action='role.created'", (cid,)
            ).fetchone() == (0,)
    finally:
        with sql_connection(stack) as db:
            db.execute("DROP TRIGGER test_reject_rbac_audit ON audit_events")
            db.execute("DROP FUNCTION test_reject_rbac_audit()")
