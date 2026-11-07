from uuid import uuid4

import pytest
from xarionix_sdk.configuration import Configuration


def document():
    return {
        "schema_version": 1,
        "installation_id": str(uuid4()),
        "installation_generation": 3,
        "module_id": "hello-business",
        "package_version": "1.1.0",
        "public": {"title": "Деловые записи"},
        "approved": {"max_items_per_company": 100},
        "runtime": {"storage_max_bytes": 67108864},
    }


def test_configuration_is_typed_nonsecret_and_bound_to_installation():
    raw = document()
    value = Configuration.parse(raw)
    assert str(value.installation_id) == raw["installation_id"]
    assert value.installation_generation == 3
    assert value.title == "Деловые записи"


@pytest.mark.parametrize(
    "change",
    [
        {"secret": "denied"},
        {"core_db_password": "denied"},
        {"permissions": ["core.users.read"]},
        {"schema_version": True},
        {"installation_generation": 0},
        {"installation_id": "../other"},
        {"runtime": {"storage_max_bytes": 67108865}},
        {"runtime": {"host_path": "/var/lib/postgresql"}},
        {"approved": {"max_items_per_company": True}},
        {"public": {"title": "x", "token": "denied"}},
    ],
)
def test_configuration_cannot_expand_privileges_or_carry_secrets(change):
    with pytest.raises(ValueError):
        Configuration.parse(document() | change)
