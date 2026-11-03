import argparse
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.domains.installations.model import ModuleInstallation, ModuleInstallOperation, ModuleInstallPlan
from scripts import module_manager


@pytest.mark.parametrize("command", ["list", "inspect", "reconcile"])
async def test_operator_read_commands_enforce_read_only_and_never_open_cas(command, settings, monkeypatch):
    monkeypatch.setattr(module_manager, "Settings", lambda: settings)
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock()
    transaction = MagicMock()
    transaction.__aenter__ = AsyncMock()
    transaction.__aexit__ = AsyncMock()
    session.begin.return_value = transaction
    session.execute = AsyncMock()
    session.get = AsyncMock(
        return_value=ModuleInstallPlan(id=uuid.uuid4(), body={}, digest="a" * 64, state="pending")
    )
    row = ModuleInstallation(
        id=uuid.uuid4(),
        module_id="test-module",
        package_id=uuid.uuid4(),
        status="installed_disabled",
        generation=1,
    )
    if command == "reconcile":
        row = ModuleInstallOperation(
            id=uuid.uuid4(),
            plan_id=uuid.uuid4(),
            state="failed",
            attempts=1,
            failures=[],
            correlation_id=uuid.uuid4(),
        )
    result = MagicMock()
    result.all.return_value = [row]
    session.scalars = AsyncMock(return_value=result)
    engine = MagicMock()
    engine.dispose = AsyncMock()
    monkeypatch.setattr(module_manager, "create_database", lambda config: (engine, lambda: session))
    storage = MagicMock()
    monkeypatch.setattr(module_manager, "Storage", storage)
    output = await module_manager.execute(
        argparse.Namespace(command=command, plan_id=uuid.uuid4(), limit=20, offset=0)
    )
    assert output
    assert str(session.execute.call_args.args[0]) == "SET TRANSACTION READ ONLY"
    session.add.assert_not_called()
    storage.assert_not_called()
    engine.dispose.assert_awaited_once()


def test_operator_cli_failure_never_prints_sql_or_credentials(monkeypatch):
    monkeypatch.setattr(
        "sys.argv", ["module-manager", "apply", "--plan-id", str(uuid.uuid4()), "--digest", "a" * 64]
    )
    monkeypatch.setattr(
        module_manager,
        "execute",
        AsyncMock(side_effect=RuntimeError("private-token-value SQL password=secret")),
    )
    with pytest.raises(SystemExit) as error:
        module_manager.main()
    assert "private-token" not in str(error.value) and "password=" not in str(error.value)


@pytest.mark.parametrize(
    "option", ["--skip-verification", "--force", "--disable-signature", "--database-password"]
)
def test_cli_does_not_offer_unsafe_execution_or_secret_arguments(monkeypatch, option):
    monkeypatch.setattr("sys.argv", ["module-manager", "list", option])
    with pytest.raises(SystemExit) as error:
        module_manager.main()
    assert error.value.code == 2
