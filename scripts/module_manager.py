"""Operator CLI. DB credentials only through protected configuration/environment."""

import argparse
import asyncio
import json
from uuid import UUID

from fastapi.encoders import jsonable_encoder
from sqlalchemy import select

from app.core.config import Settings
from app.core.database import create_database
from app.domains.installations import executor, service
from app.domains.installations.model import ModuleInstallation, ModuleInstallOperation, ModuleInstallPlan
from app.domains.packages.storage import Storage
from app.domains.registry import load_models


async def execute(args: argparse.Namespace) -> dict[str, object]:
    load_models()
    config = Settings()
    engine, sessions = create_database(config)
    try:
        if args.command == "apply":
            return await executor.apply(
                sessions, config, Storage(config.packages_storage_root), args.plan_id, args.digest
            )
        # Read-only transactions: list/inspect/reconcile never repair or claim jobs.
        async with sessions() as session, session.begin():
            from sqlalchemy import text

            await session.execute(text("SET TRANSACTION READ ONLY"))
            if args.command == "inspect":
                value = await session.get(ModuleInstallPlan, args.plan_id)
                if value is None:
                    raise ValueError("plan_not_found")
                return service.plan_view(value)
            if args.command == "reconcile":
                rows = (
                    await session.scalars(
                        select(ModuleInstallOperation)
                        .where(ModuleInstallOperation.state.in_(["applying", "failed"]))
                        .order_by(ModuleInstallOperation.created_at, ModuleInstallOperation.id)
                        .limit(args.limit)
                        .offset(args.offset)
                    )
                ).all()
                return {
                    "operations": [service.operation_view(row) for row in rows],
                    "read_only": True,
                    "next_action": "Inspect saved plan; retry apply with the original digest after lease expiry and renewed approval if necessary",
                }
            installations = (
                await session.scalars(
                    select(ModuleInstallation)
                    .order_by(ModuleInstallation.module_id)
                    .limit(args.limit)
                    .offset(args.offset)
                )
            ).all()
            return {
                "installations": [
                    {
                        "id": row.id,
                        "module_id": row.module_id,
                        "package_id": row.package_id,
                        "status": row.status,
                        "generation": row.generation,
                    }
                    for row in installations
                ]
            }
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Xarionix trusted operator: no package execution, secrets or SQL in argv"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("list", "inspect", "apply", "reconcile"):
        command = commands.add_parser(name)
        if name in {"inspect", "apply"}:
            command.add_argument("--plan-id", type=UUID, required=True)
        if name == "apply":
            command.add_argument("--digest", required=True)
        if name in {"list", "reconcile"}:
            command.add_argument("--limit", type=int, choices=range(1, 101), default=20)
            command.add_argument("--offset", type=int, default=0)
    args = parser.parse_args()
    if getattr(args, "offset", 0) < 0:
        parser.error("offset must be nonnegative")
    try:
        print(json.dumps(jsonable_encoder(asyncio.run(execute(args))), ensure_ascii=False))
    except Exception:
        # No exception repr, SQL, DB settings, filesystem paths, or token material.
        raise SystemExit(
            "Module operation refused or failed; inspect operation safe_error_code and operator documentation"
        ) from None


if __name__ == "__main__":
    main()
