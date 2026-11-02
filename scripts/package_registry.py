"""Explicit local operator reconciliation. No implicit cleanup at application startup."""

import argparse
import asyncio
import fcntl
import json

from sqlalchemy import select

from app.core.config import Settings
from app.core.database import create_database
from app.domains.audit.model import AuditEvent
from app.domains.packages.model import ModulePackage
from app.domains.packages.storage import Storage
from app.domains.packages.work import file_work


async def reconcile(*, remove: bool) -> dict[str, int]:
    settings = Settings()
    storage = Storage(settings.packages_storage_root)
    maintenance = storage.lock_file("maintenance.lock")
    engine, sessions = create_database(settings)
    try:
        # Refuse busy rather than block the event loop; upload/reverify holds a SHARED lease.
        fcntl.flock(maintenance, fcntl.LOCK_EX | fcntl.LOCK_NB)
        async with sessions() as session, session.begin():
            references = set((await session.scalars(select(ModulePackage.package_sha256))).all())
        from functools import partial

        report = await file_work(partial(storage.reconcile, references, remove=remove))
        if remove:
            async with sessions() as session, session.begin():
                session.add(
                    AuditEvent(
                        action="package.orphans_cleaned",
                        resource_type="package_storage",
                        details={"actor_kind": "operator", **report},
                    )
                )
        return report
    finally:
        maintenance.close()
        await engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline registry maintenance; run with the package volume mounted"
    )
    parser.add_argument("command", choices=["reconcile"])
    parser.add_argument(
        "--remove-orphans",
        action="store_true",
        help="Explicitly remove ONLY unreferenced package blobs/staging files",
    )
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(reconcile(remove=args.remove_orphans))))
        return 0
    except Exception:
        print('{"code":"registry_reconcile_failed_or_busy"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
