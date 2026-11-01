"""Explicit server-side operations, never a public bootstrap endpoint."""

import argparse
import asyncio
from uuid import UUID

from sqlalchemy import func, select

from app.core.access import Context, audit, fail, human_user, mutation_gate
from app.core.config import Settings
from app.core.database import create_database
from app.domains.identity.model import Identity
from app.domains.platform.model import PlatformAdmin
from app.domains.platform.service import classify
from app.domains.registry import load_models
from app.domains.users.model import User


async def execute(args: argparse.Namespace) -> None:
    load_models()
    config = Settings()
    engine, sessions = create_database(config)
    try:
        async with sessions() as session, session.begin():
            await mutation_gate(session)
            identity = await session.get(Identity, args.identity_id)
            if identity is None:
                raise ValueError("Existing Identity UUID required")
            user = await session.get(User, identity.user_id)
            if user is None or user.status != "active":
                raise ValueError("Active existing User required")
            ctx = Context(session, identity, user, config, {}, "operator-cli", operator=True)
            if args.command == "classify":
                # Operator already verified UUID/IdP mapping out of band. No JWT inference.
                await classify(ctx, identity.id, args.principal_type)
            else:
                await human_user(session, user.id)
                active = await session.scalar(
                    select(func.count()).select_from(PlatformAdmin).where(PlatformAdmin.active.is_(True))
                )
                current = await session.get(PlatformAdmin, user.id)
                if args.command == "bootstrap" and active:
                    if current and current.active:
                        print("Platform admin already present; no change")
                        return
                    fail(409, "bootstrap_already_completed")
                if args.command == "recover" and (
                    not args.confirm_recovery or not args.reason or not 10 <= len(args.reason.strip()) <= 500
                ):
                    raise ValueError("Recovery requires --confirm-recovery and a meaningful --reason")
                if current is None:
                    session.add(PlatformAdmin(user_id=user.id, active=True))
                else:
                    current.active = True
                # Offline recovery can restore another explicitly verified existing human
                # when prior admins lost IdP access; it never trusts email or resets IdP.
                audit(
                    ctx,
                    "platform_admin.recovered"
                    if args.command == "recover"
                    else "platform_admin.bootstrapped",
                    "user",
                    user.id,
                    operator=True,
                    reason=args.reason if args.command == "recover" else None,
                )
        print("Operator action committed; audit recorded")
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Server operator only; no passwords/tokens on command line")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("classify", "bootstrap", "recover"):
        command = commands.add_parser(name)
        command.add_argument("--identity-id", type=UUID, required=True)
        if name == "classify":
            command.add_argument(
                "--principal-type", choices=("human", "service", "unclassified"), required=True
            )
        if name == "recover":
            command.add_argument("--confirm-recovery", action="store_true")
            command.add_argument("--reason")
    args = parser.parse_args()
    try:
        asyncio.run(execute(args))
    except Exception:
        # No SQL, settings, JWT or traceback in operator logs.
        raise SystemExit(
            "Operator action refused or failed; verify UUID, policy and database locally"
        ) from None


if __name__ == "__main__":
    main()
