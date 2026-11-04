"""Read-only local engine policy check; no Core token, deployment, pull, or Docker mutation."""

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import ValidationError

from app.domains.deployments.contracts import Delivery
from scripts.deployment_agent.engine import Engine, EngineFailure


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--engine-id", required=True)
    parser.add_argument("--host-id", type=UUID, required=True)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), required=True)
    args = parser.parse_args()
    engine = None
    try:
        # A local validation envelope only, never delivered, persisted or accepted by Core.
        probe = Delivery(
            id=uuid4(),
            fence=uuid4(),
            host_id=args.host_id,
            installation_id=uuid4(),
            operation="inspect",
            generation=1,
            lease_until=datetime.now(UTC) + timedelta(seconds=30),
            package_sha256="0" * 64,
            package_size=1,
            runtime={
                "schema_version": 1,
                "engine": "oci",
                "platform": args.platform,
                "image_digest": "sha256:" + "0" * 64,
                "config_digest": "sha256:" + "0" * 64,
                "health_contract": "http-python-v1",
                "health_port": 8080,
            },
            profile="offline-small-v1",
            engine_id=args.engine_id,
            trust={"schema_version": 1, "keys": []},
        )
        engine = Engine(args.socket, args.engine_id)
        engine.available(probe)
        print(json.dumps({"ready": True, "policy": "offline-small-v1"}))
        return 0
    except EngineFailure as error:
        print(json.dumps({"ready": False, "code": str(error)}))
        return 2
    except (OSError, ValueError, ValidationError):
        print('{"ready":false,"code":"engine_configuration_unavailable"}')
        return 2
    finally:
        if engine:
            engine.close()


if __name__ == "__main__":
    raise SystemExit(main())
