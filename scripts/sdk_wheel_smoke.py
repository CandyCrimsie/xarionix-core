"""Import the actual first-party wheel, without Core's editable import paths."""

import sys
from pathlib import Path
from typing import Any


def main() -> None:
    wheel = Path(sys.argv[1]).resolve()
    if not wheel.is_file() or wheel.suffix != ".whl":
        raise ValueError("SDK wheel required")
    sys.path.insert(0, str(wheel))
    import xarionix_sdk
    from xarionix_sdk import Module, ModuleContext
    from xarionix_sdk.storage import SQLiteStorage

    if not str(xarionix_sdk.__file__).startswith(str(wheel) + "/") or SQLiteStorage is None:
        raise ValueError("SDK imported outside the reviewed wheel")
    module = Module(id="wheel-example", namespace="example", version="1.0.0")

    @module.operation("items-read", permission="example.items.read")
    async def read(ctx: ModuleContext, payload: dict[str, Any]) -> dict[str, Any]:
        return {}

    if module.contract()["schema_version"] != 1:
        raise ValueError("SDK protocol mismatch")
    print("Standalone SDK wheel and V1 contract: passed")


if __name__ == "__main__":
    main()
