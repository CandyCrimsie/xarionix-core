"""Join bounded file work before releasing its lease, including native Task.cancel()."""

import asyncio
from collections.abc import Callable
from typing import Any


async def file_work[T](function: Callable[..., T], *arguments: Any) -> T:
    worker = asyncio.create_task(asyncio.to_thread(function, *arguments))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        # Cancelling an await cannot stop a thread. Do not unlink its files or unlock CAS early.
        # The worker is finite/bounded and has no DB publication authority.
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not worker.cancelled():
            worker.exception()  # retrieve failure without replacing the original cancellation
        raise
