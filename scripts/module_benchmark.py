"""Small disposable HTTP heartbeat measurement; not a production load generator."""

import json
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def run(operations: list[Callable[[], None]], prepare: Callable[[], None], report: Path) -> None:
    results = []
    for concurrency in (1, 4, 12):
        # The fixture resets only disposable per-instance rate-limit timestamps
        # outside the timed region. Each instance is polled once per round.
        prepare()

        def invoke(operation: Callable[[], None]) -> float:
            start = time.perf_counter()
            operation()
            return (time.perf_counter() - start) * 1000

        start = time.perf_counter()
        with ThreadPoolExecutor(concurrency) as pool:
            timings = sorted(pool.map(invoke, operations))
        duration = time.perf_counter() - start
        results.append(
            {
                "concurrency": concurrency,
                "operations": len(timings),
                "throughput_per_second": round(len(timings) / duration, 2),
                "latency_ms": {
                    f"p{p}": round(timings[min(len(timings) - 1, int(len(timings) * p / 100))], 3)
                    for p in (50, 95, 99)
                },
            }
        )
    report.parent.mkdir(exist_ok=True)
    report.write_text(
        json.dumps(
            {"transport": "isolated HTTP including client/connect/JWT/DB/commit", "results": results},
            indent=2,
        )
        + "\n"
    )
