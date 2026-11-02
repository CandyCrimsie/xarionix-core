"""Opt-in, real DB benchmark called ONLY by the disposable integration fixture."""

import json
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import psycopg


def percentiles(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        f"p{p}": round(ordered[min(len(ordered) - 1, int(len(ordered) * p / 100))], 3) for p in (50, 95, 99)
    }


def run(connect: Callable[[], psycopg.Connection[Any]], revision: str, report: Path) -> None:
    """No artificial critical-section delay. Baseline reproduces Sprint 2's gate."""
    resources = [(uuid.uuid4(), uuid.uuid4(), uuid.uuid4()) for _ in range(50)]
    with connect() as db:
        for company_id, user_id, employee_id in resources:
            db.execute("INSERT INTO users(id) VALUES (%s)", (user_id,))
            db.execute(
                "INSERT INTO companies(id,name,slug,created_by_user_id) VALUES (%s,'Benchmark',%s,%s)",
                (company_id, "bench-" + company_id.hex, user_id),
            )
            db.execute(
                "INSERT INTO memberships(id,company_id,user_id,role) VALUES (%s,%s,%s,'owner')",
                (uuid.uuid4(), company_id, user_id),
            )
            db.execute(
                "INSERT INTO employees(id,company_id,display_name) VALUES (%s,%s,'Benchmark')",
                (employee_id, company_id),
            )
    results = []
    for mode in ("same_company", "different_companies"):
        for concurrency in (1, 5, 10, 20, 50):
            stop = threading.Event()
            waits: list[int] = []

            def sample(stop: threading.Event, waits: list[int]) -> None:
                with connect() as db:
                    db.autocommit = True
                    while not stop.is_set():
                        row = db.execute(
                            "SELECT count(*) FROM pg_stat_activity WHERE application_name='xarionix-lock-benchmark' AND wait_event_type='Lock'"
                        ).fetchone()
                        waits.append(int(row[0]) if row else 0)
                        stop.wait(0.01)

            def worker(
                index: int, mode: str = mode, concurrency: int = concurrency
            ) -> tuple[list[float], list[float]]:
                latencies, acquisitions = [], []
                company_id, _, employee_id = resources[0 if mode == "same_company" else index]
                with connect() as db:
                    db.execute("SET application_name='xarionix-lock-benchmark'")
                    db.commit()
                    for _ in range(max(4, 100 // concurrency)):
                        start = time.perf_counter()
                        with db.transaction():
                            if revision == "0002_platform":
                                db.execute("SELECT id FROM platform_settings WHERE id=1 FOR UPDATE")
                            else:
                                db.execute("SELECT core_lock('company',%s,false)", (str(company_id),))
                            acquisitions.append((time.perf_counter() - start) * 1000)
                            db.execute(
                                "UPDATE employees SET position='Measured mutation',updated_at=now() WHERE id=%s",
                                (employee_id,),
                            )
                            db.execute(
                                "INSERT INTO audit_events(id,action,resource_type,resource_id,company_id,details) VALUES (%s,'benchmark.write','employee',%s,%s,'{}')",
                                (uuid.uuid4(), employee_id, company_id),
                            )
                        latencies.append((time.perf_counter() - start) * 1000)
                return latencies, acquisitions

            sampler = threading.Thread(target=sample, args=(stop, waits))
            sampler.start()
            start = time.perf_counter()
            try:
                with ThreadPoolExecutor(concurrency) as pool:
                    values = list(pool.map(worker, range(concurrency)))
            finally:
                elapsed = time.perf_counter() - start
                stop.set()
                sampler.join(timeout=10)
            latencies = [value for group, _ in values for value in group]
            acquisitions = [value for _, group in values for value in group]
            results.append(
                {
                    "mode": mode,
                    "concurrency": concurrency,
                    "operations": len(latencies),
                    "throughput_per_second": round(len(latencies) / elapsed, 2),
                    "latency_ms": percentiles(latencies),
                    "lock_acquisition_ms": percentiles(acquisitions),
                    "waiting_sessions_samples": sum(waits),
                    "samples": len(waits),
                    "max_waiting_sessions": max(waits, default=0),
                }
            )
    report.parent.mkdir(exist_ok=True)
    report.write_text(json.dumps({"revision": revision, "results": results}, indent=2) + "\n")
