"""Disposable offline package benchmarks: bounded streams, never external upstream load."""

import argparse
import json
import resource
import subprocess  # nosec B404
import sys
import tempfile
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from app.domains.packages.archive import verify
from app.domains.packages.codec import PackageError
from app.domains.packages.schema import TrustKey, TrustStore
from scripts.xpkg import keygen, pack


def worker(scenario: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="xarionix-package-benchmark-") as name:
        root = Path(name)
        source = root / "distribution/resources"
        source.mkdir(parents=True)
        size, files = (
            (16 * 1024 * 1024, 1)
            if scenario in {"medium", "parallel"}
            else (1024, 512)
            if scenario == "many-files"
            else (64 * 1024, 1)
        )
        for index in range(files):
            with (source / f"artifact-{index}.bin").open("wb") as stream:
                for _ in range(size // 1024):
                    stream.write(b"x" * 1024)
        manifest = {
            "schema_version": 1,
            "module": {"id": "benchmark-module", "name": "Benchmark", "version": "1.0.0", "type": "standard"},
            "publisher": {"id": "benchmark-publisher"},
            "compatibility": {"core": ">=0.1.0 <0.2.0", "module_protocol": 1},
            "permissions": {"namespace": "benchmark", "definitions": []},
            "dependencies": [],
            "artifacts": [],
        }
        template = root / "manifest.json"
        template.write_text(json.dumps(manifest))
        key = keygen(root / "disposable.key", root / "public.txt")
        path = root / "package.xpkg"
        pack(
            root / "distribution",
            template,
            root / "disposable.key",
            "benchmark-publisher",
            "benchmark-key",
            path,
        )
        trust = TrustStore(
            schema_version=1,
            keys=[
                TrustKey(
                    publisher_id="benchmark-publisher",
                    key_id="benchmark-key",
                    public_key=key["public_key"],
                    namespaces=["benchmark"],
                )
            ],
        )
        if scenario == "invalid-early":
            path.write_bytes(b"not-a-package")
        tracemalloc.start()
        start = time.perf_counter()
        verdict = "valid"
        try:
            if scenario == "parallel":
                with ThreadPoolExecutor(2) as pool:
                    list(pool.map(lambda _: verify(path, trust), range(4)))
            else:
                verify(path, trust)
        except PackageError:
            verdict = "rejected"
        elapsed = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform != "darwin":
            rss *= 1024
        total = path.stat().st_size * (4 if scenario == "parallel" else 1)
        return {
            "scenario": scenario,
            "seconds": round(elapsed, 5),
            "python_peak_bytes": peak,
            "process_peak_rss_bytes": rss,
            "payload_files": files,
            "processed_package_bytes": total,
            "mib_per_second": round(total / max(elapsed, 0.000001) / 1024**2, 2),
            "verdict": verdict,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    scenarios = ["small", "medium", "many-files", "parallel", "invalid-early"]
    parser.add_argument("--worker", choices=scenarios)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker)))
        return
    results = []
    for scenario in scenarios:
        # Fixed interpreter/module/allowlisted scenario. Child stdout contains metrics only.
        result = subprocess.run(
            [sys.executable, "-m", "scripts.xpkg_benchmark", "--worker", scenario],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )  # nosec B603
        results.append(json.loads(result.stdout))
    print(json.dumps({"local_observation_not_sla": True, "results": results}, indent=2))


if __name__ == "__main__":
    main()
