#!/usr/bin/env python3
"""Run a disjoint list of CWQ MPC domains in one isolated MP-SPDZ home."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.run_cwq_mpc_1000_suite import aggregate  # noqa: E402


def available_memory_gib() -> float:
    values = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        key, raw = line.split(":", 1)
        values[key] = int(raw.strip().split()[0])
    return values["MemAvailable"] / 1024 / 1024


def wait_for_memory(minimum_gib: float, poll_seconds: int) -> None:
    while True:
        available = available_memory_gib()
        if available >= minimum_gib:
            print(f"memory gate: {available:.1f} GiB available", flush=True)
            return
        print(
            f"memory gate: {available:.1f} GiB available; waiting for "
            f"{minimum_gib:.1f} GiB",
            flush=True,
        )
        time.sleep(poll_seconds)


def acquire_worker_lock(home: Path):
    home.mkdir(parents=True, exist_ok=True)
    handle = (home / ".cwq-domain-worker.lock").open("w", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise RuntimeError(f"another domain worker is already using {home}") from exc
    handle.write(f"pid={os.getpid()}\n")
    handle.flush()
    return handle


def update_progress(manifest: dict, output_root: Path) -> dict:
    summaries = []
    for item in manifest["domains"]:
        path = output_root / item["domain"] / "summary.json"
        if not path.exists():
            continue
        summary = json.loads(path.read_text(encoding="utf-8"))
        if not summary.get("all_exact") or summary.get("queries") != item["queries"]:
            continue
        summary["public_first_relation_domain"] = item["domain"]
        summary["public_directory_rows"] = item["directory_rows"]
        summaries.append(summary)
    progress = aggregate(manifest, summaries)
    destination = output_root / "summary.json"
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(progress, indent=2) + "\n", encoding="utf-8")
    temporary.replace(destination)
    return progress


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domains", required=True)
    parser.add_argument(
        "--suite",
        type=Path,
        default=ROOT / "data/cwq/mpc_fixture/cwq_1000_domain_suite_20260904",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=ROOT / "results/cwq_mpc_temi_domain1000_20260904",
    )
    parser.add_argument("--mpspdz-home", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=2)
    parser.add_argument("--compile-timeout", type=int, default=10800)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    parser.add_argument("--compiler-budget", type=int, default=25000)
    parser.add_argument("--min-available-gib", type=float, default=64.0)
    parser.add_argument("--memory-poll-seconds", type=int, default=60)
    parser.add_argument("--max-virtual-gib", type=float, default=180.0)
    parser.add_argument("--nice", type=int, default=10)
    args = parser.parse_args()

    requested = [value.strip() for value in args.domains.split(",") if value.strip()]
    manifest = json.loads((args.suite / "manifest.json").read_text(encoding="utf-8"))
    by_domain = {item["domain"]: item for item in manifest["domains"]}
    unknown = [domain for domain in requested if domain not in by_domain]
    if unknown:
        parser.error(f"unknown domain: {unknown[0]}")
    if not 1 <= args.batch_size <= 10:
        parser.error("--batch-size must be in [1, 10]")
    if args.compiler_budget < 1:
        parser.error("--compiler-budget must be positive")
    if args.min_available_gib <= 0:
        parser.error("--min-available-gib must be positive")
    if args.memory_poll_seconds < 1:
        parser.error("--memory-poll-seconds must be positive")
    if args.max_virtual_gib <= 0:
        parser.error("--max-virtual-gib must be positive")
    if not 0 <= args.nice <= 19:
        parser.error("--nice must be in [0, 19]")

    virtual_limit = int(args.max_virtual_gib * 1024**3)
    resource.setrlimit(resource.RLIMIT_AS, (virtual_limit, virtual_limit))
    if args.nice:
        os.nice(args.nice)

    worker_lock = acquire_worker_lock(args.mpspdz_home.resolve())
    requested.sort(key=lambda domain: by_domain[domain]["directory_rows"])
    environment = os.environ.copy()
    environment["MP_SPDZ_BUDGET"] = str(args.compiler_budget)
    update_progress(manifest, args.output_root)

    completed = []
    for position, domain in enumerate(requested, 1):
        item = by_domain[domain]
        existing_summary = args.output_root / domain / "summary.json"
        if existing_summary.exists():
            existing = json.loads(existing_summary.read_text(encoding="utf-8"))
            if existing.get("all_exact") and existing.get("queries") == item["queries"]:
                completed.append(domain)
                print(f"[{position}/{len(requested)}] reusing completed {domain}", flush=True)
                update_progress(manifest, args.output_root)
                continue
        wait_for_memory(args.min_available_gib, args.memory_poll_seconds)
        print(
            f"[{position}/{len(requested)}] {domain}: {item['queries']} questions, "
            f"{item['directory_rows']:,} physical directory rows",
            flush=True,
        )
        command = [
            sys.executable,
            "-u",
            str(ROOT / "scripts/run_kqapro_relation_mpc.py"),
            "--fixture", str(Path(item["fixture"])),
            "--output", str(args.output_root / domain),
            "--mpspdz-home", str(args.mpspdz_home),
            "--batch-size", str(args.batch_size),
            "--protocol", "temi",
            "--compile-timeout", str(args.compile_timeout),
            "--runtime-timeout", str(args.runtime_timeout),
            "--pad-final-batch",
            "--resume",
        ]
        subprocess.run(command, check=True, env=environment)
        summary = json.loads(
            (args.output_root / domain / "summary.json").read_text(encoding="utf-8")
        )
        if not summary.get("all_exact") or summary.get("queries") != item["queries"]:
            raise RuntimeError(f"{domain} did not complete with exact results")
        completed.append(domain)
        update_progress(manifest, args.output_root)
        print(f"completed {domain}", flush=True)
    print(json.dumps({"completed_domains": completed}, indent=2), flush=True)
    del worker_lock
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
