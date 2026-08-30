#!/usr/bin/env python3
"""Run controlled CWQ Temi experiments under localhost and WAN profiles.

The WAN profiles use the repository's unprivileged userspace TCP emulator.
They are not packet-level netem measurements or real multi-host deployments.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PROFILES = {
    "localhost": None,
    "proxy_control_0ms_1000mbps": (0.0, 1000.0),
    "campus_2ms_1000mbps": (2.0, 1000.0),
    "regional_20ms_100mbps": (20.0, 100.0),
    "cross_region_80ms_100mbps": (80.0, 100.0),
    "constrained_80ms_20mbps": (80.0, 20.0),
}


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def summarize(output: Path, runs: list[dict]) -> dict:
    grouped: dict[str, list[dict]] = {}
    for run in runs:
        grouped.setdefault(run["profile"], []).append(run)
    profiles = []
    for name, records in grouped.items():
        completed = [record for record in records if record["status"] == "completed"]
        values = [record["mpc_seconds_per_query"] for record in completed]
        profiles.append(
            {
                "profile": name,
                "attempted_repetitions": len(records),
                "completed_repetitions": len(completed),
                "all_exact": bool(completed) and all(record["all_exact"] for record in completed),
                "median_mpc_seconds_per_query": statistics.median(values) if values else None,
                "min_mpc_seconds_per_query": min(values) if values else None,
                "max_mpc_seconds_per_query": max(values) if values else None,
                "median_global_mb_per_query": (
                    statistics.median(record["global_mb_per_query"] for record in completed)
                    if completed
                    else None
                ),
                "median_runner_wall_seconds": (
                    statistics.median(record["wall_seconds"] for record in completed)
                    if completed
                    else None
                ),
            }
        )
    by_name = {profile["profile"]: profile for profile in profiles}
    localhost = by_name.get("localhost", {}).get("median_mpc_seconds_per_query")
    proxy_control = by_name.get("proxy_control_0ms_1000mbps", {}).get(
        "median_mpc_seconds_per_query"
    )
    for profile in profiles:
        value = profile["median_mpc_seconds_per_query"]
        profile["mpc_slowdown_vs_direct_localhost"] = (
            value / localhost if value is not None and localhost else None
        )
        profile["mpc_slowdown_vs_zero_delay_proxy"] = (
            value / proxy_control if value is not None and proxy_control else None
        )
    summary = {
        "evaluation": "CWQ Temi controlled network-sensitivity experiment",
        "execution_scope": "three MP-SPDZ processes on one physical host",
        "wan_method": "unprivileged userspace TCP payload proxy",
        "real_wan_deployment": False,
        "profiles": profiles,
        "runs": runs,
        "claim_limitations": (
            "Emulated profiles model byte-stream propagation delay and throughput, "
            "not packet loss, kernel queues, route variation, separate host compute, "
            "or independently administered MPC servers."
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture",
        type=Path,
        default=ROOT / "data/cwq/mpc_fixture/q10_closure_c3",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--profiles",
        default="localhost,campus_2ms_1000mbps,regional_20ms_100mbps",
        help=f"Comma-separated names: {', '.join(PROFILES)}",
    )
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=5)
    parser.add_argument("--runtime-timeout", type=int, default=7200)
    parser.add_argument("--compile-timeout", type=int, default=7200)
    args = parser.parse_args()
    args.profiles = [item.strip() for item in args.profiles.split(",") if item.strip()]
    unknown = sorted(set(args.profiles) - set(PROFILES))
    if unknown:
        parser.error(f"unknown profiles: {', '.join(unknown)}")
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")
    return args


def main() -> None:
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    combined_path = args.output / "summary.json"
    if combined_path.exists():
        previous = read_json(combined_path)
        runs = list(previous.get("runs", []))
    else:
        runs = []
    completed_keys = {
        (record.get("profile"), record.get("repetition"))
        for record in runs
        if record.get("status") == "completed"
    }
    for profile_name in args.profiles:
        link = PROFILES[profile_name]
        for repetition in range(1, args.repetitions + 1):
            if (profile_name, repetition) in completed_keys:
                print(
                    f"{profile_name} repetition {repetition}: reusing completed run",
                    flush=True,
                )
                continue
            run_dir = args.output / profile_name / f"rep_{repetition:02d}"
            run_dir.mkdir(parents=True, exist_ok=True)
            terminal_log = run_dir / "terminal.log"
            command = [
                sys.executable,
                "-u",
                str(ROOT / "scripts/run_kqapro_relation_mpc.py"),
                "--fixture",
                str(args.fixture.resolve()),
                "--output",
                str(run_dir),
                "--protocol",
                "temi",
                "--batch-size",
                str(args.batch_size),
                "--runtime-timeout",
                str(args.runtime_timeout),
                "--compile-timeout",
                str(args.compile_timeout),
            ]
            if link is not None:
                rtt_ms, bandwidth_mbps = link
                command.extend(
                    [
                        "--wan-rtt-ms",
                        str(rtt_ms),
                        "--wan-bandwidth-mbps",
                        str(bandwidth_mbps),
                        "--wan-profile-name",
                        profile_name,
                    ]
                )
            print(f"{profile_name} repetition {repetition}: starting", flush=True)
            started = time.perf_counter()
            with terminal_log.open("wb") as log:
                completed = subprocess.run(
                    command,
                    cwd=ROOT,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=args.runtime_timeout * 2,
                )
            wall = time.perf_counter() - started
            record = {
                "profile": profile_name,
                "repetition": repetition,
                "status": "failed" if completed.returncode else "completed",
                "returncode": completed.returncode,
                "wall_seconds": wall,
                "result_directory": str(run_dir),
                "terminal_log": str(terminal_log),
            }
            summary_path = run_dir / "summary.json"
            if completed.returncode == 0 and summary_path.exists():
                result = read_json(summary_path)
                record.update(
                    {
                        "all_exact": result["all_exact"],
                        "queries": result["queries"],
                        "mpc_seconds_per_query": result["amortized_mpc_seconds_per_query"],
                        "global_mb_per_query": result["amortized_global_mb_per_query"],
                        "network_profile": result["network_profile"],
                    }
                )
            runs.append(record)
            completed_keys.add((profile_name, repetition))
            summarize(args.output, runs)
            print(
                f"{profile_name} repetition {repetition}: {record['status']} "
                f"in {wall:.1f}s",
                flush=True,
            )
            if completed.returncode:
                raise SystemExit(
                    f"profile failed; inspect {terminal_log}. Partial summary was saved."
                )
    print(json.dumps(summarize(args.output, runs), indent=2))


if __name__ == "__main__":
    main()
