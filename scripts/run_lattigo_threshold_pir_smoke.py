#!/usr/bin/env python3
"""Run the Lattigo multiparty threshold-PIR smoke example."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Lattigo N-party threshold PIR smoke test.")
    parser.add_argument("--lattigo-root", type=Path, default=ROOT / "external" / "lattigo")
    parser.add_argument("--binary", type=Path, default=ROOT / "tools" / "lattigo_threshold_pir" / "lattigo-int-pir")
    parser.add_argument("--parties", type=int, default=3)
    parser.add_argument("--threshold", type=int, default=2)
    parser.add_argument("--go-routines", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--json", action="store_true", help="Emit parsed timing summary as JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    use_binary = args.binary.exists()
    if not use_binary and shutil.which("go") is None:
        raise SystemExit(
            "Go is not installed or not on PATH. Install Go, then rerun this command. "
            "The Lattigo threshold-PIR backend is implemented in Go."
        )
    if not use_binary and not (args.lattigo_root / "examples" / "multiparty" / "int_pir" / "main.go").exists():
        raise SystemExit(f"Lattigo int_pir example not found under {args.lattigo_root}")

    start = time.perf_counter()
    if use_binary:
        command = [str(args.binary), str(args.parties), str(args.threshold), str(args.go_routines)]
        cwd = ROOT
    else:
        command = [
            "go",
            "run",
            "./examples/multiparty/int_pir",
            str(args.parties),
            str(args.threshold),
            str(args.go_routines),
        ]
        cwd = args.lattigo_root
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=args.timeout,
        check=False,
    )
    wall = time.perf_counter() - start
    if args.json:
        print(
            json.dumps(
                {
                    "backend": "lattigo-threshold-pir-smoke",
                    "parties": args.parties,
                    "threshold": args.threshold,
                    "go_routines": args.go_routines,
                    "used_binary": use_binary,
                    "wall_seconds": wall,
                    "parsed_timings": _parse_timings(completed.stdout + completed.stderr),
                    "returncode": completed.returncode,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(completed.stdout, end="")
        print(completed.stderr, file=sys.stderr, end="")
        print(f"fedkg_lattigo_threshold_pir_smoke_seconds={wall:.6f}")
    return completed.returncode


def _parse_timings(output: str) -> dict[str, str]:
    patterns = {
        "setup_done": r"Setup done \(cloud: ([^,]+), party: ([^)]+)\)",
        "query_evaluation": r"> Query Evaluation\s+done \(cloud: ([^,]+), party: ([^)]+)\)",
        "finished": r"> Finished \(total cloud: ([^,]+), total party: ([^)]+)\)",
    }
    parsed = {}
    for name, pattern in patterns.items():
        match = re.search(pattern, output)
        if match:
            parsed[f"{name}_cloud"] = match.group(1).strip()
            parsed[f"{name}_party"] = match.group(2).strip()
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
