#!/usr/bin/env python3
"""Compare packed PIR+MP-SPDZ against pure bucketized MP-SPDZ on the same queries."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run side-by-side secure retrieval comparisons.")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--queries-jsonl", required=True, type=Path)
    parser.add_argument("--pir-index-dir", required=True, type=Path)
    parser.add_argument("--pure-mpc-index-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--max-queries", type=int, default=1)
    parser.add_argument("--semantic-bucket-mode", choices=("alias", "lsh", "hybrid"), default="alias")
    parser.add_argument("--max-query-buckets", type=int, default=1)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--parties", type=int, default=3)
    parser.add_argument("--threshold", type=int, default=2)
    parser.add_argument("--go-routines", type=int, default=8)
    parser.add_argument("--mp-spdz-protocol", choices=("semi", "atlas"), default="semi")
    parser.add_argument("--mp-spdz-home", type=Path, default=Path("external/MP-SPDZ"))
    parser.add_argument("--pure-left-cap", type=int, default=8)
    parser.add_argument("--pure-right-cap", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument(
        "--pure-timeout",
        type=float,
        default=300.0,
        help="Timeout for the pure bucketized MP-SPDZ baseline.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.mp_spdz_home = _resolve_repo_relative(args.mp_spdz_home)
    if not os.environ.get("FEDKG_SETUP_KEY"):
        raise SystemExit("FEDKG_SETUP_KEY is required")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    pir_output = args.output_dir / "packed_pir_mpspdz.jsonl"
    pir_log = args.output_dir / "packed_pir_mpspdz.log"
    pure_output = args.output_dir / "pure_bucketized_mpspdz.jsonl"
    pure_instance = args.output_dir / "pure_bucketized_instance"
    summary_output = args.output_dir / "comparison_summary.json"

    pir_started = time.perf_counter()
    pir = _run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_numeric_pir_mpspdz_batch.py"),
            "--index-dir",
            str(args.pir_index_dir),
            "--queries-jsonl",
            str(args.queries_jsonl),
            "--output",
            str(pir_output),
            "--start",
            str(args.start),
            "--max-queries",
            str(args.max_queries),
            "--semantic-bucket-mode",
            args.semantic_bucket_mode,
            "--max-query-buckets",
            str(args.max_query_buckets),
            "--topk",
            str(args.topk),
            "--parties",
            str(args.parties),
            "--threshold",
            str(args.threshold),
            "--go-routines",
            str(args.go_routines),
            "--mp-spdz-protocol",
            args.mp_spdz_protocol,
            "--setup-parallelism",
            "1",
            "--shard-parallelism",
            "1",
            "--mp-spdz-home",
            str(args.mp_spdz_home),
            "--timeout",
            str(args.timeout),
        ],
        cwd=ROOT,
    )
    pir_seconds = time.perf_counter() - pir_started
    pir_log.write_text(pir.stdout + pir.stderr)

    pure_started = time.perf_counter()
    pure_error = None
    pure_stdout = ""
    pure_stderr = ""
    try:
        pure = _run(
            [
                sys.executable,
                str(ROOT / "mpspdz_client_excluded" / "scripts" / "run_bucketized_mpc_metaqa_batch.py"),
                "--manifest",
                str(args.manifest),
                "--index-dir",
                str(args.pure_mpc_index_dir),
                "--queries-jsonl",
                str(args.queries_jsonl),
                "--output",
                str(pure_output),
                "--instance-dir",
                str(pure_instance),
                "--start-index",
                str(args.start),
                "--max-queries",
                str(args.max_queries),
                "--max-query-buckets",
                str(args.max_query_buckets),
                "--left-candidate-cap",
                str(args.pure_left_cap),
                "--right-candidate-cap",
                str(args.pure_right_cap),
                "--topk",
                str(args.topk),
                "--semantic-bucket-mode",
                args.semantic_bucket_mode,
                "--mp-spdz-home",
                str(args.mp_spdz_home),
            ],
            cwd=ROOT,
            timeout=args.pure_timeout,
        )
        pure_stdout = pure.stdout
        pure_stderr = pure.stderr
    except subprocess.TimeoutExpired as exc:
        pure_stdout = _to_text(exc.stdout)
        pure_stderr = _to_text(exc.stderr)
        pure_error = f"timed out after {args.pure_timeout:.1f}s"
    pure_seconds = time.perf_counter() - pure_started
    (args.output_dir / "pure_bucketized_mpspdz.log").write_text(pure_stdout + pure_stderr)

    pir_records = _read_jsonl(pir_output)
    pure_records = _read_jsonl(pure_output)
    summary = {
        "query_count": args.max_queries,
        "start": args.start,
        "packed_pir_mpspdz": {
            "output": str(pir_output),
            "protocol": args.mp_spdz_protocol,
            "wall_seconds": pir_seconds,
            "avg_wall_seconds": pir_seconds / max(1, len(pir_records)),
            "records": len(pir_records),
            "correct": sum(1 for row in pir_records if row.get("correct")),
            "avg_reported_e2e": _avg(row.get("total_seconds") for row in pir_records),
            "avg_reported_pir": _avg((row.get("pir") or {}).get("time_seconds") for row in pir_records),
            "avg_reported_mpc": _avg(
                ((row.get("mp_spdz") or {}).get("metrics") or {}).get("wall_time_seconds")
                for row in pir_records
            ),
        },
        "pure_bucketized_mpspdz": {
            "output": str(pure_output),
            "wall_seconds": pure_seconds,
            "avg_wall_seconds": pure_seconds / max(1, len(pure_records)),
            "records": len(pure_records),
            "correct": sum(1 for row in pure_records if row.get("bucketized_mpc_correct")),
            "error": pure_error,
            "summary": _last_json_object(pure_stdout),
        },
    }
    summary_output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def _run(command: list[str], *, cwd: Path, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    print("RUN", " ".join(command), flush=True)
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result


def _resolve_repo_relative(path: Path) -> Path:
    if path.is_absolute():
        return path
    return ROOT / path


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _avg(values) -> float | None:
    selected = [float(value) for value in values if value is not None]
    if not selected:
        return None
    return sum(selected) / len(selected)


def _last_json_object(text: str) -> dict | None:
    decoder = json.JSONDecoder()
    last = None
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            last = value
    return last


if __name__ == "__main__":
    raise SystemExit(main())
