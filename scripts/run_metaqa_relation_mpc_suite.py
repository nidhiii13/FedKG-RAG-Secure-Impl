#!/usr/bin/env python3
"""Run and aggregate the prepared two-bucket MetaQA q500 Temi suite."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def aggregate(manifest: dict[str, Any], output: Path) -> dict[str, Any]:
    summaries = []
    for bucket in manifest["buckets"]:
        path = output / bucket["bucket"] / "summary.json"
        if path.exists():
            summary = read_json(path)
            if summary.get("all_exact"):
                summaries.append({"bucket": bucket["bucket"], **summary})
    questions = sum(item["queries"] for item in summaries)
    mpc_seconds = sum(item["total_mpc_seconds_including_preprocessing"] for item in summaries)
    global_mb = sum(item["total_global_data_mb"] for item in summaries)
    result = {
        "evaluation_label": manifest["evaluation_label"],
        "status": "completed" if questions == manifest["selected_questions"] else "partial",
        "selected_questions": manifest["selected_questions"],
        "securely_executed_distinct_questions": questions,
        "buckets_completed": len(summaries),
        "buckets_total": len(manifest["buckets"]),
        "all_exact": bool(summaries) and all(item["all_exact"] for item in summaries),
        "genuine_query_fields_compared": sum(
            sum(batch.get("genuine_query_fields_compared", batch["fields_compared"])
                for batch in item["batches"])
            for item in summaries
        ),
        "total_mpc_seconds_including_preprocessing": mpc_seconds,
        "total_global_data_mb": global_mb,
        "amortized_mpc_seconds_per_distinct_query": mpc_seconds / questions if questions else None,
        "amortized_global_mb_per_distinct_query": global_mb / questions if questions else None,
        "protocol": "temi",
        "measurement_scope": "three MP-SPDZ parties on localhost",
        "privacy_scope": manifest["public_leakage"],
        "bucket_summaries": summaries,
    }
    write_json(output / "summary.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite",
        type=Path,
        default=Path("data/metaqa/relation_fixture/q500_private_bucket_suite_b8"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/metaqa_mpc_temi_q500_private_bucket_suite"),
    )
    parser.add_argument("--mpspdz-home", type=Path, default=Path("external/MP-SPDZ"))
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--compiler-budget", type=int, default=10000)
    parser.add_argument("--compile-timeout", type=int, default=21600)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 10:
        parser.error("--batch-size must be in [1, 10]")

    manifest = read_json(args.suite / "manifest.json")
    args.output.mkdir(parents=True, exist_ok=True)
    for bucket in manifest["buckets"]:
        name = bucket["bucket"]
        summary_path = args.output / name / "summary.json"
        if args.resume and summary_path.exists() and read_json(summary_path).get("all_exact"):
            print(f"{name}: reusing completed exact result", flush=True)
            continue
        command = [
            sys.executable,
            str(ROOT / "scripts/run_kqapro_relation_mpc.py"),
            "--fixture", bucket["fixture"],
            "--output", str(args.output / name),
            "--mpspdz-home", str(args.mpspdz_home),
            "--batch-size", str(args.batch_size),
            "--protocol", "temi",
            "--compile-timeout", str(args.compile_timeout),
            "--runtime-timeout", str(args.runtime_timeout),
            "--resume",
        ]
        environment = dict(os.environ)
        environment["MP_SPDZ_BUDGET"] = str(args.compiler_budget)
        print(f"running {name}: {bucket['questions']} questions", flush=True)
        subprocess.run(command, check=True, env=environment)
        print(json.dumps(aggregate(manifest, args.output), indent=2), flush=True)
    print(json.dumps(aggregate(manifest, args.output), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
