#!/usr/bin/env python3
"""Aggregate correctness and MP-SPDZ metrics from DORAM regression runs."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from statistics import mean
from typing import Any


TOTAL_TIME = re.compile(r"^Time = ([0-9.eE+-]+) seconds", re.MULTILINE)
TIMER = re.compile(
    r"^Time(\d+) = ([0-9.eE+-]+) seconds "
    r"\(([0-9.eE+-]+) MB, (\d+) rounds,",
    re.MULTILINE,
)
PARTY_DATA = re.compile(
    r"^Data sent = ([0-9.eE+-]+) MB in ~([0-9]+) rounds", re.MULTILINE
)
GLOBAL_DATA = re.compile(r"^Global data sent = ([0-9.eE+-]+) MB", re.MULTILINE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze a run produced by scripts/run_doram_regression.py"
    )
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any batch is missing, failed, or incorrect",
    )
    return parser.parse_args()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_party_zero_log(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    total = TOTAL_TIME.search(text)
    party = PARTY_DATA.search(text)
    global_data = GLOBAL_DATA.search(text)
    timers = {
        int(number): {
            "seconds": float(seconds),
            "party_data_mb": float(data),
            "reported_rounds": int(rounds),
        }
        for number, seconds, data, rounds in TIMER.findall(text)
    }
    if total is None or party is None or global_data is None:
        raise ValueError(f"required MP-SPDZ metrics are missing from {path}")
    candidate_timers = [value for key, value in timers.items() if key >= 20 and key % 2 == 0]
    output_timers = [value for key, value in timers.items() if key >= 21 and key % 2 == 1]
    return {
        "mpc_seconds": float(total.group(1)),
        "party_0_data_mb": float(party.group(1)),
        "reported_rounds": int(party.group(2)),
        "global_data_mb": float(global_data.group(1)),
        "input_seconds": timers.get(10, {}).get("seconds"),
        "first_scan_seconds": timers.get(11, {}).get("seconds"),
        "first_filter_seconds": timers.get(12, {}).get("seconds"),
        "dependent_second_scan_seconds": timers.get(13, {}).get("seconds"),
        "candidate_topk_seconds": sum(item["seconds"] for item in candidate_timers),
        "output_reshare_seconds": sum(item["seconds"] for item in output_timers),
    }


def sum_metric(rows: list[dict[str, Any]], name: str) -> float:
    return float(sum(row[name] for row in rows if row.get(name) is not None))


def analyze_dataset(dataset_dir: Path) -> dict[str, Any]:
    manifest = load_json(dataset_dir / "run_manifest.json")
    expected_batches = int(manifest["batch_count"])
    batch_rows: list[dict[str, Any]] = []
    statuses: dict[str, int] = {}
    correct_queries = 0
    completed_queries = 0
    parse_errors: list[str] = []

    for batch_index in range(expected_batches):
        batch_dir = dataset_dir / f"batch-{batch_index:03d}"
        summary_path = batch_dir / "batch_summary.json"
        if not summary_path.is_file():
            statuses["missing"] = statuses.get("missing", 0) + 1
            continue
        summary = load_json(summary_path)
        status = str(summary.get("status", "invalid"))
        statuses[status] = statuses.get(status, 0) + 1
        if status != "completed":
            continue
        query_count = int(summary["query_count"])
        completed_queries += query_count
        correct_queries += int(summary.get("correct_queries", 0))
        log_path = batch_dir / "logs" / "server-0.log"
        try:
            metrics = parse_party_zero_log(log_path)
        except (OSError, ValueError) as exc:
            parse_errors.append(str(exc))
            continue
        metrics.update(
            {
                "batch_index": batch_index,
                "query_count": query_count,
                "wall_seconds": float(summary.get("wall_seconds", 0)),
                "correct_queries": int(summary.get("correct_queries", 0)),
            }
        )
        batch_rows.append(metrics)

    metric_queries = sum(row["query_count"] for row in batch_rows)
    total_mpc = sum_metric(batch_rows, "mpc_seconds")
    total_wall = sum_metric(batch_rows, "wall_seconds")
    total_global = sum_metric(batch_rows, "global_data_mb")
    total_party = sum_metric(batch_rows, "party_0_data_mb")
    total_rounds = int(sum_metric(batch_rows, "reported_rounds"))
    complete = (
        statuses.get("completed", 0) == expected_batches
        and not parse_errors
        and completed_queries == int(manifest["query_count"])
    )
    correct = complete and correct_queries == completed_queries
    return {
        "dataset": manifest["dataset"],
        "scope": manifest["scope"],
        "requested_queries": int(manifest["query_count"]),
        "unique_base_queries": int(manifest["unique_base_queries"]),
        "expected_batches": expected_batches,
        "batch_statuses": statuses,
        "completed_queries": completed_queries,
        "correct_queries": correct_queries,
        "accuracy_over_completed": (
            correct_queries / completed_queries if completed_queries else None
        ),
        "complete": complete,
        "all_correct": correct,
        "metric_parse_errors": parse_errors,
        "totals": {
            "wall_seconds": total_wall,
            "mpc_seconds": total_mpc,
            "input_seconds": sum_metric(batch_rows, "input_seconds"),
            "first_scan_seconds": sum_metric(batch_rows, "first_scan_seconds"),
            "first_filter_seconds": sum_metric(batch_rows, "first_filter_seconds"),
            "dependent_second_scan_seconds": sum_metric(
                batch_rows, "dependent_second_scan_seconds"
            ),
            "candidate_topk_seconds": sum_metric(batch_rows, "candidate_topk_seconds"),
            "output_reshare_seconds": sum_metric(batch_rows, "output_reshare_seconds"),
            "global_data_mb": total_global,
            "party_0_data_mb": total_party,
            "reported_rounds": total_rounds,
        },
        "averages": {
            "mpc_seconds_per_query": total_mpc / metric_queries if metric_queries else None,
            "wall_seconds_per_query": total_wall / metric_queries if metric_queries else None,
            "global_data_mb_per_query": total_global / metric_queries if metric_queries else None,
            "party_0_data_mb_per_query": total_party / metric_queries if metric_queries else None,
            "reported_rounds_per_query": total_rounds / metric_queries if metric_queries else None,
            "mpc_seconds_per_batch": mean(row["mpc_seconds"] for row in batch_rows)
            if batch_rows
            else None,
        },
        "rounds_warning": manifest["rounds_warning"],
        "batches": batch_rows,
    }


def print_dataset(result: dict[str, Any]) -> None:
    averages = result["averages"]
    totals = result["totals"]
    print(f"Dataset: {result['dataset']}")
    print(f"  scope: {result['scope']}")
    print(
        f"  correctness: {result['correct_queries']}/{result['completed_queries']} "
        f"completed queries; complete={result['complete']}; "
        f"all_correct={result['all_correct']}"
    )
    print(f"  batch statuses: {result['batch_statuses']}")
    if averages["mpc_seconds_per_query"] is not None:
        print(
            f"  MPC time: {totals['mpc_seconds']:.3f}s total; "
            f"{averages['mpc_seconds_per_query']:.3f}s/query amortized"
        )
        print(
            f"  global communication: {totals['global_data_mb']:.3f} MB total; "
            f"{averages['global_data_mb_per_query']:.3f} MB/query amortized"
        )
        print(
            f"  reported rounds: {totals['reported_rounds']}; "
            f"{averages['reported_rounds_per_query']:.1f}/query amortized"
        )
    if result["metric_parse_errors"]:
        print(f"  metric errors: {result['metric_parse_errors']}")
    print(f"  rounds caveat: {result['rounds_warning']}")


def main() -> int:
    args = parse_args()
    run_dir = args.run_dir.resolve()
    candidates = []
    if (run_dir / "run_manifest.json").is_file():
        manifest = load_json(run_dir / "run_manifest.json")
        if isinstance(manifest, dict) and "dataset" in manifest:
            candidates = [run_dir]
    if not candidates:
        candidates = [
            path.parent
            for path in sorted(run_dir.glob("*/run_manifest.json"))
            if isinstance(load_json(path), dict) and "dataset" in load_json(path)
        ]
    if not candidates:
        raise SystemExit(f"no dataset run manifests found under {run_dir}")

    datasets = [analyze_dataset(path) for path in candidates]
    result = {
        "version": 1,
        "run_dir": str(run_dir),
        "all_datasets_complete": all(row["complete"] for row in datasets),
        "all_results_correct": all(row["all_correct"] for row in datasets),
        "datasets": datasets,
    }
    output = args.output.resolve() if args.output else run_dir / "analysis.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for dataset in datasets:
        print_dataset(dataset)
    print(f"Analysis JSON: {output}")
    if args.strict and not (
        result["all_datasets_complete"] and result["all_results_correct"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
