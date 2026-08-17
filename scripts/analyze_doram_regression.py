#!/usr/bin/env python3
"""Aggregate correctness and MP-SPDZ metrics from oblivious-scan regressions."""

from __future__ import annotations

import argparse
import hashlib
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


def document_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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


def load_expected_document(dataset_dir: Path, expected_batches: int) -> list[Any]:
    expected_path = dataset_dir / "expected.json"
    if expected_path.is_file():
        expected = load_json(expected_path)
        if not isinstance(expected, list):
            raise ValueError(f"expected results must be a JSON list: {expected_path}")
        return expected

    # Older regression artifacts stored the bounded reference inside each
    # batch summary. Preserve analyzability of those runs, but still compare
    # against decoded outputs below instead of trusting summary counters.
    recovered: dict[int, Any] = {}
    for batch_index in range(expected_batches):
        summary_path = dataset_dir / f"batch-{batch_index:03d}" / "batch_summary.json"
        if not summary_path.is_file():
            continue
        summary = load_json(summary_path)
        if not isinstance(summary, dict) or "expected" not in summary:
            continue
        start = int(summary.get("global_query_start", len(recovered)))
        for offset, row in enumerate(summary["expected"]):
            recovered[start + offset] = row
    if not recovered:
        raise ValueError(f"expected.json is missing and no batch references exist: {dataset_dir}")
    return [recovered[index] for index in sorted(recovered)]


def analyze_dataset(dataset_dir: Path) -> dict[str, Any]:
    manifest = load_json(dataset_dir / "run_manifest.json")
    query_document = load_json(dataset_dir / "queries.json")
    if not isinstance(query_document, list):
        raise ValueError(f"queries must be a JSON list: {dataset_dir}")
    expected_batches = int(manifest["batch_count"])
    expected_document = load_expected_document(dataset_dir, expected_batches)
    if not isinstance(expected_document, list):
        raise ValueError(f"expected results must be a JSON list: {dataset_dir}")
    distinct_query_count = len(
        {
            json.dumps(query, sort_keys=True, separators=(",", ":"))
            for query in query_document
        }
    )
    requested_executions = int(
        manifest.get("execution_count", manifest["query_count"])
    )
    if len(query_document) != requested_executions:
        raise ValueError(
            f"queries length {len(query_document)} does not match manifest "
            f"execution count {requested_executions}: {dataset_dir}"
        )
    if len(expected_document) != requested_executions:
        raise ValueError(
            f"expected length {len(expected_document)} does not match manifest "
            f"execution count {requested_executions}: {dataset_dir}"
        )
    batch_rows: list[dict[str, Any]] = []
    statuses: dict[str, int] = {}
    reference_matching_executions = 0
    completed_executions = 0
    parse_errors: list[str] = []
    integrity_errors: list[str] = []
    covered_indices: set[int] = set()

    for batch_index in range(expected_batches):
        batch_dir = dataset_dir / f"batch-{batch_index:03d}"
        summary_path = batch_dir / "batch_summary.json"
        decoded_path = batch_dir / "decoded.json"
        if not summary_path.is_file():
            statuses["missing"] = statuses.get("missing", 0) + 1
            continue
        summary = load_json(summary_path)
        status = str(summary.get("status", "invalid"))
        statuses[status] = statuses.get(status, 0) + 1
        if status != "completed":
            continue
        query_count = int(summary["query_count"])
        start = int(summary.get("global_query_start", batch_index * query_count))
        stop = start + query_count
        if start < 0 or stop > requested_executions:
            integrity_errors.append(
                f"{batch_dir}: query range [{start}, {stop}) is outside "
                f"0..{requested_executions}"
            )
            continue
        overlap = covered_indices.intersection(range(start, stop))
        if overlap:
            integrity_errors.append(
                f"{batch_dir}: overlaps already-covered execution indices"
            )
            continue
        covered_indices.update(range(start, stop))
        try:
            decoded = load_json(decoded_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            integrity_errors.append(f"{decoded_path}: {exc}")
            continue
        expected_slice = expected_document[start:stop]
        query_slice = query_document[start:stop]
        if not isinstance(decoded, list) or len(decoded) != query_count:
            integrity_errors.append(
                f"{decoded_path}: decoded row count does not match summary"
            )
            continue
        if summary.get("query_digest") not in (None, document_digest(query_slice)):
            integrity_errors.append(f"{batch_dir}: query digest mismatch")
        if summary.get("expected_digest") not in (
            None,
            document_digest(expected_slice),
        ):
            integrity_errors.append(f"{batch_dir}: expected digest mismatch")
        if summary.get("decoded_digest") not in (None, document_digest(decoded)):
            integrity_errors.append(f"{batch_dir}: decoded digest mismatch")
        matches = [
            actual == wanted for actual, wanted in zip(decoded, expected_slice)
        ]
        completed_executions += query_count
        reference_matching_executions += sum(matches)
        if "per_execution_reference_match" in summary and summary[
            "per_execution_reference_match"
        ] != matches:
            integrity_errors.append(f"{batch_dir}: reference-match vector mismatch")
        if summary.get("all_outputs_match_bounded_reference") not in (
            None,
            all(matches),
        ):
            integrity_errors.append(f"{batch_dir}: reference-match flag mismatch")
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
                "reference_matching_executions": sum(matches),
                "all_outputs_match_bounded_reference": all(matches),
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
        and not integrity_errors
        and completed_executions == requested_executions
        and len(covered_indices) == requested_executions
    )
    all_match = (
        complete and reference_matching_executions == completed_executions
    )
    return {
        "dataset": manifest["dataset"],
        # Runs predating the backend flag were all packed-scan runs.
        "backend": manifest.get("backend", "packed-scan"),
        "backend_status": manifest.get(
            "backend_status", "supported packed MPC-oblivious linear scan"
        ),
        "scope": manifest["scope"],
        "reference_kind": manifest.get("reference_kind", "bounded reference"),
        "requested_executions": requested_executions,
        "execution_count": requested_executions,
        "distinct_query_count": distinct_query_count,
        "correctness_unit": manifest.get(
            "correctness_unit",
            "MPC executions; repeated semantic queries count separately",
        ),
        "unique_base_queries": int(manifest["unique_base_queries"]),
        "expected_batches": expected_batches,
        "batch_statuses": statuses,
        "completed_executions": completed_executions,
        "reference_matching_executions": reference_matching_executions,
        "bounded_reference_match_rate": (
            reference_matching_executions / completed_executions
            if completed_executions
            else None
        ),
        "complete": complete,
        "all_mpc_outputs_match_bounded_reference": all_match,
        "metric_definition": (
            "Implementation equivalence against the supplied bounded reference; "
            "not uncapped dataset QA accuracy."
        ),
        "metric_parse_errors": parse_errors,
        "integrity_errors": integrity_errors,
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
            "mpc_seconds_per_execution": total_mpc / metric_queries
            if metric_queries
            else None,
            "wall_seconds_per_execution": total_wall / metric_queries
            if metric_queries
            else None,
            "global_data_mb_per_execution": total_global / metric_queries
            if metric_queries
            else None,
            "party_0_data_mb_per_execution": total_party / metric_queries
            if metric_queries
            else None,
            "reported_rounds_per_execution": total_rounds / metric_queries
            if metric_queries
            else None,
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
    print(f"  backend: {result['backend']} ({result['backend_status']})")
    print(f"  scope: {result['scope']}")
    print(f"  reference: {result['reference_kind']}")
    print(
        f"  executions/distinct queries: {result['execution_count']}/"
        f"{result['distinct_query_count']}"
    )
    print(
        f"  bounded reference matches: "
        f"{result['reference_matching_executions']}/"
        f"{result['completed_executions']} completed executions; "
        f"complete={result['complete']}; "
        "all_match="
        f"{result['all_mpc_outputs_match_bounded_reference']}"
    )
    print(f"  batch statuses: {result['batch_statuses']}")
    if averages["mpc_seconds_per_execution"] is not None:
        print(
            f"  MPC time: {totals['mpc_seconds']:.3f}s total; "
            f"{averages['mpc_seconds_per_execution']:.3f}s/execution amortized"
        )
        print(
            f"  global communication: {totals['global_data_mb']:.3f} MB total; "
            f"{averages['global_data_mb_per_execution']:.3f} MB/execution amortized"
        )
        print(
            f"  reported rounds: {totals['reported_rounds']}; "
            f"{averages['reported_rounds_per_execution']:.1f}/execution amortized"
        )
    if result["metric_parse_errors"]:
        print(f"  metric errors: {result['metric_parse_errors']}")
    if result["integrity_errors"]:
        print(f"  integrity errors: {result['integrity_errors']}")
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
        "all_mpc_outputs_match_bounded_reference": all(
            row["all_mpc_outputs_match_bounded_reference"] for row in datasets
        ),
        "datasets": datasets,
    }
    output = args.output.resolve() if args.output else run_dir / "analysis.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for dataset in datasets:
        print_dataset(dataset)
    print(f"Analysis JSON: {output}")
    if args.strict and not (
        result["all_datasets_complete"]
        and result["all_mpc_outputs_match_bounded_reference"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
