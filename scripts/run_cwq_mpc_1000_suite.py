#!/usr/bin/env python3
"""Execute and aggregate the prepared domain-scoped 1,000-query CWQ suite."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def aggregate(manifest: dict, summaries: list[dict]) -> dict:
    queries = sum(summary["queries"] for summary in summaries)
    executed = sum(
        summary.get("executed_queries_including_padding", summary["queries"])
        for summary in summaries
    )
    mpc_seconds = sum(
        summary["total_mpc_seconds_including_preprocessing"] for summary in summaries
    )
    global_mb = sum(summary["total_global_data_mb"] for summary in summaries)
    fields = sum(
        batch["genuine_query_fields_compared"]
        for summary in summaries
        for batch in summary["batches"]
    )
    return {
        "evaluation_label": manifest["evaluation_label"],
        "status": "completed" if queries == manifest["selected_questions"] else "partial",
        "selected_questions": manifest["selected_questions"],
        "securely_executed_distinct_questions": queries,
        "executed_queries_including_padding": executed,
        "padding_queries": executed - queries,
        "domains_completed": len(summaries),
        "domains_total": len(manifest["domains"]),
        "all_exact": all(summary["all_exact"] for summary in summaries),
        "genuine_query_fields_compared": fields,
        "total_mpc_seconds_including_preprocessing": mpc_seconds,
        "total_global_data_mb": global_mb,
        "amortized_mpc_seconds_per_distinct_query": mpc_seconds / queries,
        "amortized_global_mb_per_distinct_query": global_mb / queries,
        "protocol": "temi",
        "measurement_scope": "three MP-SPDZ parties on localhost",
        "privacy_scope": manifest["public_leakage"],
        "security_scope": manifest["security_scope"],
        "domain_summaries": summaries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite",
        type=Path,
        default=ROOT / "data/cwq/mpc_fixture/cwq_1000_domain_suite_20260904",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results/cwq_mpc_temi_domain1000_20260904",
    )
    parser.add_argument("--mpspdz-home", type=Path, default=ROOT / "external/MP-SPDZ")
    parser.add_argument("--batch-size", type=int, default=5)
    parser.add_argument("--compile-timeout", type=int, default=10800)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    manifest = read_json(args.suite / "manifest.json")
    domains = sorted(manifest["domains"], key=lambda item: item["directory_rows"])
    summaries = []
    args.output.mkdir(parents=True, exist_ok=True)
    for position, item in enumerate(domains, 1):
        domain = item["domain"]
        print(
            f"[{position}/{len(domains)}] {domain}: {item['queries']} questions, "
            f"{item['directory_rows']:,} directory rows",
            flush=True,
        )
        command = [
            sys.executable,
            "-u",
            str(ROOT / "scripts/run_kqapro_relation_mpc.py"),
            "--fixture", str(Path(item["fixture"])),
            "--output", str(args.output / domain),
            "--mpspdz-home", str(args.mpspdz_home),
            "--batch-size", str(args.batch_size),
            "--protocol", "temi",
            "--compile-timeout", str(args.compile_timeout),
            "--runtime-timeout", str(args.runtime_timeout),
            "--pad-final-batch",
        ]
        if args.resume:
            command.append("--resume")
        subprocess.run(command, check=True)
        summary = read_json(args.output / domain / "summary.json")
        summary["public_first_relation_domain"] = domain
        summary["public_directory_rows"] = item["directory_rows"]
        summaries.append(summary)
        write_json(args.output / "summary.json", aggregate(manifest, summaries))

    final = aggregate(manifest, summaries)
    write_json(args.output / "summary.json", final)
    print(json.dumps({key: value for key, value in final.items()
                      if key != "domain_summaries"}, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
