#!/usr/bin/env python3
"""Run a prepared KQA Pro two-hop workload closure in MPC batches.

The generated relation-paged program supports at most ten queries, so this
runner executes 10 + 10 + 1, reuses query-independent owner shards, reconstructs
only from the three output logs, and checks every field against the previously
generated independent cleartext oracle.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.decode_batch import decode_batch_logs  # noqa: E402
from doram_t2_3pc.packed import create_packed_query_batch_shards  # noqa: E402
from doram_t2_3pc.paged_shares import (  # noqa: E402
    assemble_paged_batch_from_paths,
    create_paged_owner_shards,
)
from doram_t2_3pc.relation_pages import RelationPageConfig  # noqa: E402
from doram_t2_3pc.run_pages_mpspdz import run as run_mpspdz  # noqa: E402
from scripts.analyze_doram_regression import parse_party_zero_log  # noqa: E402


def read_json(path: Path, expected: type) -> Any:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, expected):
        raise ValueError(f"{path} must contain a {expected.__name__}")
    return value


def write_json(path: Path, value: Any, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600 if private else 0o644)


def prepare_owner_shards(fixture: Path, output: Path, config: RelationPageConfig) -> list[list[Path]]:
    by_owner = []
    for owner in config.base.owners:
        owner_dir = output / "owner_shards" / owner
        owner_dir.mkdir(parents=True, exist_ok=True)
        existing = sorted(owner_dir.glob("paged-owner-*-to-server-*.json"))
        if len(existing) == 3:
            by_owner.append(existing)
            continue
        by_owner.append(
            create_paged_owner_shards(
                config, owner, fixture / f"{owner}.json", owner_dir
            )
        )
    return by_owner


def run(args: argparse.Namespace) -> dict[str, Any]:
    fixture = args.fixture.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    config_path = fixture / "config.json"
    config = RelationPageConfig.load(config_path)
    queries = read_json(fixture / "queries.json", list)
    oracle = read_json(fixture / "cleartext_validation.json", dict)
    expected_all = [record["oracle_output"] for record in oracle["records"]]
    if not queries or len(expected_all) != len(queries):
        raise ValueError("fixture queries and cleartext-oracle records must be non-empty and aligned")
    owner_shards = prepare_owner_shards(fixture, output, config)

    batches = []
    for start in range(0, len(queries), args.batch_size):
        stop = min(start + args.batch_size, len(queries))
        batch_index = start // args.batch_size
        batch_dir = output / f"batch_{batch_index:02d}_{start}_{stop}"
        summary_path = batch_dir / "summary.json"
        if args.resume and summary_path.exists():
            existing = read_json(summary_path, dict)
            if existing.get("status") == "completed" and existing.get("exact_oracle_match"):
                batches.append(existing)
                print(f"batch {batch_index}: reusing completed exact result")
                continue
        batch_dir.mkdir(parents=True, exist_ok=True)
        query_path = batch_dir / "queries.json"
        write_json(query_path, queries[start:stop], private=True)
        query_shards = create_packed_query_batch_shards(
            config.base, query_path, batch_dir / "query_shards"
        )
        instance = batch_dir / "instance"
        instance.mkdir(parents=True, exist_ok=True)
        for server in range(3):
            assemble_paged_batch_from_paths(
                config,
                server,
                stop - start,
                query_shards[server],
                [owner_shards[owner_index][server] for owner_index in range(len(owner_shards))],
                instance / f"Input-P{server}-0",
            )
        expected = expected_all[start:stop]
        write_json(batch_dir / "expected.json", expected, private=True)
        pending = {
            "status": "running",
            "batch": batch_index,
            "start": start,
            "stop": stop,
            "query_count": stop - start,
            "protocol": args.protocol,
        }
        write_json(summary_path, pending)
        label = f"kqapro-{batch_index}-{uuid.uuid4().hex[:6]}"
        started = time.perf_counter()
        source_logs = run_mpspdz(
            instance,
            config_path,
            stop - start,
            args.mpspdz_home,
            log_label=label,
            compile_timeout=args.compile_timeout,
            runtime_timeout=args.runtime_timeout,
            protocol=args.protocol,
        )
        wall = time.perf_counter() - started
        local_logs = []
        logs_dir = batch_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        for server, source in enumerate(source_logs):
            destination = logs_dir / f"server_{server}.log"
            shutil.copyfile(source, destination)
            os.chmod(destination, 0o600)
            local_logs.append(destination)
        decoded = decode_batch_logs(config.base, stop - start, local_logs)
        exact = decoded == expected
        metrics = parse_party_zero_log(local_logs[0])
        completed = {
            **pending,
            "status": "completed",
            "exact_oracle_match": exact,
            "fields_compared": (stop - start) * config.base.top_k * 4,
            "runner_wall_seconds_including_compile_if_needed": wall,
            "mpc_seconds_including_preprocessing": metrics["mpc_seconds"],
            "global_data_mb": metrics["global_data_mb"],
            "party0_data_mb": metrics["party_0_data_mb"],
            "party0_reported_rounds": metrics["reported_rounds"],
            "logs": [str(path) for path in local_logs],
        }
        write_json(batch_dir / "decoded.json", decoded, private=True)
        write_json(summary_path, completed)
        if not exact:
            raise RuntimeError(f"batch {batch_index} disagrees with cleartext oracle")
        batches.append(completed)
        print(
            f"batch {batch_index}: {stop-start} queries exact; "
            f"{metrics['mpc_seconds']:.3f}s, {metrics['global_data_mb']:.2f} MB"
        )

    total_queries = sum(batch["query_count"] for batch in batches)
    total_mpc = sum(batch["mpc_seconds_including_preprocessing"] for batch in batches)
    total_data = sum(batch["global_data_mb"] for batch in batches)
    capacity_path = fixture / "capacity_report.json"
    capacity = read_json(capacity_path, dict) if capacity_path.exists() else {}
    summary = {
        "evaluation_label": oracle.get(
            "evaluation_label", "KQA Pro snapshot-equivalent two-hop subset"
        ),
        "full_kqapro_accuracy": False,
        "fixture_scope": capacity.get(
            "fixture_semantics", "public-query workload closure, not full KQA Pro KB"
        ),
        "protocol": args.protocol,
        "queries": total_queries,
        "batches": batches,
        "all_exact": all(batch["exact_oracle_match"] for batch in batches),
        "total_mpc_seconds_including_preprocessing": total_mpc,
        "total_global_data_mb": total_data,
        "amortized_mpc_seconds_per_query": total_mpc / total_queries,
        "amortized_global_mb_per_query": total_data / total_queries,
        "runner_wall_seconds_sum_including_compile_if_needed": sum(
            batch["runner_wall_seconds_including_compile_if_needed"] for batch in batches
        ),
        "measurement_scope": "three MP-SPDZ parties on localhost",
        "timing_note": "MPC seconds include Temi preprocessing but exclude compilation and share preparation.",
        "round_note": "MP-SPDZ reports multithreaded rounds with double-counting; do not interpret them as sequential WAN round trips.",
        "security_note": "Temi is semi-honest dishonest-majority MPC; this localhost harness centralizes shares and is not a three-host deployment.",
    }
    write_json(output / "summary.json", summary)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture",
        type=Path,
        default=Path("data/kqa_pro/relation_fixture/validation_closure"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mpspdz-home", type=Path, default=ROOT / "external/MP-SPDZ")
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--protocol", choices=("semi", "temi", "hemi", "mascot"), default="temi")
    parser.add_argument("--compile-timeout", type=int, default=1800)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 10:
        parser.error("--batch-size must be in [1, 10]")
    return args


if __name__ == "__main__":
    print(json.dumps(run(parse_args()), indent=2))
