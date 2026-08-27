#!/usr/bin/env python3
"""Measure relation-paged cost while varying only the owner count.

The global graph, query batch, entity/relation namespaces, per-owner public
capacity, global frontier, and top-k are identical in every arm.  Edges are
redistributed deterministically over 1/2/4/8 owners.  Keeping the per-owner
capacity fixed is intentional: it measures the privacy-preserving deployment
model in which adding an owner adds an independently padded contribution
region, rather than leaking that a later owner has a smaller allocation.

The script records three different time notions:

* owner preparation: layout construction and fresh 3-of-3 sharing;
* input assembly: construction of the three server-private input streams;
* MPC time: MP-SPDZ's own protocol time, including protocol preprocessing;

Compilation is configuration-specific and is reported separately through the
runner wall time.  It must not be presented as steady-state query latency.
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
from doram_t2_3pc.io import read_json  # noqa: E402
from doram_t2_3pc.packed import create_packed_query_batch_shards  # noqa: E402
from doram_t2_3pc.paged_shares import (  # noqa: E402
    assemble_paged_batch_from_paths,
    create_paged_owner_shards,
    expected_private_input_values,
)
from doram_t2_3pc.page_program import page_cost_estimate, program_name  # noqa: E402
from doram_t2_3pc.relation_pages import (  # noqa: E402
    RelationPageConfig,
    check_global_frontier,
    evaluate_paged_cleartext,
)
from doram_t2_3pc.run_pages_mpspdz import run as run_mpspdz  # noqa: E402
from scripts.analyze_doram_regression import parse_party_zero_log  # noqa: E402


HE_PRIME = 170141183460469231731687303715885907969
DEFAULT_MPSPDZ = ROOT.parent / "SimGRAG" / "external" / "MP-SPDZ"


def write_json(path: Path, value: Any, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.chmod(path, 0o600 if private else 0o644)


def global_edges(*, entities: int, relations: int, hubs: int, degree: int) -> list[dict[str, Any]]:
    """Build one fixed graph used by every owner-count arm."""

    if entities < 2 * hubs + 1:
        raise ValueError("entities must exceed twice the hub count")
    mids = list(range(hubs, 2 * hubs))
    tails = list(range(2 * hubs, entities))
    rows: list[dict[str, Any]] = []
    evidence = 1
    for source_group, sources in (("hub", range(hubs)), ("mid", mids)):
        for local_index, source in enumerate(sources):
            for relation in range(relations):
                for slot in range(degree):
                    if source_group == "hub":
                        target = mids[(local_index + relation + slot) % len(mids)]
                    else:
                        target = tails[(local_index * 7 + relation * 3 + slot) % len(tails)]
                    rows.append(
                        {
                            "source": f"e{source}",
                            "relation": f"r{relation}",
                            "target": f"e{target}",
                            "evidence": evidence,
                            "score": 1 + evidence % 11,
                        }
                    )
                    evidence += 1
    return rows


def distribute(rows: list[dict[str, Any]], owners: int) -> dict[str, list[dict[str, Any]]]:
    """Balance every key's slots over owners without changing the union."""

    result = {f"owner_{index}": [] for index in range(owners)}
    key_ordinals: dict[tuple[str, str], int] = {}
    key_numbers: dict[tuple[str, str], int] = {}
    for row in rows:
        key = (row["source"], row["relation"])
        if key not in key_numbers:
            key_numbers[key] = len(key_numbers)
        slot = key_ordinals.get(key, 0)
        key_ordinals[key] = slot + 1
        owner = (key_numbers[key] + slot) % owners
        result[f"owner_{owner}"].append(row)
    return result


def config_document(
    *, owners: int, entities: int, relations: int, hubs: int, degree: int, top_k: int
) -> dict[str, Any]:
    # The fixed graph has (hubs + mids) * relations occupied keys.  Every owner
    # receives the same public capacity as the one-owner arm, intentionally
    # hiding its realized contribution volume.
    occupied_keys = 2 * hubs * relations
    return {
        "owners": [f"owner_{index}" for index in range(owners)],
        "entities": {f"e{index}": index + 1 for index in range(entities)},
        "relations": {f"r{index}": index + 1 for index in range(relations)},
        "fanout_per_owner": relations * degree,
        "top_k": top_k,
        "field_prime": HE_PRIME,
        "relation_page_layout": {
            "page_size": degree,
            "pages_per_key": 1,
            "page_budget": occupied_keys + 1,
            "frontier_per_owner": degree,
            "global_frontier": degree,
        },
    }


def queries(*, count: int, relations: int) -> list[dict[str, str]]:
    return [
        {
            "source": "e0",
            "relation_1": f"r{index % relations}",
            "relation_2": f"r{(index + 1) % relations}",
        }
        for index in range(count)
    ]


def run_arm(args: argparse.Namespace, owner_count: int, rows: list[dict[str, Any]]) -> dict[str, Any]:
    arm = args.output_dir / f"owners-{owner_count}"
    fixture = arm / "fixture"
    shares = arm / "owner-shards"
    instance = arm / "instance"
    logs_dir = arm / "logs"
    arm.mkdir(parents=True, exist_ok=True)

    document = config_document(
        owners=owner_count,
        entities=args.entities,
        relations=args.relations,
        hubs=args.hubs,
        degree=args.degree,
        top_k=args.top_k,
    )
    config_path = fixture / "config.json"
    write_json(config_path, document)
    config = RelationPageConfig.load(config_path)
    owner_edges = distribute(rows, owner_count)
    for owner, edges in owner_edges.items():
        write_json(fixture / f"{owner}.json", edges, private=True)
    batch_queries = queries(count=args.query_count, relations=args.relations)
    query_path = fixture / "queries.json"
    write_json(query_path, batch_queries, private=True)

    # This is a fixture-side exact check.  Deployment uses the separate MPC
    # bound gate; the query circuit trusts no query-dependent cardinality.
    bound_report = check_global_frontier(config, owner_edges)
    expected = [
        evaluate_paged_cleartext(config, owner_edges, query)
        for query in batch_queries
    ]

    started = time.perf_counter()
    owner_paths: list[list[Path]] = []
    for owner in config.base.owners:
        owner_paths.append(
            create_paged_owner_shards(
                config, owner, fixture / f"{owner}.json", shares / owner
            )
        )
    owner_prepare_seconds = time.perf_counter() - started

    started = time.perf_counter()
    query_shards = create_packed_query_batch_shards(config.base, query_path, arm / "query-shards")
    for server in range(3):
        assemble_paged_batch_from_paths(
            config,
            server,
            args.query_count,
            query_shards[server],
            [paths[server] for paths in owner_paths],
            instance / f"Input-P{server}-0",
        )
    assembly_seconds = time.perf_counter() - started
    input_bytes = sum((instance / f"Input-P{server}-0").stat().st_size for server in range(3))

    result: dict[str, Any] = {
        "owners": owner_count,
        "global_edges": len(rows),
        "per_owner_real_edges": [len(owner_edges[name]) for name in config.base.owners],
        "query_count": args.query_count,
        "distinct_queries": len({json.dumps(q, sort_keys=True) for q in batch_queries}),
        "program": program_name(config, args.query_count),
        "directory_rows": config.directory_rows,
        "directory_columns": config.directory_columns,
        "page_budget_per_owner": config.pages.page_budget,
        "page_size": config.pages.page_size,
        "global_frontier": config.pages.global_frontier,
        "private_input_values_per_server": expected_private_input_values(config, args.query_count),
        "private_input_bytes_all_servers": input_bytes,
        "owner_share_preparation_seconds": owner_prepare_seconds,
        "input_assembly_seconds": assembly_seconds,
        "bound_check_fixture_report": bound_report,
        "cost_estimate": page_cost_estimate(config, args.query_count),
        "status": "prepared" if args.prepare_only else "running",
    }
    write_json(arm / "summary.json", result)
    if args.prepare_only:
        return result

    label = f"owner-scale-{owner_count}-{uuid.uuid4().hex[:6]}"
    started = time.perf_counter()
    source_logs = run_mpspdz(
        instance,
        config_path,
        args.query_count,
        args.mpspdz_home,
        log_label=label,
        compile_timeout=args.compile_timeout,
        runtime_timeout=args.runtime_timeout,
        protocol=args.protocol,
    )
    runner_wall_seconds = time.perf_counter() - started
    logs_dir.mkdir(parents=True, exist_ok=True)
    local_logs: list[Path] = []
    for server, source in enumerate(source_logs):
        destination = logs_dir / f"server-{server}.log"
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o600)
        local_logs.append(destination)
    decoded = decode_batch_logs(config.base, args.query_count, local_logs)
    metrics = parse_party_zero_log(local_logs[0])
    exact = decoded == expected
    result.update(
        {
            "status": "completed",
            "runner_wall_seconds_including_compile_if_needed": runner_wall_seconds,
            "mpc_seconds_including_preprocessing": metrics["mpc_seconds"],
            "global_data_mb": metrics["global_data_mb"],
            "party0_data_mb": metrics["party_0_data_mb"],
            "party0_reported_rounds": metrics["reported_rounds"],
            "amortized_mpc_seconds_per_query": metrics["mpc_seconds"] / args.query_count,
            "amortized_global_mb_per_query": metrics["global_data_mb"] / args.query_count,
            "strict_first_run_wall_seconds": (
                owner_prepare_seconds + assembly_seconds + runner_wall_seconds
            ),
            "exact_oracle_match": exact,
            "fields_compared": args.query_count * args.top_k * 4,
            "logs": [str(path.resolve()) for path in local_logs],
        }
    )
    write_json(arm / "decoded.json", decoded, private=True)
    write_json(arm / "expected.json", expected, private=True)
    write_json(arm / "summary.json", result)
    if not exact:
        raise RuntimeError(f"owner-count arm {owner_count} disagrees with its oracle")
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owners", nargs="+", type=int, default=[1, 2, 4, 8])
    parser.add_argument("--entities", type=int, default=200)
    parser.add_argument("--relations", type=int, default=8)
    parser.add_argument("--hubs", type=int, default=8)
    parser.add_argument("--degree", type=int, default=2)
    parser.add_argument("--top-k", type=int, default=4)
    parser.add_argument("--query-count", type=int, default=1)
    parser.add_argument("--protocol", default="temi")
    parser.add_argument("--mpspdz-home", type=Path, default=DEFAULT_MPSPDZ)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--compile-timeout", type=int, default=1800)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    if any(value < 1 for value in args.owners):
        parser.error("owner counts must be positive")
    if args.query_count < 1:
        parser.error("query-count must be positive")
    args.output_dir = args.output_dir.resolve()
    args.mpspdz_home = args.mpspdz_home.resolve()
    return args


def main() -> int:
    args = parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise SystemExit(f"output directory is not empty: {args.output_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows = global_edges(
        entities=args.entities,
        relations=args.relations,
        hubs=args.hubs,
        degree=args.degree,
    )
    summaries = []
    for owner_count in args.owners:
        print(f"[owners={owner_count}] preparing", flush=True)
        summary = run_arm(args, owner_count, rows)
        summaries.append(summary)
        if summary["status"] == "completed":
            print(
                f"[owners={owner_count}] {summary['mpc_seconds_including_preprocessing']:.3f}s, "
                f"{summary['global_data_mb']:.3f} MB, exact={summary['exact_oracle_match']}",
                flush=True,
            )
    report = {
        "name": "relation_paged_owner_scaling",
        "date": time.strftime("%Y-%m-%d", time.gmtime()),
        "protocol": args.protocol,
        "scope": (
            "Fixed 200-entity/8-relation/256-edge graph and fixed public per-owner "
            "capacity; only owner count and edge assignment vary"
        ),
        "scope_warning": (
            "Three parties run on one localhost. MPC time includes protocol "
            "preprocessing; strict first-run wall also includes compilation when "
            "the program was not cached. This is a controlled scaling fixture, "
            "not a real-dataset or WAN measurement."
        ),
        "arms": summaries,
    }
    write_json(args.output_dir / "report.json", report)
    print(f"wrote {args.output_dir / 'report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
