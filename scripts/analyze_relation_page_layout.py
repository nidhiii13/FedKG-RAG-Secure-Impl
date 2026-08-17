#!/usr/bin/env python3
"""Parametric cost model for the experimental relation-paged layout.

This produces a *model*, not a measurement. It answers one design question:
if the packed MPC-oblivious linear scan had to represent a dataset losslessly,
how much cheaper would the relation-paged layout be?

The model's one unmeasured input is the maximum ``(source, relation)`` degree
of the target dataset, because that is what sets ``page_size``. Run
``python3 -m doram_t2_3pc.prepare_scan plan-capacity --edges <raw file>`` on the
real owner files to replace the assumed values below with measured ones. Every
assumed quantity is flagged in the output.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.relation_pages import (  # noqa: E402
    RelationPageConfig,
    paged_cost_estimate,
    relation_split_cost_advantage,
)

SCALABLE_PRIME = 170141183460469231731687303715884105727


def build_config(
    *,
    entity_count: int,
    relation_count: int,
    owner_count: int,
    page_size: int,
    pages_per_key: int,
    page_budget: int,
    top_k: int,
) -> RelationPageConfig:
    document = {
        "owners": [f"owner_{index}" for index in range(owner_count)],
        "entities": {f"e{index}": index + 1 for index in range(entity_count)},
        "relations": {f"r{index}": index + 1 for index in range(relation_count)},
        "fanout_per_owner": 2,
        "top_k": top_k,
        "field_prime": SCALABLE_PRIME,
        "relation_page_layout": {
            "page_size": page_size,
            "pages_per_key": pages_per_key,
            "page_budget": page_budget,
        },
    }
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(document))
        return RelationPageConfig.load(path)


def sweep(args: argparse.Namespace) -> dict[str, Any]:
    rows = []
    for page_size in args.page_sizes:
        # One page per key is the cheapest lossless setting when page_size
        # covers the maximum (source, relation) degree.
        page_budget = max(2, args.distinct_keys_per_owner + 1)
        config = build_config(
            entity_count=args.entity_count,
            relation_count=args.relation_count,
            owner_count=args.owner_count,
            page_size=page_size,
            pages_per_key=args.pages_per_key,
            page_budget=page_budget,
            top_k=args.top_k,
        )
        for compaction in args.compaction_slots:
            frontier = paged_cost_estimate(config, args.query_count)[
                "frontier_slots"
            ]
            if compaction > frontier:
                continue
            estimate = paged_cost_estimate(
                config, args.query_count, compacted_frontier_slots=compaction
            )
            comparison = relation_split_cost_advantage(
                config,
                args.lossless_max_source_degree,
                args.query_count,
                compacted_frontier_slots=compaction,
            )
            rows.append(
                {
                    "page_size": page_size,
                    "pages_per_key": args.pages_per_key,
                    "page_budget": page_budget,
                    "compacted_frontier_slots": compaction,
                    "frontier_slots": estimate["frontier_slots"],
                    "candidate_count_per_query": estimate[
                        "candidate_count_per_query"
                    ],
                    "paged_total_lookup_products": estimate[
                        "total_lookup_products"
                    ],
                    "paged_second_hop_products": estimate["second_hop_products"],
                    "lossless_packed_scan_second_hop_products": comparison[
                        "lossless_packed_scan_second_hop_products"
                    ],
                    "paged_speedup_vs_lossless_packed_scan": comparison[
                        "paged_speedup_vs_lossless_packed_scan"
                    ],
                    "lossless_at_this_page_size": (
                        page_size >= args.assumed_max_source_relation_degree
                    ),
                }
            )
    return {
        "model_kind": "analytic circuit-shape cost model, not a measurement",
        "unit": (
            "secret selected-products: one per (table row, output slot) pair "
            "touched by a secret-index linear lookup"
        ),
        "scope_warning": (
            "Analytic model only. It does not predict wall-clock time, "
            "communication, or WAN behaviour, and it has not been validated "
            "against an executed relation-paged MP-SPDZ program, which does "
            "not exist yet."
        ),
        "measured_inputs": {
            "entity_count": args.entity_count,
            "relation_count": args.relation_count,
            "owner_count": args.owner_count,
            "query_count": args.query_count,
            "top_k": args.top_k,
        },
        "assumed_inputs_requiring_measurement": {
            "lossless_max_source_degree": args.lossless_max_source_degree,
            "assumed_max_source_relation_degree": (
                args.assumed_max_source_relation_degree
            ),
            "distinct_keys_per_owner": args.distinct_keys_per_owner,
            "how_to_measure": (
                "python3 -m doram_t2_3pc.prepare_scan plan-capacity "
                "--edges <raw owner edge file>"
            ),
        },
        "rows": rows,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entity-count", type=int, default=43235)
    parser.add_argument("--relation-count", type=int, default=9)
    parser.add_argument("--owner-count", type=int, default=2)
    parser.add_argument("--query-count", type=int, default=1)
    parser.add_argument("--top-k", type=int, default=4)
    parser.add_argument(
        "--lossless-max-source-degree",
        type=int,
        default=2089,
        help="max source degree the packed scan would need to be lossless",
    )
    parser.add_argument(
        "--assumed-max-source-relation-degree",
        type=int,
        default=16,
        help="ASSUMED until measured on the raw dataset",
    )
    parser.add_argument("--distinct-keys-per-owner", type=int, default=66788)
    parser.add_argument("--pages-per-key", type=int, default=1)
    parser.add_argument(
        "--page-sizes", type=int, nargs="+", default=[4, 8, 16, 32]
    )
    parser.add_argument(
        "--compaction-slots", type=int, nargs="+", default=[1, 2, 4, 8]
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = sweep(args)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
