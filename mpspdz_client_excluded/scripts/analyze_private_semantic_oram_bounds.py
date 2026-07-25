#!/usr/bin/env python3
"""Analyze public padded bounds for private semantic ORAM experiments."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from bucketed_oram_limb_index import read_private_semantic_party_index


def _percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = math.ceil((pct / 100.0) * len(ordered)) - 1
    return ordered[min(max(index, 0), len(ordered) - 1)]


def _next_power_of_two(value: int) -> int:
    if value <= 1:
        return 1
    return 1 << (value - 1).bit_length()


def _counts(rows: list[list[int]], valid_index: int, count_index: int) -> list[int]:
    return [int(row[count_index]) for row in rows if int(row[valid_index])]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index-dir", required=True)
    parser.add_argument("--percentile", type=float, default=99.0)
    parser.add_argument("--max-query-buckets", type=int, default=4)
    parser.add_argument("--max-queries", type=int, default=1)
    args = parser.parse_args()

    root = Path(args.index_dir)
    metadata = json.loads((root / "metadata.json").read_text())
    party_ids = metadata["data_party_ids"]
    indexes = [read_private_semantic_party_index(root / party_id) for party_id in party_ids]

    entity_counts = [
        count
        for index in indexes
        for count in _counts(index["entity_directory"], valid_index=7, count_index=6)
    ]
    relation_counts = [
        count
        for index in indexes
        for count in _counts(index["relation_bucket_directory"], valid_index=6, count_index=5)
    ]
    entity_probe_limit = max(index["stats"]["entity_probe_limit"] for index in indexes)
    relation_probe_limit = max(index["stats"]["relation_bucket_probe_limit"] for index in indexes)

    entity_pct = _percentile(entity_counts, args.percentile)
    relation_pct = _percentile(relation_counts, args.percentile)
    entity_max = max(entity_counts, default=0)
    relation_max = max(relation_counts, default=0)

    # Compact fixed slots are public shape parameters. These estimates are
    # independent of a specific query and include both first-hop and second-hop
    # probes for every query in the batch.
    recommended_entity_slots = _next_power_of_two(
        args.max_queries * 2 * entity_probe_limit
    )
    recommended_relation_slots = _next_power_of_two(
        args.max_queries * 2 * args.max_query_buckets * relation_probe_limit
    )
    recommended_max_candidates = _next_power_of_two(max(1, entity_pct))
    recommended_edge_rows = _next_power_of_two(
        recommended_entity_slots * recommended_max_candidates
    )
    recommended_relation_candidates = _next_power_of_two(max(1, relation_pct))
    recommended_relation_rows = _next_power_of_two(
        recommended_relation_slots * recommended_relation_candidates
    )

    result = {
        "index_dir": str(root),
        "party_count": len(party_ids),
        "percentile": args.percentile,
        "max_queries": args.max_queries,
        "max_query_buckets": args.max_query_buckets,
        "entity_degree": {
            "count": len(entity_counts),
            "p50": _percentile(entity_counts, 50),
            "p90": _percentile(entity_counts, 90),
            "p95": _percentile(entity_counts, 95),
            "p99": _percentile(entity_counts, 99),
            "selected_percentile": entity_pct,
            "max": entity_max,
        },
        "relation_bucket_degree": {
            "count": len(relation_counts),
            "p50": _percentile(relation_counts, 50),
            "p90": _percentile(relation_counts, 90),
            "p95": _percentile(relation_counts, 95),
            "p99": _percentile(relation_counts, 99),
            "selected_percentile": relation_pct,
            "max": relation_max,
        },
        "probe_limits": {
            "entity_probe_limit": entity_probe_limit,
            "relation_bucket_probe_limit": relation_probe_limit,
        },
        "recommended_public_bounds": {
            "max_candidates": recommended_max_candidates,
            "max_relation_candidates": recommended_relation_candidates,
            "fixed_compact_entity_slots": recommended_entity_slots,
            "fixed_compact_relation_slots": recommended_relation_slots,
            "fixed_compact_edge_rows": recommended_edge_rows,
            "fixed_compact_relation_rows": recommended_relation_rows,
        },
        "strict_max_public_bounds": {
            "max_candidates": _next_power_of_two(max(1, entity_max)),
            "max_relation_candidates": _next_power_of_two(max(1, relation_max)),
        },
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
