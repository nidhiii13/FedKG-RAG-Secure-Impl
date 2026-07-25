#!/usr/bin/env python3
"""Build fixed padded bucketized KG tables for N-party MP-SPDZ retrieval."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from bucketed_oram_limb_index import ID_EFFECTIVE_BITS, ID_LIMBS, evidence_handle, hmac_limbs, logical_edges
from prepare_metaqa_twohop_edge_join_mpspdz_inputs import _all_edges
from prepare_metaqa_twohop_mpspdz_inputs import _canonical_text, _load_manifest, _load_party

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.semantic.relation_buckets import relation_bucket_names


EMPTY_ROW = [0] * (ID_LIMBS * 4 + 3)


def _row_for_edge(
    setup_key: str,
    bucket: str,
    direction: int,
    source: str,
    relation: str,
    target: str,
) -> list[int]:
    return [
        *hmac_limbs(setup_key, "relation_bucket", bucket),
        *hmac_limbs(setup_key, "entity", source),
        *hmac_limbs(setup_key, "relation", relation),
        *hmac_limbs(setup_key, "entity", target),
        evidence_handle(setup_key, source, relation, target),
        direction,
        1,
    ]


def build_party_table(
    graph: dict,
    setup_key: str,
    *,
    allowed_relations: set[str] | None,
    semantic_bucket_mode: str,
    buckets_per_relation: int | None,
    rows_per_party: int,
) -> tuple[list[list[int]], dict[str, dict], dict]:
    rows = []
    vault = {}
    bucket_counts: dict[str, int] = {}
    for direction, source, relation, target in logical_edges(graph, allowed_relations):
        relation_key = _canonical_text(relation)
        buckets = relation_bucket_names(relation_key, mode=semantic_bucket_mode)
        if buckets_per_relation is not None:
            buckets = buckets[:buckets_per_relation]
        for bucket in buckets:
            rows.append(_row_for_edge(setup_key, bucket, direction, source, relation, target))
            bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
        handle = evidence_handle(setup_key, source, relation, target)
        vault[str(handle)] = {"source": source, "relation": relation, "target": target}
    if len(rows) > rows_per_party:
        raise ValueError(
            f"bucketized table has {len(rows)} rows but rows-per-party is {rows_per_party}"
        )
    rows.extend([EMPTY_ROW[:] for _ in range(rows_per_party - len(rows))])
    stats = {
        "real_rows": len(rows) - sum(1 for row in rows if row[-1] == 0),
        "rows_per_party": rows_per_party,
        "bucket_count": len(bucket_counts),
        "max_bucket_rows": max(bucket_counts.values(), default=0),
    }
    return rows, vault, stats


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--relation", action="append", default=[])
    parser.add_argument("--semantic-bucket-mode", choices=["alias", "lsh", "hybrid"], default="hybrid")
    parser.add_argument(
        "--buckets-per-relation",
        type=int,
        default=0,
        help="Fixed public cap on semantic buckets materialized per relation; 0 keeps all buckets.",
    )
    parser.add_argument("--rows-per-party", type=int, required=True)
    args = parser.parse_args()

    setup_key = os.environ.get("FEDKG_SETUP_KEY")
    if not setup_key:
        raise SystemExit("FEDKG_SETUP_KEY is required")
    allowed_relations = {_canonical_text(value) for value in args.relation} or None
    if args.buckets_per_relation < 0:
        raise SystemExit("--buckets-per-relation must be non-negative")
    buckets_per_relation = args.buckets_per_relation or None
    manifest = _load_manifest(Path(args.manifest))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    party_graphs = []
    for party in manifest["parties"]:
        graph, _ = _load_party(Path(party["data"]))
        party_graphs.append((party, graph))
    indexed_relations = (
        allowed_relations
        or {
            _canonical_text(relation)
            for _, graph in party_graphs
            for _, relation, _ in _all_edges(graph)
        }
    )

    summaries = []
    for party, graph in party_graphs:
        rows, vault, stats = build_party_table(
            graph,
            setup_key,
            allowed_relations=allowed_relations,
            semantic_bucket_mode=args.semantic_bucket_mode,
            buckets_per_relation=buckets_per_relation,
            rows_per_party=args.rows_per_party,
        )
        party_dir = output_dir / party["party_id"]
        party_dir.mkdir(parents=True, exist_ok=True)
        (party_dir / "bucketized_mpc_table.json").write_text(json.dumps({"rows": rows}))
        (party_dir / "evidence_vault.json").write_text(json.dumps(vault))
        (party_dir / "bucketized_mpc_table.json").chmod(0o600)
        (party_dir / "evidence_vault.json").chmod(0o600)
        summaries.append({"party_id": party["party_id"], **stats})

    metadata = {
        "format": "fedkg-mpspdz-bucketized-index-set-v1",
        "id_limbs": ID_LIMBS,
        "id_effective_bits": ID_EFFECTIVE_BITS,
        "semantic_bucket_mode": args.semantic_bucket_mode,
        "buckets_per_relation": buckets_per_relation or "all",
        "relations": sorted(indexed_relations) if allowed_relations else "all",
        "rows_per_party": args.rows_per_party,
        "data_party_ids": [summary["party_id"] for summary in summaries],
        "security_model": (
            "Fixed padded bucketized tables for MP-SPDZ private scans. "
            "Rows are secret inputs; table size is public."
        ),
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    print(json.dumps({"output_dir": str(output_dir), **metadata, "private_party_stats": summaries}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
