#!/usr/bin/env python3
"""Build party-local exact 128-bit HMAC ORAM indexes for MetaQA."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from bucketed_oram_limb_index import ID_EFFECTIVE_BITS, ID_LIMBS, build_party_index, write_party_index
from prepare_metaqa_twohop_edge_join_mpspdz_inputs import _all_edges
from prepare_metaqa_twohop_mpspdz_inputs import _canonical_text, _load_manifest, _load_party
from src.semantic.relation_buckets import relation_bucket_names


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--relation",
        action="append",
        default=[],
        help="Public relation partition to index; repeat as needed. Empty indexes all relations.",
    )
    parser.add_argument("--directory-load-factor", type=float, default=0.5)
    parser.add_argument("--max-candidates", type=int, default=64)
    parser.add_argument("--semantic-bucket-mode", choices=["alias", "lsh", "hybrid"], default="hybrid")
    args = parser.parse_args()

    setup_key = os.environ.get("FEDKG_SETUP_KEY")
    if not setup_key:
        raise SystemExit("FEDKG_SETUP_KEY is required")
    allowed_relations = {_canonical_text(value) for value in args.relation} or None
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

    initial_indexes = [
        build_party_index(
            graph,
            setup_key,
            allowed_relations=allowed_relations,
            load_factor=args.directory_load_factor,
            read_padding=args.max_candidates,
        )
        for _, graph in party_graphs
    ]
    directory_capacity = max(
        index["stats"]["source_directory_capacity"]
        for index in initial_indexes
    )

    summaries = []
    for (party, graph), initial_index in zip(party_graphs, initial_indexes):
        if initial_index["stats"]["source_directory_capacity"] == directory_capacity:
            index = initial_index
        else:
            index = build_party_index(
                graph,
                setup_key,
                allowed_relations=allowed_relations,
                load_factor=args.directory_load_factor,
                source_directory_capacity=directory_capacity,
                read_padding=args.max_candidates,
            )
        party_dir = output_dir / party["party_id"]
        write_party_index(index, party_dir)
        summaries.append({"party_id": party["party_id"], **index["stats"]})

    metadata = {
        "format": "fedkg-mpspdz-oram-limb-index-set-v1",
        "id_limbs": ID_LIMBS,
        "id_effective_bits": ID_EFFECTIVE_BITS,
        "relations": sorted(indexed_relations) if allowed_relations else "all",
        "semantic_bucket_mode": args.semantic_bucket_mode,
        "semantic_relation_buckets": {
            bucket: sorted(
                relation
                for relation in indexed_relations
                if bucket in relation_bucket_names(relation, mode=args.semantic_bucket_mode)
            )
            for bucket in sorted(
                {
                    bucket
                    for relation in indexed_relations
                    for bucket in relation_bucket_names(relation, mode=args.semantic_bucket_mode)
                }
            )
        },
        "data_party_ids": [summary["party_id"] for summary in summaries],
        "directory_capacity": directory_capacity,
        "max_candidates": args.max_candidates,
        "security_model": (
            "Indexes use four 32-bit HMAC limbs for exact 128-bit entity/relation identifiers. "
            "oram_limb_index.json and evidence_vault.json are private party-local files."
        ),
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    print(json.dumps({"output_dir": str(output_dir), **metadata, "private_party_stats": summaries}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
