#!/usr/bin/env python3
"""Build query-independent party-local MetaQA ORAM adjacency indexes."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from bucketed_oram_index import build_party_index, write_party_index
from prepare_metaqa_twohop_mpspdz_inputs import _canonical_text, _load_manifest, _load_party


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
        max(index["stats"]["source_directory_capacity"], index["stats"]["target_directory_capacity"])
        for index in initial_indexes
    )

    summaries = []
    for (party, graph), initial_index in zip(party_graphs, initial_indexes):
        if (
            initial_index["stats"]["source_directory_capacity"] == directory_capacity
            and initial_index["stats"]["target_directory_capacity"] == directory_capacity
        ):
            index = initial_index
        else:
            index = build_party_index(
                graph,
                setup_key,
                allowed_relations=allowed_relations,
                load_factor=args.directory_load_factor,
                source_directory_capacity=directory_capacity,
                target_directory_capacity=directory_capacity,
                read_padding=args.max_candidates,
            )
        party_dir = output_dir / party["party_id"]
        write_party_index(index, party_dir)
        summaries.append({"party_id": party["party_id"], **index["stats"]})

    metadata = {
        "format": "fedkg-mpspdz-oram-index-set-v1",
        "relations": sorted(allowed_relations) if allowed_relations else "all",
        "data_party_ids": [summary["party_id"] for summary in summaries],
        "directory_capacity": directory_capacity,
        "max_candidates": args.max_candidates,
        "security_model": (
            "Indexes are built offline without an online query. oram_index.json and evidence_vault.json "
            "are private party-local files and must not be sent to the query gateway."
        ),
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    print(json.dumps({"output_dir": str(output_dir), **metadata, "private_party_stats": summaries}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
