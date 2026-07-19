#!/usr/bin/env python3
"""Prepare a private two-hop ORAM lookup and cross-party MPC join instance."""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path

from bucketed_oram_index import directory_slot, probe_slots, read_party_index
from prepare_metaqa_mpspdz_inputs import _normalize_relation
from prepare_metaqa_twohop_mpspdz_inputs import (
    _canonical_text,
    _hmac_int,
    _is_unknown,
    _load_manifest,
    _parse_edge,
    _repo_root,
    _write_input_file,
)
from prepare_metaqa_twohop_split_edge_join_mpspdz_inputs import (
    TYPE_IDENTITY_RELATION,
    _is_type_relation,
)


def _direction_bit(direction: str) -> int:
    if direction == "forward":
        return 0
    if direction == "reverse":
        return 1
    raise ValueError(f"unsupported logical direction: {direction}")


def _bits_for(value: int) -> int:
    return max(1, math.ceil(math.log2(max(2, value))))


def _is_oram_type_relation(relation: str) -> bool:
    canonical = _canonical_text(relation)
    return _is_type_relation(relation) or canonical in {"is one of", "one of"}


def _pad_rows(rows: list[list[int]], capacity: int, width: int) -> list[list[int]]:
    if len(rows) > capacity:
        raise ValueError(f"index has {len(rows)} rows but MPC capacity is {capacity}")
    return rows + [[0] * width for _ in range(capacity - len(rows))]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--index-dir", required=True)
    parser.add_argument("--edge", required=True, action="append", type=_parse_edge)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-candidates", type=int, default=64)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--semantic-relations", action="store_true")
    args = parser.parse_args()

    if len(args.edge) != 2:
        raise SystemExit("ORAM two-hop retrieval requires exactly two --edge values")
    setup_key = os.environ.get("FEDKG_SETUP_KEY")
    if not setup_key:
        raise SystemExit("FEDKG_SETUP_KEY is required")

    original_edge_1, original_edge_2 = args.edge
    relation_1, direction_1 = _normalize_relation(
        original_edge_1[1], semantic_relations=args.semantic_relations
    )
    type_identity_mode = bool(
        args.semantic_relations and _is_oram_type_relation(original_edge_2[1])
    )
    if type_identity_mode:
        relation_2, direction_2 = TYPE_IDENTITY_RELATION, "forward"
    else:
        relation_2, direction_2 = _normalize_relation(
            original_edge_2[1], semantic_relations=args.semantic_relations
        )
    edge_1 = (original_edge_1[0], relation_1, original_edge_1[2])
    edge_2 = (original_edge_2[0], relation_2, original_edge_2[2])
    target_is_unknown = _is_unknown(edge_2[2])
    if target_is_unknown and not type_identity_mode:
        raise SystemExit(
            "unknown-to-unknown second-hop expansion is not supported by the single-access ORAM path; "
            "use a known target or the synthetic type-identity constraint"
        )

    manifest = _load_manifest(Path(args.manifest))
    index_root = Path(args.index_dir)
    metadata = json.loads((index_root / "metadata.json").read_text())
    if metadata.get("format") != "fedkg-mpspdz-oram-index-set-v1":
        raise SystemExit("unsupported ORAM index-set format")
    if args.max_candidates > int(metadata["max_candidates"]):
        raise SystemExit(
            f"--max-candidates exceeds index read padding ({metadata['max_candidates']}); rebuild indexes"
        )

    party_ids = [party["party_id"] for party in manifest["parties"]]
    indexes = [read_party_index(index_root / party_id) for party_id in party_ids]
    directory_capacity = int(metadata["directory_capacity"])
    if any(
        len(index["source_directory"]) != directory_capacity
        or len(index["target_directory"]) != directory_capacity
        for index in indexes
    ):
        raise SystemExit("party ORAM directories do not share the public fixed capacity")

    source_edge_capacity = max(len(index["source_edges"]) for index in indexes)
    target_edge_capacity = max(len(index["target_edges"]) for index in indexes)
    probe_limit = max(
        max(index["stats"]["source_probe_limit"], index["stats"]["target_probe_limit"])
        for index in indexes
    )
    probe_limit = max(1, probe_limit)

    source_id = _hmac_int(setup_key, "entity", edge_1[0])
    relation_1_id = _hmac_int(setup_key, "relation", relation_1)
    relation_2_id = _hmac_int(setup_key, "relation", relation_2)
    target_id = 0 if target_is_unknown else _hmac_int(setup_key, "entity", edge_2[2])
    direction_1_bit = _direction_bit(direction_1)
    direction_2_bit = _direction_bit(direction_2)
    source_base = directory_slot(
        setup_key,
        "source",
        direction_1_bit,
        source_id,
        relation_1_id,
        directory_capacity,
    )
    target_base = directory_slot(
        setup_key,
        "target",
        direction_2_bit,
        target_id,
        relation_2_id,
        directory_capacity,
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    template_path = (
        _repo_root()
        / "mpspdz_client_excluded"
        / "programs"
        / "secure_kg_twohop_oram_join_topk.mpc.template"
    )
    program = template_path.read_text().format(
        data_parties=len(indexes),
        directory_capacity=directory_capacity,
        source_edge_capacity=source_edge_capacity,
        target_edge_capacity=target_edge_capacity,
        probe_limit=probe_limit,
        max_candidates=args.max_candidates,
        top_k=args.topk,
        query_count=1,
        source_edge_index_bits=_bits_for(source_edge_capacity),
        target_edge_index_bits=_bits_for(target_edge_capacity),
        candidate_count_bits=_bits_for(max(source_edge_capacity, target_edge_capacity)),
    )
    (output_dir / "secure_kg_twohop_oram_join_topk.mpc").write_text(program)

    query_values = [
        source_id,
        relation_1_id,
        direction_1_bit,
        relation_2_id,
        direction_2_bit,
        target_id,
        int(target_is_unknown),
        int(type_identity_mode),
        *probe_slots(source_base, directory_capacity, probe_limit),
        *probe_slots(target_base, directory_capacity, probe_limit),
    ]
    player_data = output_dir / "Player-Data"
    query_input_path = player_data / "Input-P0-0"
    _write_input_file(query_input_path, query_values)
    query_input_path.chmod(0o600)

    party_summaries = []
    for player, (party_id, index) in enumerate(zip(party_ids, indexes), start=1):
        source_edges = _pad_rows(index["source_edges"], source_edge_capacity, 5)
        target_edges = _pad_rows(index["target_edges"], target_edge_capacity, 5)
        values = [
            value
            for table in (
                index["source_directory"],
                index["target_directory"],
                source_edges,
                target_edges,
            )
            for row in table
            for value in row
        ]
        input_path = player_data / f"Input-P{player}-0"
        _write_input_file(input_path, values)
        input_path.chmod(0o600)
        party_summaries.append(
            {
                "player": player,
                "party_id": party_id,
                "source_directory_capacity": directory_capacity,
                "target_directory_capacity": directory_capacity,
                "source_edge_capacity": source_edge_capacity,
                "target_edge_capacity": target_edge_capacity,
            }
        )

    mapping = {
        "query": {
            "original_edges": [
                {"source": original_edge_1[0], "relation": original_edge_1[1], "target": original_edge_1[2]},
                {"source": original_edge_2[0], "relation": original_edge_2[1], "target": original_edge_2[2]},
            ],
            "edges": [
                {"source": edge_1[0], "relation": edge_1[1], "target": edge_1[2]},
                {"source": edge_2[0], "relation": edge_2[1], "target": edge_2[2]},
            ],
            "directions": [direction_1, direction_2],
            "semantic_relations": args.semantic_relations,
            "type_identity_mode": type_identity_mode,
        },
        "index_dir": str(index_root.resolve()),
        "data_parties": party_summaries,
        "topk": args.topk,
        "max_candidates": args.max_candidates,
        "probe_limit": probe_limit,
        "security_note": (
            "Party indexes are query-independent. Directory and adjacency accesses use secret ORAM indexes; "
            "the cross-party edge join and top-k execute inside MP-SPDZ. Only selected evidence handles open."
        ),
    }
    receipt_path = output_dir / "query_gateway_receipt.json"
    receipt_path.write_text(json.dumps(mapping, indent=2))
    receipt_path.chmod(0o600)
    print(json.dumps({"output_dir": str(output_dir), **mapping}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
