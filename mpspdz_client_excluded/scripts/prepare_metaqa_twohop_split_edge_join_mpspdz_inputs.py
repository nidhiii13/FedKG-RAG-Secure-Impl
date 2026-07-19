#!/usr/bin/env python3
"""Prepare a split edge-table two-hop join instance for MP-SPDZ.

This variant keeps first-hop and second-hop candidate edge tables separate,
which reduces the MPC pair space from all_edges^2 to left_edges * right_edges.
It is still a bounded prototype, not a full private graph database.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from prepare_metaqa_twohop_edge_join_mpspdz_inputs import _all_edges
from prepare_metaqa_twohop_mpspdz_inputs import (
    _canonical_text,
    _hmac_int,
    _is_unknown,
    _load_manifest,
    _load_party,
    _normalize_edge_relations,
    _parse_edge,
    _repo_root,
    _write_input_file,
)
from prepare_metaqa_mpspdz_inputs import _normalize_relation

TYPE_RELATIONS = {"is a", "is", "is one of", "one of", "type", "instance of"}
TYPE_IDENTITY_RELATION = "__type_identity__"


def _is_type_relation(relation: str) -> bool:
    return _canonical_text(relation) in TYPE_RELATIONS


def _logical_edges(
    graph: dict, canonical_relation: str, direction: str
) -> list[tuple[str, str, str]]:
    rows = []
    for source, relation, target in _all_edges(graph):
        if relation != canonical_relation:
            continue
        if direction == "reverse":
            rows.append((target, canonical_relation, source))
        else:
            rows.append((source, canonical_relation, target))
    return rows


def _universal_logical_edges(graph: dict) -> list[tuple[str, str, str]]:
    rows = set()
    entities = set()
    for source, relation, target in _all_edges(graph):
        source = str(source)
        relation = str(relation)
        target = str(target)
        rows.add((source, relation, target))
        rows.add((target, relation, source))
        entities.add(source)
        entities.add(target)
    for entity in entities:
        rows.add((entity, TYPE_IDENTITY_RELATION, entity))
    return sorted(rows, key=lambda row: (_canonical_text(row[1]), _canonical_text(row[0]), _canonical_text(row[2])))


def _matches_first_role(row: tuple[str, str, str], edge_1: tuple[str, str, str]) -> bool:
    source, relation, _ = row
    return _canonical_text(source) == _canonical_text(edge_1[0]) and relation == edge_1[1]


def _matches_second_role(row: tuple[str, str, str], edge_2: tuple[str, str, str]) -> bool:
    _, relation, target = row
    target_2 = edge_2[2]
    return relation == edge_2[1] and (_is_unknown(target_2) or _canonical_text(target) == _canonical_text(target_2))


def _select_rows(
    graph: dict,
    edge_1: tuple[str, str, str],
    edge_2: tuple[str, str, str],
    direction_1: str,
    direction_2: str,
    left_rows_per_party: int,
    right_rows_per_party: int,
    *,
    prioritize_query_rows: bool,
    private_tables: bool,
) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    if private_tables:
        universal_edges = _universal_logical_edges(graph)
        return universal_edges[:left_rows_per_party], universal_edges[:right_rows_per_party]

    left_edges = _logical_edges(graph, edge_1[1], direction_1)
    second_is_type = edge_2[1] == TYPE_IDENTITY_RELATION
    if second_is_type:
        # Query rewrites often add a synthetic type edge such as
        # (UNKNOWN film, is a, UNKNOWN/movie/work). MetaQA party graphs do not
        # store that as a normal traversal edge, so we encode it as an identity
        # edge on the first-hop target. The MPC join still checks
        # left.target == right.source privately.
        right_edges = sorted(
            {
                (target, TYPE_IDENTITY_RELATION, target)
                for _, _, target in left_edges
            },
            key=lambda row: (_canonical_text(row[0]), _canonical_text(row[2])),
        )
    else:
        right_edges = _logical_edges(graph, edge_2[1], direction_2)
    if prioritize_query_rows:
        left = [row for row in left_edges if _matches_first_role(row, edge_1)]
        if second_is_type:
            left_targets = {_canonical_text(target) for _, _, target in left}
            right = [row for row in right_edges if _canonical_text(row[0]) in left_targets]
        else:
            right = [row for row in right_edges if _matches_second_role(row, edge_2)]
    else:
        left = list(left_edges)
        right = list(right_edges)
    return left[:left_rows_per_party], right[:right_rows_per_party]


def _encode_rows(setup_key: str, rows: list[tuple[str, str, str]], capacity: int) -> tuple[list[tuple[int, int, int, int]], list[dict]]:
    encoded = [
        (
            _hmac_int(setup_key, "entity", source),
            _hmac_int(setup_key, "relation", relation),
            _hmac_int(setup_key, "entity", target),
            1,
        )
        for source, relation, target in rows
    ]
    public = [
        {
            "source": source,
            "relation": relation,
            "target": target,
            "source_id": _hmac_int(setup_key, "entity", source),
            "relation_id": _hmac_int(setup_key, "relation", relation),
            "target_id": _hmac_int(setup_key, "entity", target),
        }
        for source, relation, target in rows
    ]
    encoded.extend([(0, 0, 0, 0)] * (capacity - len(encoded)))
    public.extend([{"padding": True}] * (capacity - len(public)))
    return encoded, public


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--edge", required=True, action="append", type=_parse_edge)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--left-rows-per-party", type=int, default=8)
    parser.add_argument("--right-rows-per-party", type=int, default=8)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--semantic-relations", action="store_true")
    parser.add_argument("--prioritize-query-rows", action="store_true")
    parser.add_argument(
        "--private-tables",
        action="store_true",
        help="Build query-independent fixed party tables; disables query-dependent row prioritization.",
    )
    args = parser.parse_args()

    if len(args.edge) != 2:
        raise SystemExit("split edge-join prototype requires exactly two --edge values")

    setup_key = os.environ.get("FEDKG_SETUP_KEY")
    if not setup_key:
        raise SystemExit("FEDKG_SETUP_KEY is required")

    original_edge_1, original_edge_2 = args.edge
    relation_1, direction_1 = _normalize_relation(original_edge_1[1], semantic_relations=args.semantic_relations)
    if args.semantic_relations and _is_type_relation(original_edge_2[1]):
        relation_2, direction_2 = TYPE_IDENTITY_RELATION, "forward"
    else:
        relation_2, direction_2 = _normalize_relation(original_edge_2[1], semantic_relations=args.semantic_relations)
    edge_1 = (original_edge_1[0], relation_1, original_edge_1[2])
    edge_2 = (original_edge_2[0], relation_2, original_edge_2[2])
    target = edge_2[2]
    target_is_unknown = 1 if _is_unknown(target) else 0
    target_id = 0 if target_is_unknown else _hmac_int(setup_key, "entity", target)

    manifest = _load_manifest(Path(args.manifest))
    parties = manifest["parties"]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    template_path = _repo_root() / "mpspdz_client_excluded" / "programs" / "secure_kg_twohop_split_edge_join_topk.mpc.template"
    program = template_path.read_text().format(
        left_rows_per_party=args.left_rows_per_party,
        right_rows_per_party=args.right_rows_per_party,
        data_parties=len(parties),
        top_k=args.topk,
    )
    (output_dir / "secure_kg_twohop_split_edge_join_topk.mpc").write_text(program)

    player_data = output_dir / "Player-Data"
    query_values = [
        _hmac_int(setup_key, "entity", edge_1[0]),
        _hmac_int(setup_key, "relation", edge_1[1]),
        _hmac_int(setup_key, "relation", edge_2[1]),
        target_id,
        target_is_unknown,
    ]
    _write_input_file(player_data / "Input-P0-0", query_values)

    left_tables = []
    right_tables = []
    party_summaries = []
    for index, party in enumerate(parties, start=1):
        graph, _ = _load_party(Path(party["data"]))
        left_rows, right_rows = _select_rows(
            graph,
            edge_1,
            edge_2,
            direction_1,
            direction_2,
            args.left_rows_per_party,
            args.right_rows_per_party,
            prioritize_query_rows=args.prioritize_query_rows,
            private_tables=args.private_tables,
        )
        left_encoded, left_public = _encode_rows(setup_key, left_rows, args.left_rows_per_party)
        right_encoded, right_public = _encode_rows(setup_key, right_rows, args.right_rows_per_party)
        flat_values = [value for row in left_encoded for value in row] + [
            value for row in right_encoded for value in row
        ]
        _write_input_file(player_data / f"Input-P{index}-0", flat_values)
        left_tables.append({"player": index, "party_id": party["party_id"], "rows": left_public})
        right_tables.append({"player": index, "party_id": party["party_id"], "rows": right_public})
        party_summaries.append(
            {
                "player": index,
                "party_id": party["party_id"],
                "left_real_rows": len(left_rows),
                "right_real_rows": len(right_rows),
                "left_padded_rows": args.left_rows_per_party,
                "right_padded_rows": args.right_rows_per_party,
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
            "semantic_relations": args.semantic_relations,
            "direction_1": direction_1,
            "direction_2": direction_2,
            "source_id": query_values[0],
            "relation_1_id": query_values[1],
            "relation_2_id": query_values[2],
            "target_id": target_id,
            "target_is_unknown": target_is_unknown,
        },
        "data_parties": party_summaries,
        "left_rows_per_party": args.left_rows_per_party,
        "right_rows_per_party": args.right_rows_per_party,
        "left_total_rows": args.left_rows_per_party * len(parties),
        "right_total_rows": args.right_rows_per_party * len(parties),
        "pair_capacity": args.left_rows_per_party * args.right_rows_per_party * len(parties) * len(parties),
        "topk": args.topk,
        "left_tables": left_tables,
        "right_tables": right_tables,
        "private_tables": args.private_tables,
        "security_note": (
            "This split edge-table prototype performs the two-hop join inside MPC over separate bounded "
            "first-hop and second-hop tables. In private-tables mode, party tables are query-independent; "
            "otherwise query-row prioritization is a local testing shortcut."
        ),
    }
    (output_dir / "public_mapping.json").write_text(json.dumps(mapping, indent=2))
    print(json.dumps({"output_dir": str(output_dir), **mapping}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
