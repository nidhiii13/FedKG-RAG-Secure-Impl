#!/usr/bin/env python3
"""Prepare a bounded edge-table two-hop join instance for MP-SPDZ.

Unlike prepare_metaqa_twohop_mpspdz_inputs.py, this script does not precompute
complete path rows. Each data party contributes padded one-hop edge rows, and
the generated MP-SPDZ program performs the two-hop join privately.

The local test helper can prioritize rows relevant to the requested query so a
small bounded instance is easy to run. That prioritization is not a production
privacy mechanism; production use needs fixed padded edge tables or an ORAM/PIR
style access layer.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import pickle
from pathlib import Path

from prepare_metaqa_twohop_mpspdz_inputs import (
    FIELD_MASK,
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


def _edge_id(setup_key: str, source: str, relation: str, target: str) -> int:
    value = json.dumps(
        [_canonical_text(source), _canonical_text(relation), _canonical_text(target)],
        separators=(",", ":"),
    )
    digest = hmac.new(setup_key.encode("utf-8"), f"edge:{value}".encode("utf-8"), hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big") & FIELD_MASK


def _all_edges(graph: dict) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for source in sorted(graph):
        for relation in sorted(graph[source]):
            for target in sorted(str(value) for value in graph[source][relation]):
                rows.append((str(source), str(relation), target))
    return rows


def _prioritize_edges(
    edges: list[tuple[str, str, str]],
    edge_1: tuple[str, str, str],
    edge_2: tuple[str, str, str],
) -> list[tuple[str, str, str]]:
    source_1, relation_1, _ = edge_1
    _, relation_2, target_2 = edge_2
    target_unknown = _is_unknown(target_2)

    def key(row: tuple[str, str, str]) -> tuple[int, str, str, str]:
        source, relation, target = row
        first_hop = _canonical_text(source) == _canonical_text(source_1) and relation == relation_1
        second_hop = relation == relation_2 and (target_unknown or _canonical_text(target) == _canonical_text(target_2))
        if first_hop:
            priority = 0
        elif second_hop:
            priority = 1
        else:
            priority = 2
        return priority, _canonical_text(source), _canonical_text(relation), _canonical_text(target)

    return sorted(edges, key=key)


def _encoded_edge_rows(
    graph: dict,
    setup_key: str,
    edge_1: tuple[str, str, str],
    edge_2: tuple[str, str, str],
    rows_per_party: int,
    *,
    prioritize_query_rows: bool,
) -> tuple[list[tuple[int, int, int, int]], list[dict]]:
    edges = _all_edges(graph)
    if prioritize_query_rows:
        edges = _prioritize_edges(edges, edge_1, edge_2)
    edges = edges[:rows_per_party]

    encoded_rows = [
        (
            _hmac_int(setup_key, "entity", source),
            _hmac_int(setup_key, "relation", relation),
            _hmac_int(setup_key, "entity", target),
            1,
        )
        for source, relation, target in edges
    ]
    public_rows = [
        {
            "source": source,
            "relation": relation,
            "target": target,
            "edge_id": _edge_id(setup_key, source, relation, target),
            "source_id": _hmac_int(setup_key, "entity", source),
            "relation_id": _hmac_int(setup_key, "relation", relation),
            "target_id": _hmac_int(setup_key, "entity", target),
        }
        for source, relation, target in edges
    ]

    encoded_rows.extend([(0, 0, 0, 0)] * (rows_per_party - len(encoded_rows)))
    public_rows.extend([{"padding": True}] * (rows_per_party - len(public_rows)))
    return encoded_rows, public_rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--edge", required=True, action="append", type=_parse_edge)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--edge-rows-per-party", type=int, default=64)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--semantic-relations", action="store_true")
    parser.add_argument(
        "--prioritize-query-rows",
        action="store_true",
        help="Local smoke-test helper that puts likely matching rows first in the bounded input table.",
    )
    args = parser.parse_args()

    if len(args.edge) != 2:
        raise SystemExit("edge-join prototype requires exactly two --edge values")

    setup_key = os.environ.get("FEDKG_SETUP_KEY")
    if not setup_key:
        raise SystemExit("FEDKG_SETUP_KEY is required")

    original_edge_1, original_edge_2 = args.edge
    edge_1 = _normalize_edge_relations(original_edge_1, semantic_relations=args.semantic_relations)
    edge_2 = _normalize_edge_relations(original_edge_2, semantic_relations=args.semantic_relations)
    target = edge_2[2]
    target_is_unknown = 1 if _is_unknown(target) else 0
    target_id = 0 if target_is_unknown else _hmac_int(setup_key, "entity", target)

    manifest = _load_manifest(Path(args.manifest))
    parties = manifest["parties"]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    template_path = _repo_root() / "mpspdz_client_excluded" / "programs" / "secure_kg_twohop_edge_join_topk.mpc.template"
    program = template_path.read_text().format(
        edge_rows_per_party=args.edge_rows_per_party,
        data_parties=len(parties),
        top_k=args.topk,
    )
    (output_dir / "secure_kg_twohop_edge_join_topk.mpc").write_text(program)

    player_data = output_dir / "Player-Data"
    query_values = [
        _hmac_int(setup_key, "entity", edge_1[0]),
        _hmac_int(setup_key, "relation", edge_1[1]),
        _hmac_int(setup_key, "relation", edge_2[1]),
        target_id,
        target_is_unknown,
    ]
    _write_input_file(player_data / "Input-P0-0", query_values)

    edge_tables = []
    party_summaries = []
    for index, party in enumerate(parties, start=1):
        graph, _ = _load_party(Path(party["data"]))
        encoded_rows, public_rows = _encoded_edge_rows(
            graph,
            setup_key,
            edge_1,
            edge_2,
            args.edge_rows_per_party,
            prioritize_query_rows=args.prioritize_query_rows,
        )
        _write_input_file(player_data / f"Input-P{index}-0", [value for row in encoded_rows for value in row])
        edge_tables.append({"player": index, "party_id": party["party_id"], "rows": public_rows})
        party_summaries.append(
            {
                "player": index,
                "party_id": party["party_id"],
                "real_rows": sum(1 for row in public_rows if not row.get("padding")),
                "padded_rows": args.edge_rows_per_party,
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
            "source_id": query_values[0],
            "relation_1_id": query_values[1],
            "relation_2_id": query_values[2],
            "target_id": target_id,
            "target_is_unknown": target_is_unknown,
        },
        "data_parties": party_summaries,
        "edge_rows_per_party": args.edge_rows_per_party,
        "total_edge_rows": args.edge_rows_per_party * len(parties),
        "topk": args.topk,
        "edge_tables": edge_tables,
        "security_note": (
            "This edge-table prototype performs the two-hop join inside MPC. "
            "The optional row prioritization and plaintext mapping are local testing aids, not production privacy mechanisms."
        ),
    }
    (output_dir / "public_mapping.json").write_text(json.dumps(mapping, indent=2))
    print(json.dumps({"output_dir": str(output_dir), **mapping}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
