#!/usr/bin/env python3
"""Prepare several private queries against one initialized MP-SPDZ ORAM state."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from bucketed_oram_index import directory_slot, probe_slots
from prepare_metaqa_mpspdz_inputs import _normalize_relation
from prepare_metaqa_twohop_mpspdz_inputs import _hmac_int, _is_unknown, _repo_root, _write_input_file
from prepare_metaqa_twohop_oram_mpspdz_inputs import (
    _bits_for,
    _direction_bit,
    _is_oram_type_relation,
)
from prepare_metaqa_twohop_split_edge_join_mpspdz_inputs import TYPE_IDENTITY_RELATION


SINGLE_PREPARER = Path(__file__).with_name("prepare_metaqa_twohop_oram_mpspdz_inputs.py")


def _two_edges(graph: list[list[str]]) -> list[list[str]]:
    if len(graph) == 2:
        return graph
    if len(graph) == 1:
        return [graph[0], [graph[0][2], "is a", "UNKNOWN"]]
    raise ValueError(f"expected one or two query-graph edges, got {len(graph)}")


def _edge_arg(edge: list[str]) -> str:
    return "|".join(str(value) for value in edge)


def _encode_query(
    query: dict,
    setup_key: str,
    directory_capacity: int,
    probe_limit: int,
) -> tuple[list[int], dict]:
    original_edge_1, original_edge_2 = _two_edges(query["query_graph"])
    relation_1, direction_1 = _normalize_relation(original_edge_1[1], semantic_relations=True)
    type_identity = _is_oram_type_relation(original_edge_2[1])
    if type_identity:
        relation_2, direction_2 = TYPE_IDENTITY_RELATION, "forward"
    else:
        relation_2, direction_2 = _normalize_relation(original_edge_2[1], semantic_relations=True)
    target_unknown = _is_unknown(original_edge_2[2])
    if target_unknown and not type_identity:
        raise ValueError("unknown-to-unknown second-hop expansion is unsupported")

    source_id = _hmac_int(setup_key, "entity", original_edge_1[0])
    relation_1_id = _hmac_int(setup_key, "relation", relation_1)
    relation_2_id = _hmac_int(setup_key, "relation", relation_2)
    target_id = 0 if target_unknown else _hmac_int(setup_key, "entity", original_edge_2[2])
    direction_1_bit = _direction_bit(direction_1)
    direction_2_bit = _direction_bit(direction_2)
    source_base = directory_slot(
        setup_key, "source", direction_1_bit, source_id, relation_1_id, directory_capacity
    )
    target_base = directory_slot(
        setup_key, "target", direction_2_bit, target_id, relation_2_id, directory_capacity
    )
    values = [
        source_id,
        relation_1_id,
        direction_1_bit,
        relation_2_id,
        direction_2_bit,
        target_id,
        int(target_unknown),
        int(type_identity),
        *probe_slots(source_base, directory_capacity, probe_limit),
        *probe_slots(target_base, directory_capacity, probe_limit),
    ]
    receipt = {
        "index": query.get("index"),
        "query": query.get("query"),
        "groundtruths": query.get("groundtruths", []),
        "query_graph": query.get("query_graph"),
        "effective_edges": [original_edge_1, original_edge_2],
        "canonical_relations": [relation_1, relation_2],
        "directions": [direction_1, direction_2],
        "type_identity_mode": type_identity,
    }
    return values, receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--index-dir", required=True)
    parser.add_argument("--queries-jsonl", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-queries", type=int, default=10)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--max-candidates", type=int, default=64)
    parser.add_argument("--topk", type=int, default=3)
    args = parser.parse_args()
    setup_key = os.environ.get("FEDKG_SETUP_KEY")
    if not setup_key:
        raise SystemExit("FEDKG_SETUP_KEY is required")

    queries = [json.loads(line) for line in Path(args.queries_jsonl).read_text().splitlines() if line.strip()]
    queries = queries[args.start_index : args.start_index + args.max_queries]
    if not queries:
        raise SystemExit("no queries selected")
    first_edges = _two_edges(queries[0]["query_graph"])
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        str(SINGLE_PREPARER),
        "--manifest",
        args.manifest,
        "--index-dir",
        args.index_dir,
        "--edge",
        _edge_arg(first_edges[0]),
        "--edge",
        _edge_arg(first_edges[1]),
        "--output-dir",
        str(output_dir),
        "--max-candidates",
        str(args.max_candidates),
        "--topk",
        str(args.topk),
        "--semantic-relations",
    ]
    prepared = subprocess.run(
        command,
        cwd=_repo_root(),
        env=os.environ.copy(),
        check=True,
        text=True,
        capture_output=True,
    )
    mapping = json.loads(prepared.stdout)
    directory_capacity = mapping["data_parties"][0]["source_directory_capacity"]
    source_edge_capacity = mapping["data_parties"][0]["source_edge_capacity"]
    target_edge_capacity = mapping["data_parties"][0]["target_edge_capacity"]
    probe_limit = mapping["probe_limit"]

    query_values = []
    receipts = []
    for query in queries:
        values, receipt = _encode_query(query, setup_key, directory_capacity, probe_limit)
        query_values.extend(values)
        receipts.append(receipt)
    query_input = output_dir / "Player-Data" / "Input-P0-0"
    _write_input_file(query_input, query_values)
    query_input.chmod(0o600)

    template = (
        _repo_root()
        / "mpspdz_client_excluded"
        / "programs"
        / "secure_kg_twohop_oram_join_topk.mpc.template"
    ).read_text()
    program = template.format(
        data_parties=len(mapping["data_parties"]),
        directory_capacity=directory_capacity,
        source_edge_capacity=source_edge_capacity,
        target_edge_capacity=target_edge_capacity,
        probe_limit=probe_limit,
        max_candidates=args.max_candidates,
        top_k=args.topk,
        query_count=len(queries),
        source_edge_index_bits=_bits_for(source_edge_capacity),
        target_edge_index_bits=_bits_for(target_edge_capacity),
        candidate_count_bits=_bits_for(max(source_edge_capacity, target_edge_capacity)),
    )
    program_path = output_dir / "secure_kg_twohop_oram_join_topk.mpc"
    program_path.write_text(program)

    batch_receipt = {
        "format": "fedkg-mpspdz-oram-query-batch-v1",
        "index_dir": mapping["index_dir"],
        "data_parties": mapping["data_parties"],
        "queries": receipts,
        "topk": args.topk,
        "max_candidates": args.max_candidates,
        "probe_limit": probe_limit,
    }
    receipt_path = output_dir / "query_gateway_receipt.json"
    receipt_path.write_text(json.dumps(batch_receipt, indent=2))
    receipt_path.chmod(0o600)
    print(json.dumps({"output_dir": str(output_dir), **batch_receipt}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
