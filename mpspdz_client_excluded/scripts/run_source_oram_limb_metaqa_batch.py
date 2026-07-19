#!/usr/bin/env python3
"""Run source-only MP-SPDZ ORAM retrieval with exact 128-bit HMAC IDs."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

from bucketed_oram_limb_index import (
    ID_EFFECTIVE_BITS,
    ID_LIMBS,
    directory_slot_limb,
    hmac_limbs,
    probe_slots,
    read_party_index,
)
from decode_mpspdz_oram_output import _load_vaults, _resolve
from local_gc_ranking import rerank_selected_paths_with_local_gc
from prepare_metaqa_mpspdz_inputs import _normalize_relation
from prepare_metaqa_twohop_mpspdz_inputs import _is_unknown, _load_manifest, _repo_root, _write_input_file
from prepare_metaqa_twohop_oram_mpspdz_inputs import _bits_for, _direction_bit, _pad_rows
from prepare_metaqa_twohop_split_edge_join_mpspdz_inputs import TYPE_IDENTITY_RELATION, _is_type_relation
from run_twohop_e2e import _parse_mpspdz_metrics, _run
from src.semantic.relation_buckets import relation_bucket_names


REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")


def _edge_tuple(value: object) -> tuple[str, str, str]:
    if not isinstance(value, (list, tuple)) or len(value) != 3:
        raise ValueError("query graph edges must be [source, relation, target]")
    return str(value[0]), str(value[1]), str(value[2])


def _opposite_direction(direction_bit: int) -> int:
    if direction_bit not in (0, 1):
        raise ValueError(f"unsupported direction bit {direction_bit}")
    return 1 - direction_bit


def _semantic_relation_match(
    label: str,
    metadata: dict,
    *,
    bucket_mode: str,
) -> tuple[str | None, dict]:
    index_mode = metadata.get("semantic_bucket_mode")
    bucket_index = metadata.get("semantic_relation_buckets") or {}
    if index_mode != bucket_mode:
        raise ValueError(f"semantic bucket mode mismatch: index={index_mode}, query={bucket_mode}")
    buckets = relation_bucket_names(label, mode=bucket_mode)  # type: ignore[arg-type]
    counts: dict[str, int] = {}
    matched_buckets: dict[str, list[str]] = {}
    for bucket in buckets:
        relations = list(bucket_index.get(bucket, []))
        if not relations:
            continue
        matched_buckets[bucket] = relations
        for relation in relations:
            counts[relation] = counts.get(relation, 0) + 1
    if not counts:
        return None, {
            "label": label,
            "bucket_mode": bucket_mode,
            "bucket_count": len(buckets),
            "matched_buckets": {},
            "selected_relation": None,
        }
    selected = sorted(counts, key=lambda relation: (-counts[relation], relation))[0]
    return selected, {
        "label": label,
        "bucket_mode": bucket_mode,
        "bucket_count": len(buckets),
        "matched_buckets": matched_buckets,
        "candidate_counts": counts,
        "selected_relation": selected,
    }


def _resolve_relation(
    label: str,
    metadata: dict,
    *,
    semantic_relations: bool,
    semantic_buckets: bool,
    bucket_mode: str,
) -> tuple[str, str, dict | None]:
    normalized_relation, direction = _normalize_relation(label, semantic_relations=semantic_relations)
    if not semantic_buckets:
        return normalized_relation, direction, None
    routed_relation, trace = _semantic_relation_match(label, metadata, bucket_mode=bucket_mode)
    if routed_relation is None:
        trace["fallback_relation"] = normalized_relation
        return normalized_relation, direction, trace
    return routed_relation, direction, trace


def _normalize_query(
    row: dict,
    setup_key: str,
    metadata: dict,
    *,
    semantic_relations: bool,
    semantic_buckets: bool,
    bucket_mode: str,
) -> tuple[dict, list[int]]:
    original_edges = [_edge_tuple(edge) for edge in (row.get("query_graph") or row.get("edges") or [])]
    if len(original_edges) == 1:
        unknown = original_edges[0][2]
        original_edges.append((unknown, "is a", "UNKNOWN"))
        synthetic_onehop = True
    elif len(original_edges) == 2:
        synthetic_onehop = False
    else:
        raise ValueError(f"128-bit source-only ORAM batch supports one or two edges, got {len(original_edges)}")

    first, second = original_edges
    relation_1, direction_1, semantic_trace_1 = _resolve_relation(
        first[1],
        metadata,
        semantic_relations=semantic_relations,
        semantic_buckets=semantic_buckets,
        bucket_mode=bucket_mode,
    )
    type_mode = bool(semantic_relations and _is_type_relation(second[1]))
    if type_mode:
        relation_2, direction_2, semantic_trace_2 = TYPE_IDENTITY_RELATION, "forward", None
    else:
        relation_2, direction_2, semantic_trace_2 = _resolve_relation(
            second[1],
            metadata,
            semantic_relations=semantic_relations,
            semantic_buckets=semantic_buckets,
            bucket_mode=bucket_mode,
        )
    target_is_unknown = _is_unknown(second[2])
    if target_is_unknown and not type_mode:
        raise ValueError("unknown-to-unknown second hop requires iterative private frontier access")

    source_id = hmac_limbs(setup_key, "entity", first[0])
    relation_1_id = hmac_limbs(setup_key, "relation", relation_1)
    relation_2_id = hmac_limbs(setup_key, "relation", relation_2)
    target_id = tuple(0 for _ in range(ID_LIMBS)) if target_is_unknown else hmac_limbs(setup_key, "entity", second[2])
    direction_1_bit = _direction_bit(direction_1)
    direction_2_bit = _direction_bit(direction_2)
    reverse_direction_2_bit = _opposite_direction(direction_2_bit)
    normalized = {
        "index": row.get("index"),
        "query": row.get("query") or row.get("question"),
        "groundtruths": row.get("groundtruths") or row.get("answers") or [],
        "federated_correct": row.get("federated_correct"),
        "federated_retrieval_time": row.get("federated_retrieval_time"),
        "original_edges": [list(edge) for edge in (original_edges[:1] if synthetic_onehop else original_edges)],
        "normalized_edges": [
            [first[0], relation_1, first[2]],
            [second[0], relation_2, second[2]],
        ],
        "directions": [direction_1, direction_2],
        "type_identity_mode": type_mode,
        "synthetic_onehop": synthetic_onehop,
        "semantic_bucket_routing": {
            "enabled": semantic_buckets,
            "mode": bucket_mode if semantic_buckets else None,
            "edge_1": semantic_trace_1,
            "edge_2": semantic_trace_2,
        },
    }
    values = [
        *source_id,
        *relation_1_id,
        direction_1_bit,
        *relation_2_id,
        reverse_direction_2_bit,
        *target_id,
        int(target_is_unknown),
        int(type_mode),
    ]
    normalized["_lookup"] = {
        "source_id": source_id,
        "relation_1_id": relation_1_id,
        "relation_2_id": relation_2_id,
        "reverse_direction_2_bit": reverse_direction_2_bit,
        "direction_1_bit": direction_1_bit,
        "target_id": target_id,
    }
    return normalized, values


def _parse_outputs(output: str, query_count: int) -> list[list[tuple[int, int]]]:
    selected: list[list[tuple[int, int]]] = [[] for _ in range(query_count)]
    in_table = False
    for line in output.splitlines():
        if line.strip() == "query rank left_evidence_handle right_evidence_handle":
            in_table = True
            continue
        if not in_table:
            continue
        match = OUTPUT_RE.match(line)
        if not match:
            if any(selected):
                break
            continue
        query = int(match.group(1))
        left = int(match.group(3))
        right = int(match.group(4))
        if query >= query_count:
            raise ValueError(f"MP-SPDZ returned invalid query index {query}")
        if left:
            selected[query].append((left, right))
    return selected


def _contains_groundtruth(edges: list[list[str]], groundtruths: list[str]) -> bool:
    haystack = "\n".join(part for edge in edges for part in edge).lower()
    return bool(groundtruths) and any(str(answer).lower() in haystack for answer in groundtruths)


def _logical_right_edge(reverse_edge: dict | None) -> list[str] | None:
    if reverse_edge is None:
        return None
    return [reverse_edge["target"], reverse_edge["relation"], reverse_edge["source"]]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--index-dir", required=True)
    parser.add_argument("--queries-jsonl", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--instance-dir", required=True)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--max-queries", type=int, default=10)
    parser.add_argument("--max-candidates", type=int, default=16)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--semantic-relations", action="store_true")
    parser.add_argument("--semantic-buckets", action="store_true")
    parser.add_argument("--semantic-bucket-mode", choices=["alias", "lsh", "hybrid"], default="hybrid")
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    parser.add_argument(
        "--ranking-backend",
        choices=("mpc", "local-gc-prototype"),
        default="mpc",
    )
    args = parser.parse_args()

    setup_key = os.environ.get("FEDKG_SETUP_KEY")
    if not setup_key:
        raise SystemExit("FEDKG_SETUP_KEY is required")
    index_root = Path(args.index_dir)
    metadata = json.loads((index_root / "metadata.json").read_text())
    if metadata.get("format") != "fedkg-mpspdz-oram-limb-index-set-v1":
        raise SystemExit("unsupported 128-bit ORAM index-set format")
    if int(metadata.get("id_limbs", 0)) != ID_LIMBS:
        raise SystemExit("unsupported limb count")
    rows = []
    with Path(args.queries_jsonl).open() as handle:
        for line_number, line in enumerate(handle):
            if line_number < args.start_index:
                continue
            if len(rows) >= args.max_queries:
                break
            rows.append(json.loads(line))
    if not rows:
        raise SystemExit("no queries selected")

    normalized_queries = []
    base_query_values = []
    for row in rows:
        normalized, values = _normalize_query(
            row,
            setup_key,
            metadata,
            semantic_relations=args.semantic_relations,
            semantic_buckets=args.semantic_buckets,
            bucket_mode=args.semantic_bucket_mode,
        )
        normalized_queries.append(normalized)
        base_query_values.append(values)

    manifest = _load_manifest(Path(args.manifest))
    party_ids = [party["party_id"] for party in manifest["parties"]]
    if args.max_candidates > int(metadata["max_candidates"]):
        raise SystemExit("max-candidates exceeds the offline index read padding")
    indexes = [read_party_index(index_root / party_id) for party_id in party_ids]
    directory_capacity = int(metadata["directory_capacity"])
    source_edge_capacity = max(len(index["source_edges"]) for index in indexes)
    probe_limit = max(index["stats"]["source_probe_limit"] for index in indexes)

    query_values = []
    for normalized, values in zip(normalized_queries, base_query_values):
        lookup = normalized.pop("_lookup")
        source_base = directory_slot_limb(
            setup_key,
            "source",
            lookup["direction_1_bit"],
            lookup["source_id"],
            lookup["relation_1_id"],
            directory_capacity,
        )
        reverse_base = directory_slot_limb(
            setup_key,
            "source",
            lookup["reverse_direction_2_bit"],
            lookup["target_id"],
            lookup["relation_2_id"],
            directory_capacity,
        )
        query_values.extend(values)
        query_values.extend(probe_slots(source_base, directory_capacity, probe_limit))
        query_values.extend(probe_slots(reverse_base, directory_capacity, probe_limit))

    instance_dir = Path(args.instance_dir)
    instance_dir.mkdir(parents=True, exist_ok=True)
    template = (
        _repo_root()
        / "mpspdz_client_excluded"
        / "programs"
        / "secure_kg_twohop_source_oram_limb_batch_topk.mpc.template"
    ).read_text()
    program = template.format(
        data_parties=len(indexes),
        num_queries=len(rows),
        directory_capacity=directory_capacity,
        source_edge_capacity=source_edge_capacity,
        probe_limit=probe_limit,
        max_candidates=args.max_candidates,
        top_k=args.topk,
        source_edge_index_bits=_bits_for(source_edge_capacity),
        candidate_count_bits=_bits_for(source_edge_capacity),
    )
    program_name = "secure_kg_twohop_source_oram_limb_batch_topk"
    (instance_dir / f"{program_name}.mpc").write_text(program)
    player_data = instance_dir / "Player-Data"
    query_path = player_data / "Input-P0-0"
    _write_input_file(query_path, query_values)
    query_path.chmod(0o600)
    for player, index in enumerate(indexes, start=1):
        source_edges = _pad_rows(index["source_edges"], source_edge_capacity, 14)
        values = [
            value
            for table in (index["source_directory"], source_edges)
            for row in table
            for value in row
        ]
        input_path = player_data / f"Input-P{player}-0"
        _write_input_file(input_path, values)
        input_path.chmod(0o600)

    receipt = {
        "format": "fedkg-mpspdz-source-oram-limb-batch-v1",
        "id_limbs": ID_LIMBS,
        "id_effective_bits": ID_EFFECTIVE_BITS,
        "index_dir": str(index_root.resolve()),
        "data_parties": [{"party_id": party_id} for party_id in party_ids],
        "queries": normalized_queries,
        "security_note": (
            "Entity/relation equality uses four HMAC-derived 32-bit limbs. All limbs must match."
        ),
    }
    receipt_path = instance_dir / "query_gateway_receipt.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2))
    receipt_path.chmod(0o600)

    print(f"Prepared {len(rows)} private queries with 128-bit source-only ORAM state.", flush=True)
    started = time.perf_counter()
    run_env = os.environ.copy()
    run_env["MP_SPDZ_HOME"] = args.mp_spdz_home
    mpc = _run(
        ["bash", str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "run_mpspdz_oram_instance.sh"), str(instance_dir)],
        env=run_env,
        cwd=REPO_ROOT,
    )
    elapsed = time.perf_counter() - started
    raw_output = instance_dir / "mp_spdz_output.txt"
    raw_output.write_text(mpc.stdout)
    raw_output.chmod(0o600)
    selected = _parse_outputs(mpc.stdout, len(rows))
    vaults = _load_vaults(receipt)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    correct = 0
    records = []
    for query_number, (query, handles) in enumerate(zip(normalized_queries, selected)):
        paths = []
        all_edges = []
        for rank, (left_handle, right_handle) in enumerate(handles):
            left = _resolve(left_handle, vaults)
            right = _resolve(right_handle, vaults)
            edges = [[left["source"], left["relation"], left["target"]]]
            logical_right = _logical_right_edge(right)
            if logical_right is not None:
                edges.append(logical_right)
            paths.append({"rank": rank, "edges": edges})
            all_edges.extend(edges)
        local_gc = None
        if args.ranking_backend == "local-gc-prototype":
            paths, local_gc = rerank_selected_paths_with_local_gc(
                paths,
                party_count=len(party_ids),
                k=args.topk,
            )
            all_edges = [edge for path in paths for edge in path["edges"]]
        is_correct = _contains_groundtruth(all_edges, query["groundtruths"])
        correct += int(is_correct)
        record = {
            **query,
            "status": "ok",
            "source_oram_limb_mpc_correct": is_correct,
            "ranking_backend": args.ranking_backend,
            "selected_paths": paths,
        }
        if local_gc is not None:
            record["local_gc_ranking"] = local_gc
        records.append(record)
        print(
            f"[{query_number + 1}/{len(rows)}] index={query['index']} "
            f"correct={is_correct} paths={len(paths)} query={query['query']}",
            flush=True,
        )
    with output_path.open("w") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    summary = {
        "total": len(rows),
        "correct": correct,
        "accuracy": correct / len(rows),
        "batch_e2e_seconds": elapsed,
        "average_amortized_seconds": elapsed / len(rows),
        "mp_spdz_metrics": _parse_mpspdz_metrics(mpc.stdout),
        "output": str(output_path),
        "instance_dir": str(instance_dir),
        "optimized_path": "source-only-oram-128-bit",
        "id_effective_bits": ID_EFFECTIVE_BITS,
        "ranking_backend": args.ranking_backend,
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
