#!/usr/bin/env python3
"""Run 128-bit MP-SPDZ ORAM retrieval with private relation-bucket routing."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

from bucketed_oram_limb_index import (
    ID_EFFECTIVE_BITS,
    ID_LIMBS,
    entity_directory_slot_limb,
    hmac_limbs,
    probe_slots,
    read_private_semantic_party_index,
    relation_bucket_slot_limb,
)
from decode_mpspdz_oram_output import _load_vaults, _resolve
from local_gc_ranking import rerank_selected_paths_with_local_gc
from prepare_metaqa_mpspdz_inputs import _normalize_relation
from prepare_metaqa_twohop_mpspdz_inputs import _is_unknown, _load_manifest, _repo_root, _write_input_file
from prepare_metaqa_twohop_oram_mpspdz_inputs import _bits_for, _direction_bit, _pad_rows
from prepare_metaqa_twohop_split_edge_join_mpspdz_inputs import _is_type_relation
from run_twohop_e2e import _parse_mpspdz_metrics, _run

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.semantic.relation_buckets import relation_bucket_names


OUTPUT_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")
_LOW_VALUE_TOKENS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "by",
    "did",
    "do",
    "does",
    "for",
    "in",
    "is",
    "of",
    "the",
    "to",
    "was",
    "were",
    "what",
    "which",
    "who",
}


def _edge_tuple(value: object) -> tuple[str, str, str]:
    if not isinstance(value, (list, tuple)) or len(value) != 3:
        raise ValueError("query graph edges must be [source, relation, target]")
    return str(value[0]), str(value[1]), str(value[2])


def _opposite_direction(direction_bit: int) -> int:
    if direction_bit not in (0, 1):
        raise ValueError(f"unsupported direction bit {direction_bit}")
    return 1 - direction_bit


def _query_buckets(label: str, *, mode: str, limit: int) -> list[str]:
    buckets = relation_bucket_names(label, mode=mode)  # type: ignore[arg-type]
    if not buckets:
        raise ValueError(f"relation label produced no semantic buckets: {label}")
    ordered = []
    ordered.extend(sorted(bucket for bucket in buckets if bucket.startswith("alias:")))
    ordered.extend(
        sorted(
            bucket
            for bucket in buckets
            if bucket.startswith("tok:") and bucket.split(":", 1)[1] not in _LOW_VALUE_TOKENS
        )
    )
    ordered.extend(
        sorted(
            bucket
            for bucket in buckets
            if bucket.startswith("bigram:")
            and not any(part in _LOW_VALUE_TOKENS for part in bucket.split(":")[1:])
        )
    )
    ordered.extend(sorted(bucket for bucket in buckets if bucket.startswith("lsh:")))
    ordered.extend(sorted(bucket for bucket in buckets if bucket not in ordered))
    deduped = list(dict.fromkeys(ordered or sorted(buckets)))
    return deduped[:limit]


def _normalize_query(
    row: dict,
    setup_key: str,
    *,
    bucket_mode: str,
    max_query_buckets: int,
) -> tuple[dict, list[int]]:
    original_edges = [_edge_tuple(edge) for edge in (row.get("query_graph") or row.get("edges") or [])]
    if len(original_edges) == 1:
        unknown = original_edges[0][2]
        original_edges.append((unknown, "is a", "UNKNOWN"))
        synthetic_onehop = True
    elif len(original_edges) == 2:
        synthetic_onehop = False
    else:
        raise ValueError(
            f"private semantic 128-bit source-only ORAM supports one or two edges, got {len(original_edges)}"
        )

    first, second = original_edges
    _, direction_1 = _normalize_relation(first[1], semantic_relations=True)
    type_mode = bool(_is_type_relation(second[1]))
    if type_mode:
        relation_2_buckets: list[str] = []
        direction_2 = "forward"
    else:
        _, direction_2 = _normalize_relation(second[1], semantic_relations=True)
        relation_2_buckets = _query_buckets(
            second[1],
            mode=bucket_mode,
            limit=max_query_buckets,
        )
    relation_1_buckets = _query_buckets(
        first[1],
        mode=bucket_mode,
        limit=max_query_buckets,
    )
    target_is_unknown = _is_unknown(second[2])
    if target_is_unknown and not type_mode:
        raise ValueError("unknown-to-unknown second hop requires iterative private frontier access")

    source_id = hmac_limbs(setup_key, "entity", first[0])
    zero_bucket_id = tuple(0 for _ in range(ID_LIMBS))
    relation_1_bucket_ids = [
        hmac_limbs(setup_key, "relation_bucket", bucket)
        for bucket in relation_1_buckets
    ]
    relation_2_bucket_ids = [
        hmac_limbs(setup_key, "relation_bucket", bucket)
        for bucket in relation_2_buckets
    ]
    relation_1_bucket_ids.extend([zero_bucket_id] * (max_query_buckets - len(relation_1_bucket_ids)))
    relation_2_bucket_ids.extend([zero_bucket_id] * (max_query_buckets - len(relation_2_bucket_ids)))
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
        "directions": [direction_1, direction_2],
        "type_identity_mode": type_mode,
        "synthetic_onehop": synthetic_onehop,
        "private_semantic_bucket_routing": {
            "enabled": True,
            "mode": bucket_mode,
            "edge_1_query_buckets": relation_1_buckets,
            "edge_2_query_buckets": [] if type_mode else relation_2_buckets,
            "max_query_buckets": max_query_buckets,
            "note": "Query bucket IDs are secret inputs; bucket-to-relation resolution is performed inside MP-SPDZ.",
        },
    }
    values = [
        *source_id,
        *(limb for bucket_id in relation_1_bucket_ids for limb in bucket_id),
        direction_1_bit,
        *(limb for bucket_id in relation_2_bucket_ids for limb in bucket_id),
        reverse_direction_2_bit,
        *target_id,
        int(target_is_unknown),
        int(type_mode),
    ]
    normalized["_lookup"] = {
        "source_id": source_id,
        "relation_1_bucket_ids": relation_1_bucket_ids,
        "relation_2_bucket_ids": relation_2_bucket_ids,
        "target_id": target_id,
        "direction_1_bit": direction_1_bit,
        "reverse_direction_2_bit": reverse_direction_2_bit,
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


def _entity_directory_count(index: dict, entity_id: tuple[int, ...], direction: int, slots: list[int]) -> int:
    for slot in slots:
        entry = index["entity_directory"][slot]
        if (
            entry[7]
            and tuple(entry[:ID_LIMBS]) == tuple(entity_id)
            and int(entry[4]) == int(direction)
        ):
            return int(entry[6])
    return 0


def _remap_slots(slots: list[int], mapping: dict[int, int]) -> list[int]:
    return [mapping[slot] for slot in slots]


def _compact_party_index_for_probes(
    index: dict,
    *,
    entity_slots: list[int],
    relation_bucket_slots: list[int],
    max_candidates: int,
    max_relation_candidates: int,
    fixed_entity_slots: int | None = None,
    fixed_relation_slots: int | None = None,
    fixed_entity_edge_rows: int | None = None,
    fixed_relation_edge_rows: int | None = None,
) -> tuple[dict, dict[int, int], dict[int, int]]:
    unique_entity_slots = list(dict.fromkeys(entity_slots))
    if fixed_entity_slots is not None and len(unique_entity_slots) > fixed_entity_slots:
        raise ValueError(
            f"compact entity slot bound too small: {len(unique_entity_slots)} > {fixed_entity_slots}"
        )
    entity_slot_map = {slot: new_slot for new_slot, slot in enumerate(unique_entity_slots)}
    compact_entity_directory = []
    compact_entity_edges = []
    for old_slot in unique_entity_slots:
        row = list(index["entity_directory"][old_slot])
        if row[7]:
            old_offset = int(row[5])
            old_count = min(int(row[6]), max_candidates)
            new_offset = len(compact_entity_edges)
            compact_entity_edges.extend(index["entity_edges"][old_offset : old_offset + old_count])
            row[5] = new_offset
            row[6] = old_count
        compact_entity_directory.append(row)
    if fixed_entity_slots is not None:
        compact_entity_directory.extend(
            [[0] * 8 for _ in range(fixed_entity_slots - len(compact_entity_directory))]
        )
    compact_entity_edges.extend([[0] * 14 for _ in range(max_candidates)])
    if fixed_entity_edge_rows is not None:
        if len(compact_entity_edges) > fixed_entity_edge_rows:
            raise ValueError(
                f"compact entity edge bound too small: {len(compact_entity_edges)} > {fixed_entity_edge_rows}"
            )
        compact_entity_edges.extend(
            [[0] * 14 for _ in range(fixed_entity_edge_rows - len(compact_entity_edges))]
        )

    unique_relation_slots = list(dict.fromkeys(relation_bucket_slots))
    if fixed_relation_slots is not None and len(unique_relation_slots) > fixed_relation_slots:
        raise ValueError(
            f"compact relation slot bound too small: {len(unique_relation_slots)} > {fixed_relation_slots}"
        )
    relation_slot_map = {slot: new_slot for new_slot, slot in enumerate(unique_relation_slots)}
    compact_relation_directory = []
    compact_relation_edges = []
    for old_slot in unique_relation_slots:
        row = list(index["relation_bucket_directory"][old_slot])
        if row[6]:
            old_offset = int(row[4])
            old_count = min(int(row[5]), max_relation_candidates)
            new_offset = len(compact_relation_edges)
            compact_relation_edges.extend(
                index["relation_bucket_edges"][old_offset : old_offset + old_count]
            )
            row[4] = new_offset
            row[5] = old_count
        compact_relation_directory.append(row)
    if fixed_relation_slots is not None:
        compact_relation_directory.extend(
            [[0] * 7 for _ in range(fixed_relation_slots - len(compact_relation_directory))]
        )
    compact_relation_edges.extend([[0] * 5 for _ in range(max_relation_candidates)])
    if fixed_relation_edge_rows is not None:
        if len(compact_relation_edges) > fixed_relation_edge_rows:
            raise ValueError(
                f"compact relation edge bound too small: {len(compact_relation_edges)} > {fixed_relation_edge_rows}"
            )
        compact_relation_edges.extend(
            [[0] * 5 for _ in range(fixed_relation_edge_rows - len(compact_relation_edges))]
        )

    compact_index = {
        **index,
        "entity_directory": compact_entity_directory,
        "entity_edges": compact_entity_edges,
        "relation_bucket_directory": compact_relation_directory,
        "relation_bucket_edges": compact_relation_edges,
    }
    return compact_index, entity_slot_map, relation_slot_map


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
    parser.add_argument(
        "--auto-tighten-max-candidates",
        action="store_true",
        help=(
            "Use the smallest MAX_CANDIDATES required by this local batch. "
            "This is useful for local benchmarking, but query-dependent runtime "
            "can reveal a degree bound."
        ),
    )
    parser.add_argument(
        "--require-full-fanout",
        action="store_true",
        help="Fail instead of truncating when max-candidates is below a needed entity block count.",
    )
    parser.add_argument("--max-relation-candidates", type=int, default=1)
    parser.add_argument("--max-query-buckets", type=int, default=4)
    parser.add_argument(
        "--compact-probed-benchmark",
        action="store_true",
        help=(
            "Local benchmark mode: compact party ORAM inputs to the directory probe slots "
            "and edge blocks touched by this selected batch. This is not production-secure "
            "because table size becomes query-dependent."
        ),
    )
    parser.add_argument("--fixed-compact-entity-slots", type=int)
    parser.add_argument("--fixed-compact-relation-slots", type=int)
    parser.add_argument("--fixed-compact-edge-rows", type=int)
    parser.add_argument("--fixed-compact-relation-rows", type=int)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--semantic-bucket-mode", choices=["alias", "lsh", "hybrid"], default="hybrid")
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    parser.add_argument(
        "--mp-spdz-protocol",
        choices=("semi", "semi2k", "replicated", "ring", "ps-rep-ring", "sy-rep-ring", "rep4-ring", "shamir"),
        default="semi",
        help="MP-SPDZ protocol script. Default preserves the existing semi-party path.",
    )
    parser.add_argument(
        "--skip-compile-if-present",
        action="store_true",
        help="Reuse an existing MP-SPDZ compiled program when the public circuit profile matches.",
    )
    parser.add_argument(
        "--production-secure",
        action="store_true",
        help=(
            "Enforce the pre-reveal MP-SPDZ ranking path and fixed public fanout. "
            "This rejects local GC prototype reranking and query-dependent auto-tightening."
        ),
    )
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
    if metadata.get("format") != "fedkg-mpspdz-oram-limb-private-semantic-index-set-v1":
        raise SystemExit("unsupported private semantic 128-bit ORAM index-set format")
    if int(metadata.get("id_limbs", 0)) != ID_LIMBS:
        raise SystemExit("unsupported limb count")
    if metadata.get("semantic_bucket_mode") != args.semantic_bucket_mode:
        raise SystemExit("semantic bucket mode mismatch between index and query")
    if args.max_candidates > int(metadata["max_candidates"]):
        raise SystemExit("max-candidates exceeds the offline index read padding")
    if args.max_relation_candidates > int(metadata["max_relation_candidates"]):
        raise SystemExit("max-relation-candidates exceeds the offline relation padding")
    if args.max_query_buckets < 1:
        raise SystemExit("max-query-buckets must be positive")
    if args.production_secure:
        if args.ranking_backend != "mpc":
            raise SystemExit(
                "--production-secure requires --ranking-backend mpc; "
                "local-gc-prototype reranks after MP-SPDZ output and is not a distributed pre-reveal GC"
            )
        if args.auto_tighten_max_candidates:
            raise SystemExit(
                "--production-secure rejects --auto-tighten-max-candidates because query-dependent "
                "fanout can leak a degree bound"
            )
        fixed_compact_args = (
            args.fixed_compact_entity_slots,
            args.fixed_compact_relation_slots,
            args.fixed_compact_edge_rows,
            args.fixed_compact_relation_rows,
        )
        if args.compact_probed_benchmark and any(value is None for value in fixed_compact_args):
            raise SystemExit(
                "--production-secure allows compact-probed mode only with all fixed compact bounds: "
                "--fixed-compact-entity-slots, --fixed-compact-relation-slots, "
                "--fixed-compact-edge-rows, --fixed-compact-relation-rows"
            )
    fixed_compact_values = (
        args.fixed_compact_entity_slots,
        args.fixed_compact_relation_slots,
        args.fixed_compact_edge_rows,
        args.fixed_compact_relation_rows,
    )
    if any(value is not None for value in fixed_compact_values) and not args.compact_probed_benchmark:
        raise SystemExit("fixed compact bounds require --compact-probed-benchmark")
    for name, value in (
        ("fixed-compact-entity-slots", args.fixed_compact_entity_slots),
        ("fixed-compact-relation-slots", args.fixed_compact_relation_slots),
        ("fixed-compact-edge-rows", args.fixed_compact_edge_rows),
        ("fixed-compact-relation-rows", args.fixed_compact_relation_rows),
    ):
        if value is not None and value < 1:
            raise SystemExit(f"--{name} must be positive")

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
            bucket_mode=args.semantic_bucket_mode,
            max_query_buckets=args.max_query_buckets,
        )
        normalized_queries.append(normalized)
        base_query_values.append(values)

    manifest = _load_manifest(Path(args.manifest))
    party_ids = [party["party_id"] for party in manifest["parties"]]
    indexes = [read_private_semantic_party_index(index_root / party_id) for party_id in party_ids]
    entity_directory_capacity = int(metadata["entity_directory_capacity"])
    relation_bucket_directory_capacity = int(metadata["relation_bucket_directory_capacity"])
    entity_edge_capacity = max(len(index["entity_edges"]) for index in indexes)
    relation_bucket_edge_capacity = max(len(index["relation_bucket_edges"]) for index in indexes)
    entity_probe_limit = max(index["stats"]["entity_probe_limit"] for index in indexes)
    relation_bucket_probe_limit = max(
        index["stats"]["relation_bucket_probe_limit"] for index in indexes
    )

    query_values = []
    query_lookups = []
    required_max_candidates = 1
    for normalized, values in zip(normalized_queries, base_query_values):
        lookup = normalized.pop("_lookup")
        source_base = entity_directory_slot_limb(
            setup_key,
            "entity-source",
            lookup["direction_1_bit"],
            lookup["source_id"],
            entity_directory_capacity,
        )
        reverse_base = entity_directory_slot_limb(
            setup_key,
            "entity-source",
            lookup["reverse_direction_2_bit"],
            lookup["target_id"],
            entity_directory_capacity,
        )
        source_slots = probe_slots(source_base, entity_directory_capacity, entity_probe_limit)
        reverse_slots = probe_slots(reverse_base, entity_directory_capacity, entity_probe_limit)
        for index in indexes:
            required_max_candidates = max(
                required_max_candidates,
                _entity_directory_count(
                    index,
                    lookup["source_id"],
                    lookup["direction_1_bit"],
                    source_slots,
                ),
            )
            if not normalized.get("type_identity_mode"):
                required_max_candidates = max(
                    required_max_candidates,
                    _entity_directory_count(
                        index,
                        lookup["target_id"],
                        lookup["reverse_direction_2_bit"],
                        reverse_slots,
                    ),
                )
        rel1_slots_by_bucket = []
        for bucket_id in lookup["relation_1_bucket_ids"]:
            rel1_base = relation_bucket_slot_limb(
                setup_key,
                bucket_id,
                relation_bucket_directory_capacity,
            )
            rel1_slots_by_bucket.append(
                probe_slots(rel1_base, relation_bucket_directory_capacity, relation_bucket_probe_limit)
            )
        rel2_slots_by_bucket = []
        for bucket_id in lookup["relation_2_bucket_ids"]:
            rel2_base = relation_bucket_slot_limb(
                setup_key,
                bucket_id,
                relation_bucket_directory_capacity,
            )
            rel2_slots_by_bucket.append(
                probe_slots(rel2_base, relation_bucket_directory_capacity, relation_bucket_probe_limit)
            )
        query_lookups.append(
            {
                "lookup": lookup,
                "source_slots": source_slots,
                "reverse_slots": reverse_slots,
                "rel1_slots_by_bucket": rel1_slots_by_bucket,
                "rel2_slots_by_bucket": rel2_slots_by_bucket,
            }
        )

    if required_max_candidates > args.max_candidates and args.require_full_fanout:
        raise SystemExit(
            "max-candidates is below the selected batch fanout "
            f"({args.max_candidates} < {required_max_candidates}); rebuild/run with a larger value"
        )
    effective_max_candidates = args.max_candidates
    if args.auto_tighten_max_candidates:
        effective_max_candidates = min(args.max_candidates, required_max_candidates)

    compact_benchmark_stats = None
    if args.compact_probed_benchmark:
        compacted_indexes = []
        entity_maps = []
        relation_maps = []
        for index in indexes:
            entity_slots = [
                slot
                for query_lookup in query_lookups
                for slots in (query_lookup["source_slots"], query_lookup["reverse_slots"])
                for slot in slots
            ]
            relation_slots = [
                slot
                for query_lookup in query_lookups
                for slots_by_bucket in (
                    query_lookup["rel1_slots_by_bucket"],
                    query_lookup["rel2_slots_by_bucket"],
                )
                for slots in slots_by_bucket
                for slot in slots
            ]
            compacted, entity_map, relation_map = _compact_party_index_for_probes(
                index,
                entity_slots=entity_slots,
                relation_bucket_slots=relation_slots,
                max_candidates=effective_max_candidates,
                max_relation_candidates=args.max_relation_candidates,
                fixed_entity_slots=args.fixed_compact_entity_slots,
                fixed_relation_slots=args.fixed_compact_relation_slots,
                fixed_entity_edge_rows=args.fixed_compact_edge_rows,
                fixed_relation_edge_rows=args.fixed_compact_relation_rows,
            )
            compacted_indexes.append(compacted)
            entity_maps.append(entity_map)
            relation_maps.append(relation_map)
        indexes = compacted_indexes
        for query_lookup in query_lookups:
            # All parties receive the same compact probe positions because each
            # compact party table is constructed with the same ordered probe list.
            query_lookup["source_slots"] = _remap_slots(query_lookup["source_slots"], entity_maps[0])
            query_lookup["reverse_slots"] = _remap_slots(query_lookup["reverse_slots"], entity_maps[0])
            query_lookup["rel1_slots_by_bucket"] = [
                _remap_slots(slots, relation_maps[0])
                for slots in query_lookup["rel1_slots_by_bucket"]
            ]
            query_lookup["rel2_slots_by_bucket"] = [
                _remap_slots(slots, relation_maps[0])
                for slots in query_lookup["rel2_slots_by_bucket"]
            ]
        compact_benchmark_stats = {
            "original_entity_directory_capacity": entity_directory_capacity,
            "original_entity_edge_capacity": entity_edge_capacity,
            "original_relation_bucket_directory_capacity": relation_bucket_directory_capacity,
            "original_relation_bucket_edge_capacity": relation_bucket_edge_capacity,
        }
        entity_directory_capacity = max(len(index["entity_directory"]) for index in indexes)
        relation_bucket_directory_capacity = max(
            len(index["relation_bucket_directory"]) for index in indexes
        )
        entity_edge_capacity = max(len(index["entity_edges"]) for index in indexes)
        relation_bucket_edge_capacity = max(len(index["relation_bucket_edges"]) for index in indexes)
        compact_benchmark_stats.update(
            {
                "compact_entity_directory_capacity": entity_directory_capacity,
                "compact_entity_edge_capacity": entity_edge_capacity,
                "compact_relation_bucket_directory_capacity": relation_bucket_directory_capacity,
                "compact_relation_bucket_edge_capacity": relation_bucket_edge_capacity,
                "fixed_compact_bounds": {
                    "entity_slots": args.fixed_compact_entity_slots,
                    "relation_slots": args.fixed_compact_relation_slots,
                    "edge_rows": args.fixed_compact_edge_rows,
                    "relation_rows": args.fixed_compact_relation_rows,
                },
            }
        )

    for query_lookup, values in zip(query_lookups, base_query_values):
        lookup = query_lookup["lookup"]
        query_values.extend(values)
        query_values.extend(query_lookup["source_slots"])
        query_values.extend(query_lookup["reverse_slots"])
        for slots in query_lookup["rel1_slots_by_bucket"]:
            query_values.extend(slots)
        for slots in query_lookup["rel2_slots_by_bucket"]:
            query_values.extend(slots)

    instance_dir = Path(args.instance_dir)
    instance_dir.mkdir(parents=True, exist_ok=True)
    template = (
        _repo_root()
        / "mpspdz_client_excluded"
        / "programs"
        / "secure_kg_twohop_source_oram_limb_private_semantic_batch_topk.mpc.template"
    ).read_text()
    circuit_profile = {
        "data_parties": len(indexes),
        "num_queries": len(rows),
        "entity_directory_capacity": entity_directory_capacity,
        "entity_edge_capacity": entity_edge_capacity,
        "relation_bucket_directory_capacity": relation_bucket_directory_capacity,
        "relation_bucket_edge_capacity": relation_bucket_edge_capacity,
        "entity_probe_limit": entity_probe_limit,
        "relation_bucket_probe_limit": relation_bucket_probe_limit,
        "max_candidates": effective_max_candidates,
        "max_relation_candidates": args.max_relation_candidates,
        "max_query_buckets": args.max_query_buckets,
        "top_k": args.topk,
        "entity_edge_index_bits": _bits_for(entity_edge_capacity),
        "candidate_count_bits": _bits_for(entity_edge_capacity),
        "relation_bucket_edge_index_bits": _bits_for(relation_bucket_edge_capacity),
        "relation_candidate_count_bits": _bits_for(relation_bucket_edge_capacity),
    }
    profile_hash = hashlib.sha256(
        json.dumps(circuit_profile, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    program = template.format(
        **circuit_profile,
    )
    program_name = f"secure_kg_twohop_source_oram_limb_private_semantic_batch_topk_{profile_hash}"
    (instance_dir / f"{program_name}.mpc").write_text(program)
    player_data = instance_dir / "Player-Data"
    query_path = player_data / "Input-P0-0"
    _write_input_file(query_path, query_values)
    query_path.chmod(0o600)

    for player, index in enumerate(indexes, start=1):
        entity_edges = _pad_rows(index["entity_edges"], entity_edge_capacity, 14)
        relation_bucket_edges = _pad_rows(index["relation_bucket_edges"], relation_bucket_edge_capacity, 5)
        values = [
            value
            for table in (
                index["entity_directory"],
                entity_edges,
                index["relation_bucket_directory"],
                relation_bucket_edges,
            )
            for row in table
            for value in row
        ]
        input_path = player_data / f"Input-P{player}-0"
        _write_input_file(input_path, values)
        input_path.chmod(0o600)

    receipt = {
        "format": "fedkg-mpspdz-source-oram-limb-private-semantic-batch-v1",
        "id_limbs": ID_LIMBS,
        "id_effective_bits": ID_EFFECTIVE_BITS,
        "index_dir": str(index_root.resolve()),
        "data_parties": [{"party_id": party_id} for party_id in party_ids],
        "queries": normalized_queries,
        "max_candidates_requested": args.max_candidates,
        "max_candidates_effective": effective_max_candidates,
        "required_max_candidates_for_batch": required_max_candidates,
        "candidate_truncation_possible": required_max_candidates > effective_max_candidates,
        "compact_probed_benchmark": args.compact_probed_benchmark,
        "compact_benchmark_stats": compact_benchmark_stats,
        "circuit_profile": circuit_profile,
        "circuit_profile_hash": profile_hash,
        "mp_spdz_program": program_name,
        "mp_spdz_protocol": args.mp_spdz_protocol,
        "security_note": (
            "Query relation bucket IDs are secret inputs. MP-SPDZ privately resolves "
            "all padded query buckets to relation candidates and filters entity-only "
            "edge blocks in MPC."
        ),
    }
    receipt_path = instance_dir / "query_gateway_receipt.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2))
    receipt_path.chmod(0o600)

    print(f"Prepared {len(rows)} private semantic bucket ORAM queries.", flush=True)
    started = time.perf_counter()
    run_env = os.environ.copy()
    run_env["MP_SPDZ_HOME"] = args.mp_spdz_home
    run_env["MP_SPDZ_PROTOCOL"] = args.mp_spdz_protocol
    bytecode_dir = Path(args.mp_spdz_home) / "Programs" / "Bytecode"
    compile_skipped = False
    if args.skip_compile_if_present and any(bytecode_dir.glob(f"{program_name}*.bc")):
        run_env["MP_SPDZ_SKIP_COMPILE"] = "1"
        compile_skipped = True
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
            "private_semantic_oram_correct": is_correct,
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
        "mp_spdz_protocol": args.mp_spdz_protocol,
        "output": str(output_path),
        "instance_dir": str(instance_dir),
        "optimized_path": "source-only-oram-128-bit-private-semantic-bucket",
        "id_effective_bits": ID_EFFECTIVE_BITS,
        "ranking_backend": args.ranking_backend,
        "max_query_buckets": args.max_query_buckets,
        "max_candidates_requested": args.max_candidates,
        "max_candidates_effective": effective_max_candidates,
        "required_max_candidates_for_batch": required_max_candidates,
        "auto_tighten_max_candidates": args.auto_tighten_max_candidates,
        "candidate_truncation_possible": required_max_candidates > effective_max_candidates,
        "production_secure": args.production_secure,
        "compact_probed_benchmark": args.compact_probed_benchmark,
        "compact_benchmark_stats": compact_benchmark_stats,
        "circuit_profile_hash": profile_hash,
        "mp_spdz_program": program_name,
        "compile_skipped": compile_skipped,
        "ranking_security_note": (
            "MP-SPDZ computes support aggregation and top-k before evidence reveal."
            if args.ranking_backend == "mpc"
            else "local-gc-prototype reranks only paths already selected/revealed by MP-SPDZ."
        ),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
