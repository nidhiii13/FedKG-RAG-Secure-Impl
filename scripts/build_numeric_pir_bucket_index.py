#!/usr/bin/env python3
"""Build fixed numeric PIR bucket records for MPC consumption.

Record layout:
    [edge_count, source_1, relation_1, target_1, ..., source_M, relation_M, target_M]

Packed PIR row layout:
    logical_record_0 || logical_record_1 || ... || logical_record_{page_capacity - 1}

All entity/relation values are compact integer aliases for HMAC IDs. The compact
IDs are dictionary-assigned, not hashed, so they do not introduce an additional
collision layer. Values must fit the configured Lattigo BGV plaintext modulus.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.common.normalization import normalize_text
from src.crypto.hmac_ids import HmacIdProvider
from src.party.secure_index import SecurePartyIndex
from src.runtime.simgrag_loader import load_manifest, load_party_payload
from src.semantic.relation_buckets import relation_bucket_tokens

DEFAULT_PLAINTEXT_MODULUS = 65537


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build numeric PIR bucket index for MPC handoff.")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--semantic-bucket-mode", choices=("alias", "lsh", "hybrid"), default="alias")
    parser.add_argument("--relation", action="append")
    parser.add_argument("--entity", action="append")
    parser.add_argument("--max-edges-per-record", type=int, default=8)
    parser.add_argument(
        "--page-capacity",
        type=int,
        default=256,
        help="Number of logical bucket records packed into one physical PIR row.",
    )
    parser.add_argument(
        "--shard-size",
        type=int,
        default=8192,
        help="Maximum PIR rows per shard, including the dummy row.",
    )
    parser.add_argument(
        "--plaintext-modulus",
        type=int,
        default=DEFAULT_PLAINTEXT_MODULUS,
        help="BGV plaintext modulus and additive sharing modulus. Use a larger batching prime for larger datasets.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.max_edges_per_record < 1:
        raise SystemExit("--max-edges-per-record must be positive")
    if args.shard_size < 2:
        raise SystemExit("--shard-size must be at least 2")
    if args.page_capacity < 1:
        raise SystemExit("--page-capacity must be positive")
    if args.plaintext_modulus < 2:
        raise SystemExit("--plaintext-modulus must be at least 2")
    ids = HmacIdProvider.from_env(args.key_env)
    manifest = load_manifest(args.manifest)
    allowed_relations = {normalize_text(value) for value in args.relation or []}
    allowed_entities = {normalize_text(value) for value in args.entity or []}

    buckets: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    hmac_display: dict[str, str] = {}
    for party in manifest.parties:
        graph, types = load_party_payload(party.data_path)
        index = SecurePartyIndex.from_plain_graph(party.party_id, graph, types, ids)
        hmac_display.update(index.display_entities)
        hmac_display.update(index.display_relations)
        relation_bucket_cache = {
            relation_id: relation_bucket_tokens(ids, display, mode=args.semantic_bucket_mode)
            for relation_id, display in index.display_relations.items()
            if not allowed_relations or normalize_text(display) in allowed_relations
        }
        for source_id, rels in index.adjacency.items():
            for relation_id, target_ids in rels.items():
                bucket_tokens = relation_bucket_cache.get(relation_id)
                if not bucket_tokens:
                    continue
                for target_id in target_ids:
                    if allowed_entities and not (
                        normalize_text(index.display_entities.get(source_id, source_id)) in allowed_entities
                        or normalize_text(index.display_entities.get(target_id, target_id)) in allowed_entities
                    ):
                        continue
                    edge = (source_id, relation_id, target_id)
                    for bucket_token in bucket_tokens:
                        buckets[f"forward:{source_id}:{bucket_token}"].append(edge)
                        buckets[f"reverse:{target_id}:{bucket_token}"].append(edge)

    all_ids = sorted({value for edges in buckets.values() for edge in edges for value in edge})
    if len(all_ids) + 1 >= args.plaintext_modulus:
        raise SystemExit(
            f"compact id count {len(all_ids)} exceeds plaintext modulus capacity {args.plaintext_modulus}"
        )
    hmac_to_int = {value: index + 1 for index, value in enumerate(all_ids)}
    int_to_hmac = {str(value): key for key, value in hmac_to_int.items()}

    logical_records: list[list[int]] = []
    logical_keys: list[str] = []
    overflow: dict[str, int] = {}
    evidence_vault: dict[str, list[list[str]]] = {}
    logical_record_size = 1 + (args.max_edges_per_record * 3)
    record_size = logical_record_size * args.page_capacity
    if record_size > 8192:
        raise SystemExit(
            f"packed record_size {record_size} exceeds current Lattigo vector slot capacity 8192; "
            "reduce --page-capacity or --max-edges-per-record"
        )
    for key in sorted(buckets):
        edges = sorted(set(buckets[key]))
        if len(edges) > args.max_edges_per_record:
            overflow[key] = len(edges)
            edges = edges[: args.max_edges_per_record]
        row = [len(edges)]
        for source_id, relation_id, target_id in edges:
            numeric_edge = [hmac_to_int[source_id], hmac_to_int[relation_id], hmac_to_int[target_id]]
            row.extend(numeric_edge)
            evidence_vault["|".join(str(value) for value in numeric_edge)] = [
                [
                    hmac_display.get(source_id, source_id),
                    hmac_display.get(relation_id, relation_id),
                    hmac_display.get(target_id, target_id),
                ]
            ]
        row.extend([0] * (logical_record_size - len(row)))
        logical_keys.append(key)
        logical_records.append(row)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    directory, shard_metadata = _write_shards(
        args.output_dir,
        logical_keys,
        logical_records,
        record_size,
        args.shard_size,
    )
    (args.output_dir / "directory.json").write_text(json.dumps(directory, indent=2, sort_keys=True) + "\n")
    (args.output_dir / "id_map.json").write_text(
        json.dumps(
            {
                "encoding": "compact-int-to-hmac-v1",
                "int_to_hmac": int_to_hmac,
                "int_to_display": {
                    str(hmac_to_int[hmac_id]): display
                    for hmac_id, display in hmac_display.items()
                    if hmac_id in hmac_to_int
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    (args.output_dir / "evidence_vault.json").write_text(json.dumps(evidence_vault, indent=2, sort_keys=True) + "\n")
    (args.output_dir / "metadata.json").write_text(
        json.dumps(
            {
                "manifest": str(args.manifest),
                "semantic_bucket_mode": args.semantic_bucket_mode,
                "relation_filter": sorted(allowed_relations),
                "entity_filter": sorted(allowed_entities),
                "record_format": "json-u64-array",
                "record_size": record_size,
                "logical_record_size": logical_record_size,
                "page_capacity": args.page_capacity,
                "database_size": len(logical_records),
                "physical_database_size": sum(int(shard["rows"]) - 1 for shard in shard_metadata),
                "partitioned": True,
                "shard_size": args.shard_size,
                "shards": shard_metadata,
                "max_edges_per_record": args.max_edges_per_record,
                "overflow_bucket_count": len(overflow),
                "overflow_examples": dict(list(overflow.items())[:10]),
                "compact_id_count": len(all_ids),
                "plaintext_modulus": args.plaintext_modulus,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "database_size": len(logical_records),
                "shard_count": len(shard_metadata),
                "record_size": record_size,
                "logical_record_size": logical_record_size,
                "page_capacity": args.page_capacity,
                "physical_database_size": sum(int(shard["rows"]) - 1 for shard in shard_metadata),
                "overflow_bucket_count": len(overflow),
                "compact_id_count": len(all_ids),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _write_shards(
    output_dir: Path,
    keys: list[str],
    records: list[list[int]],
    record_size: int,
    shard_size: int,
) -> tuple[dict[str, dict[str, int]], list[dict[str, int | str]]]:
    shard_dir = output_dir / "shards"
    shard_dir.mkdir(parents=True, exist_ok=True)
    logical_record_size = len(records[0]) if records else record_size
    if record_size % logical_record_size != 0:
        raise ValueError("record_size must be a multiple of logical_record_size")
    page_capacity = record_size // logical_record_size
    dummy_logical = [0] * logical_record_size
    dummy = [0] * record_size
    directory: dict[str, dict[str, int]] = {}
    metadata: list[dict[str, int | str]] = []
    payload_capacity = shard_size - 1
    pages: list[list[int]] = []
    page_keys: list[list[str]] = []
    for start in range(0, len(records), page_capacity):
        logical_page = records[start : start + page_capacity]
        key_page = keys[start : start + page_capacity]
        while len(logical_page) < page_capacity:
            logical_page.append(dummy_logical)
        page = [value for logical_record in logical_page for value in logical_record]
        pages.append(page)
        page_keys.append(key_page)

    for shard_index, start in enumerate(range(0, len(pages), payload_capacity)):
        chunk_records = pages[start : start + payload_capacity]
        chunk_keys = page_keys[start : start + payload_capacity]
        shard_records = [dummy] + chunk_records
        shard_path = shard_dir / f"shard_{shard_index:05d}.jsonl"
        shard_path.write_text(
            "\n".join(json.dumps(row, separators=(",", ":")) for row in shard_records) + "\n"
        )
        for row_offset, key_page in enumerate(chunk_keys, start=1):
            for page_offset, key in enumerate(key_page):
                directory[key] = {"shard": shard_index, "row": row_offset, "offset": page_offset}
        metadata.append(
            {
                "shard": shard_index,
                "path": str(shard_path.relative_to(output_dir)),
                "rows": len(shard_records),
                "dummy_row": 0,
                "page_capacity": page_capacity,
            }
        )
    if not records:
        shard_path = shard_dir / "shard_00000.jsonl"
        shard_path.write_text(json.dumps(dummy, separators=(",", ":")) + "\n")
        metadata.append({"shard": 0, "path": str(shard_path.relative_to(output_dir)), "rows": 1, "dummy_row": 0})
    return directory, metadata


if __name__ == "__main__":
    raise SystemExit(main())
