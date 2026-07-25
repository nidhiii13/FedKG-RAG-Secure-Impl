#!/usr/bin/env python3
"""Build a replicated encoded bucket database for XOR PIR lookup."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.crypto.hmac_ids import HmacIdProvider
from src.common.normalization import normalize_text
from src.party.secure_index import SecurePartyIndex
from src.pir.xor_pir import FixedRecordDatabase
from src.runtime.simgrag_loader import load_manifest, load_party_payload
from src.semantic.relation_buckets import relation_bucket_tokens


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build fixed-record PIR bucket index from MetaQA parties.")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--semantic-bucket-mode", choices=("alias", "lsh", "hybrid"), default="hybrid")
    parser.add_argument(
        "--relation",
        action="append",
        help="Optional plaintext relation label to include; repeat to build a smaller benchmark index.",
    )
    parser.add_argument(
        "--entity",
        action="append",
        help=(
            "Optional plaintext entity label; include edges touching this entity. "
            "This is intended for smoke tests, not production privacy benchmarks."
        ),
    )
    parser.add_argument("--max-edges-per-record", type=int, default=64)
    parser.add_argument("--record-size", type=int, default=32768)
    parser.add_argument(
        "--auto-record-size",
        action="store_true",
        help="Increase record-size to the next power of two when packed rows exceed --record-size.",
    )
    parser.add_argument(
        "--records-per-pir-row",
        type=int,
        default=1,
        help="Pack this many logical bucket records into one PIR database row.",
    )
    parser.add_argument(
        "--compact-ids",
        action="store_true",
        help="Store small integer entity/relation ids in PIR rows and write id_map.json for decoding.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ids = HmacIdProvider.from_env(args.key_env)
    manifest = load_manifest(args.manifest)
    allowed_relations = {normalize_text(value) for value in args.relation or []}
    allowed_entities = {normalize_text(value) for value in args.entity or []}

    buckets: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    display_relations: dict[str, str] = {}
    display_entities: dict[str, str] = {}
    for party in manifest.parties:
        graph, types = load_party_payload(party.data_path)
        index = SecurePartyIndex.from_plain_graph(party.party_id, graph, types, ids)
        display_relations.update(index.display_relations)
        display_entities.update(index.display_entities)
        relation_bucket_cache = {
            relation_id: relation_bucket_tokens(
                ids,
                display,
                mode=args.semantic_bucket_mode,
            )
            for relation_id, display in index.display_relations.items()
            if not allowed_relations or normalize_text(display) in allowed_relations
        }
        for source_id, rels in index.adjacency.items():
            for relation_id, target_ids in rels.items():
                if relation_id not in relation_bucket_cache:
                    continue
                for bucket_token in relation_bucket_cache.get(relation_id, []):
                    forward_key = _bucket_key("forward", source_id, bucket_token)
                    for target_id in target_ids:
                        if allowed_entities and not (
                            normalize_text(index.display_entities.get(source_id, source_id)) in allowed_entities
                            or normalize_text(index.display_entities.get(target_id, target_id)) in allowed_entities
                        ):
                            continue
                        buckets[forward_key].append((source_id, relation_id, target_id))
                        reverse_key = _bucket_key("reverse", target_id, bucket_token)
                        buckets[reverse_key].append((source_id, relation_id, target_id))

    logical_records = []
    directory = {}
    overflow = {}
    for key in sorted(buckets):
        edges = sorted(set(buckets[key]))
        if len(edges) > args.max_edges_per_record:
            overflow[key] = len(edges)
            edges = edges[: args.max_edges_per_record]
        logical_records.append({"key": key, "edges": [list(edge) for edge in edges]})

    payload_records = logical_records
    id_map = None
    if args.compact_ids:
        all_ids = sorted({value for record in logical_records for edge in record["edges"] for value in edge})
        hmac_to_compact = {value: index + 1 for index, value in enumerate(all_ids)}
        id_map = {
            "encoding": "compact-int-to-hmac-v1",
            "int_to_hmac": {str(index): value for value, index in hmac_to_compact.items()},
        }
        payload_records = [
            {
                "edges": [
                    [hmac_to_compact[source], hmac_to_compact[relation], hmac_to_compact[target]]
                    for source, relation, target in record["edges"]
                ]
            }
            for record in logical_records
        ]

    if args.records_per_pir_row < 1:
        raise SystemExit("--records-per-pir-row must be at least 1")
    if args.records_per_pir_row == 1:
        records = payload_records
        directory = {record["key"]: index for index, record in enumerate(logical_records)}
        record_format = "single-compact-record" if args.compact_ids else "single-json-record"
    else:
        records = []
        directory = {}
        for start in range(0, len(logical_records), args.records_per_pir_row):
            chunk = logical_records[start : start + args.records_per_pir_row]
            payload_chunk = payload_records[start : start + args.records_per_pir_row]
            row_index = len(records)
            for offset, record in enumerate(chunk):
                directory[record["key"]] = {
                    "row": row_index,
                    "offset": offset,
                }
            records.append({"records": payload_chunk})
        record_format = "packed-compact-records" if args.compact_ids else "packed-json-records"

    max_payload_size = max(
        (
            len(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            for record in records
        ),
        default=0,
    )
    record_size = args.record_size
    if max_payload_size > record_size:
        if not args.auto_record_size:
            raise SystemExit(
                f"largest packed record has {max_payload_size} bytes but --record-size is {record_size}; "
                "increase --record-size or pass --auto-record-size"
            )
        record_size = _next_power_of_two(max_payload_size)

    database = FixedRecordDatabase.from_json_records(records, record_size)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "records.jsonl").write_text(
        "\n".join(json.dumps(record, sort_keys=True, separators=(",", ":")) for record in records) + "\n"
    )
    (args.output_dir / "directory.json").write_text(json.dumps(directory, indent=2, sort_keys=True) + "\n")
    if id_map is not None:
        (args.output_dir / "id_map.json").write_text(json.dumps(id_map, indent=2, sort_keys=True) + "\n")
    (args.output_dir / "metadata.json").write_text(
        json.dumps(
            {
                "manifest": str(args.manifest),
                "semantic_bucket_mode": args.semantic_bucket_mode,
                "relation_filter": sorted(allowed_relations),
                "entity_filter": sorted(allowed_entities),
                "record_size": record_size,
                "requested_record_size": args.record_size,
                "max_payload_size": max_payload_size,
                "record_format": record_format,
                "compact_ids": args.compact_ids,
                "records_per_pir_row": args.records_per_pir_row,
                "logical_record_count": len(logical_records),
                "database_size": database.size,
                "max_edges_per_record": args.max_edges_per_record,
                "overflow_bucket_count": len(overflow),
                "overflow_examples": dict(list(overflow.items())[:10]),
                "display_entity_count": len(display_entities),
                "display_relation_count": len(display_relations),
                "security_model": (
                    "replicated N-server XOR PIR; query index hidden unless all PIR servers collude"
                ),
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
                "database_size": database.size,
                "record_size": record_size,
                "max_payload_size": max_payload_size,
                "overflow_bucket_count": len(overflow),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _bucket_key(direction: str, entity_id: str, relation_bucket_token: str) -> str:
    return f"{direction}:{entity_id}:{relation_bucket_token}"


def _next_power_of_two(value: int) -> int:
    if value <= 1:
        return 1
    return 1 << (value - 1).bit_length()


if __name__ == "__main__":
    raise SystemExit(main())
