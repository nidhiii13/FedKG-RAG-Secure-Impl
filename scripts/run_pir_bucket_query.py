#!/usr/bin/env python3
"""Run N-server XOR PIR over encoded bucket records and bounded path joining."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.crypto.hmac_ids import HmacIdProvider
from src.pir.xor_pir import FixedRecordDatabase, XorPirClient, XorPirServer
from src.semantic.relation_buckets import relation_bucket_tokens


UNKNOWN_PREFIX = "UNKNOWN"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run PIR bucket retrieval over encoded KG records.")
    parser.add_argument("--index-dir", required=True, type=Path)
    parser.add_argument("--edge", action="append", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--semantic-bucket-mode", choices=("alias", "lsh", "hybrid"), default="hybrid")
    parser.add_argument("--pir-servers", type=int, default=3)
    parser.add_argument("--max-query-buckets", type=int, default=0)
    parser.add_argument("--allow-large-pir-scan", action="store_true")
    parser.add_argument("--topk", type=int, default=3)
    return parser.parse_args()


def parse_edges(values: list[str]) -> list[tuple[str, str, str]]:
    edges = []
    for value in values:
        parts = tuple(part.strip() for part in value.split("|"))
        if len(parts) != 3 or any(not part for part in parts):
            raise SystemExit(f"invalid --edge value: {value!r}")
        edges.append(parts)
    if len(edges) not in (1, 2):
        raise SystemExit("this PIR smoke runner supports one-hop or two-hop path queries")
    return edges  # type: ignore[return-value]


def main() -> int:
    args = parse_args()
    total_start = time.perf_counter()
    ids = HmacIdProvider.from_env(args.key_env)
    edges = parse_edges(args.edge)

    load_start = time.perf_counter()
    metadata = json.loads((args.index_dir / "metadata.json").read_text())
    directory = json.loads((args.index_dir / "directory.json").read_text())
    payload_records = [
        json.loads(line)
        for line in (args.index_dir / "records.jsonl").read_text().splitlines()
        if line.strip()
    ]
    database = FixedRecordDatabase.from_json_records(
        payload_records,
        record_size=int(metadata["record_size"]),
    )
    servers = [XorPirServer(database) for _ in range(args.pir_servers)]
    client = XorPirClient(args.pir_servers)
    load_seconds = time.perf_counter() - load_start

    retrieve_start = time.perf_counter()
    request_count = _estimate_request_count(edges, ids, args, directory)
    estimated_scan_bytes = request_count * args.pir_servers * database.size * database.record_size
    if estimated_scan_bytes > 2_000_000_000 and not args.allow_large_pir_scan:
        raise SystemExit(
            "refusing large XOR-PIR scan: "
            f"{estimated_scan_bytes / 1_000_000_000:.2f} GB estimated. "
            "Use a smaller benchmark index or pass --allow-large-pir-scan."
        )
    retrieved_by_edge = [_retrieve_edge_records(edge, ids, args, directory, client, servers) for edge in edges]
    retrieve_seconds = time.perf_counter() - retrieve_start

    join_start = time.perf_counter()
    candidates = _join_paths(retrieved_by_edge, args.topk)
    join_seconds = time.perf_counter() - join_start

    payload = {
        "query": edges,
        "pir_backend": {
            "type": "replicated-n-server-xor-pir",
            "server_count": args.pir_servers,
            "database_size": database.size,
            "record_size": database.record_size,
            "request_count": request_count,
            "estimated_scan_gb": round(estimated_scan_bytes / 1_000_000_000, 6),
            "security_model": "query index is hidden unless all PIR servers collude",
        },
        "candidate_count": len(candidates),
        "selected_encoded_paths": candidates[: args.topk],
        "timing_seconds": {
            "load_index": round(load_seconds, 6),
            "pir_retrieval": round(retrieve_seconds, 6),
            "bounded_join_and_topk": round(join_seconds, 6),
            "total": round(time.perf_counter() - total_start, 6),
        },
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    return 0


def _retrieve_edge_records(
    edge: tuple[str, str, str],
    ids: HmacIdProvider,
    args: argparse.Namespace,
    directory: dict[str, int],
    client: XorPirClient,
    servers: list[XorPirServer],
) -> list[tuple[str, str, str]]:
    source, relation, target = edge
    relation_buckets = relation_bucket_tokens(ids, relation, mode=args.semantic_bucket_mode)
    if args.max_query_buckets > 0:
        relation_buckets = relation_buckets[: args.max_query_buckets]
    if not _is_unknown(source):
        direction = "forward"
        entity_id = ids.entity_id(source)
    elif not _is_unknown(target):
        direction = "reverse"
        entity_id = ids.entity_id(target)
    else:
        raise SystemExit("each PIR edge must bind either source or target")

    out: set[tuple[str, str, str]] = set()
    for bucket in relation_buckets:
        key = f"{direction}:{entity_id}:{bucket}"
        index = directory.get(key)
        if index is None:
            continue
        query = client.create_query(index, servers[0].database.size)
        answers = [
            server.answer(vector)
            for server, vector in zip(servers, query.server_vectors)
        ]
        record = json.loads(client.recover(answers).decode("utf-8"))
        for encoded_edge in record["edges"]:
            out.add(tuple(encoded_edge))
    return sorted(out)


def _estimate_request_count(
    edges: list[tuple[str, str, str]],
    ids: HmacIdProvider,
    args: argparse.Namespace,
    directory: dict[str, int],
) -> int:
    count = 0
    for source, relation, target in edges:
        relation_buckets = relation_bucket_tokens(ids, relation, mode=args.semantic_bucket_mode)
        if args.max_query_buckets > 0:
            relation_buckets = relation_buckets[: args.max_query_buckets]
        if not _is_unknown(source):
            direction = "forward"
            entity_id = ids.entity_id(source)
        elif not _is_unknown(target):
            direction = "reverse"
            entity_id = ids.entity_id(target)
        else:
            continue
        for bucket in relation_buckets:
            if f"{direction}:{entity_id}:{bucket}" in directory:
                count += 1
    return count


def _join_paths(
    retrieved_by_edge: list[list[tuple[str, str, str]]],
    topk: int,
) -> list[dict[str, object]]:
    if len(retrieved_by_edge) == 1:
        return [
            {"score": 1.0, "edges": [list(edge)]}
            for edge in retrieved_by_edge[0][:topk]
        ]
    left_edges, right_edges = retrieved_by_edge
    candidates = []
    for left in left_edges:
        for right in right_edges:
            if left[2] != right[0]:
                continue
            candidates.append({"score": 1.0, "edges": [list(left), list(right)]})
    candidates.sort(key=lambda item: json.dumps(item["edges"], sort_keys=True))
    return candidates


def _is_unknown(value: str) -> bool:
    return value.strip().upper().startswith(UNKNOWN_PREFIX)


if __name__ == "__main__":
    raise SystemExit(main())
