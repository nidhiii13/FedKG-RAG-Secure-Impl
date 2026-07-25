#!/usr/bin/env python3
"""Run SealPIR-style private bucket retrieval over encoded KG bucket records."""

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
from src.pir.sealpir_backend import SealPirCliBackend, SealPirDatabaseConfig, SealPirBackendError
from src.pir.xor_pir import FixedRecordDatabase
from src.semantic.relation_buckets import relation_bucket_tokens


UNKNOWN_PREFIX = "UNKNOWN"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run native SealPIR bucket lookup plus bounded join.")
    parser.add_argument("--index-dir", required=True, type=Path)
    parser.add_argument("--edge", action="append", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--semantic-bucket-mode", choices=("alias", "lsh", "hybrid"), default="hybrid")
    parser.add_argument("--max-query-buckets", type=int, default=1)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--sealpir-cli", type=Path, default=Path("tools/sealpir_cli/fedkg-sealpir-cli"))
    parser.add_argument("--timeout", type=float, default=120.0)
    return parser.parse_args()


def parse_edges(values: list[str]) -> list[tuple[str, str, str]]:
    edges = []
    for value in values:
        parts = tuple(part.strip() for part in value.split("|"))
        if len(parts) != 3 or any(not part for part in parts):
            raise SystemExit(f"invalid --edge value: {value!r}")
        edges.append(parts)
    if len(edges) not in (1, 2):
        raise SystemExit("this SealPIR runner supports one-hop or two-hop path queries")
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
    config = SealPirDatabaseConfig(
        database_size=database.size,
        record_size=database.record_size,
        label=f"fedkg-sealpir:{args.index_dir}",
    )
    backend = SealPirCliBackend(args.sealpir_cli, timeout_seconds=args.timeout)
    load_seconds = time.perf_counter() - load_start

    try:
        setup_start = time.perf_counter()
        server_state = backend.setup(database.records, config)
        setup_seconds = time.perf_counter() - setup_start

        retrieve_start = time.perf_counter()
        retrieved_by_edge = [
            _retrieve_edge_records(edge, ids, args, directory, backend, server_state, config)
            for edge in edges
        ]
        retrieve_seconds = time.perf_counter() - retrieve_start
    except SealPirBackendError as exc:
        raise SystemExit(str(exc)) from exc

    join_start = time.perf_counter()
    candidates = _join_paths(retrieved_by_edge, args.topk)
    join_seconds = time.perf_counter() - join_start

    payload = {
        "query": edges,
        "pir_backend": {
            "type": "native-sealpir-lattice-pir-adapter",
            "database_size": database.size,
            "record_size": database.record_size,
            "security_model": "computational PIR; server should not learn requested bucket index",
        },
        "candidate_count": len(candidates),
        "selected_encoded_paths": candidates[: args.topk],
        "post_retrieval_requirement": "feed bounded candidates into Prio/MPC aggregation and GC/MPC top-k",
        "timing_seconds": {
            "load_index": round(load_seconds, 6),
            "sealpir_setup": round(setup_seconds, 6),
            "sealpir_retrieval": round(retrieve_seconds, 6),
            "bounded_join": round(join_seconds, 6),
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
    backend: SealPirCliBackend,
    server_state: bytes,
    config: SealPirDatabaseConfig,
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
        raise SystemExit("each SealPIR edge must bind either source or target")

    out: set[tuple[str, str, str]] = set()
    for bucket in relation_buckets:
        key = f"{direction}:{entity_id}:{bucket}"
        index = directory.get(key)
        if index is None:
            continue
        query = backend.query(index, config)
        answer = backend.answer(server_state, query.request)
        record = json.loads(backend.decode(query.client_state, answer).decode("utf-8"))
        for encoded_edge in record["edges"]:
            out.add(tuple(encoded_edge))
    return sorted(out)


def _join_paths(
    retrieved_by_edge: list[list[tuple[str, str, str]]],
    topk: int,
) -> list[dict[str, object]]:
    if len(retrieved_by_edge) == 1:
        return [{"score": 1.0, "edges": [list(edge)]} for edge in retrieved_by_edge[0][:topk]]
    left_edges, right_edges = retrieved_by_edge
    candidates = []
    for left in left_edges:
        for right in right_edges:
            if left[2] == right[0]:
                candidates.append({"score": 1.0, "edges": [list(left), list(right)]})
    candidates.sort(key=lambda item: json.dumps(item["edges"], sort_keys=True))
    return candidates


def _is_unknown(value: str) -> bool:
    return value.strip().upper().startswith(UNKNOWN_PREFIX)


if __name__ == "__main__":
    raise SystemExit(main())
