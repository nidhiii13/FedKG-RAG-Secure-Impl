#!/usr/bin/env python3
"""Run real SealPIR roundtrip bucket retrieval via the native wrapper."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.crypto.hmac_ids import HmacIdProvider
from src.semantic.relation_buckets import relation_bucket_tokens

UNKNOWN_PREFIX = "UNKNOWN"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SealPIR roundtrip retrieval over encoded buckets.")
    parser.add_argument("--index-dir", required=True, type=Path)
    parser.add_argument("--edge", action="append", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--semantic-bucket-mode", choices=("alias", "lsh", "hybrid"), default="alias")
    parser.add_argument("--max-query-buckets", type=int, default=1)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument(
        "--sealpir-roundtrip",
        type=Path,
        default=Path("build/fedkg-sealpir-cli/fedkg-sealpir-roundtrip"),
    )
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--poly-modulus-degree", type=int, default=4096)
    parser.add_argument("--logt", type=int, default=20)
    parser.add_argument("--recursion", type=int, default=2)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    total_start = time.perf_counter()
    ids = HmacIdProvider.from_env(args.key_env)
    edges = _parse_edges(args.edge)

    load_start = time.perf_counter()
    metadata = json.loads((args.index_dir / "metadata.json").read_text())
    directory = json.loads((args.index_dir / "directory.json").read_text())
    records_path = args.index_dir / "records.jsonl"
    load_seconds = time.perf_counter() - load_start

    retrieve_start = time.perf_counter()
    retrieved_by_edge = [
        _retrieve_edge_records(edge, ids, args, directory, records_path, int(metadata["record_size"]))
        for edge in edges
    ]
    retrieve_seconds = time.perf_counter() - retrieve_start

    join_start = time.perf_counter()
    candidates = _join_paths(retrieved_by_edge, args.topk)
    join_seconds = time.perf_counter() - join_start

    payload = {
        "query": edges,
        "pir_backend": {
            "type": "sealpir-native-roundtrip",
            "database_size": metadata["database_size"],
            "record_size": metadata["record_size"],
            "semantic_bucket_mode": metadata.get("semantic_bucket_mode"),
            "relation_filter": metadata.get("relation_filter", []),
            "security_model": "computational single-server PIR for hidden bucket index",
            "roundtrip_note": "setup/query/answer/decode are executed in one local native process for validation",
        },
        "candidate_count": len(candidates),
        "selected_encoded_paths": candidates[: args.topk],
        "post_retrieval_requirement": "feed bounded candidates into Prio/MPC aggregation and GC/MPC top-k",
        "timing_seconds": {
            "load_index_metadata": round(load_seconds, 6),
            "sealpir_roundtrip_retrieval": round(retrieve_seconds, 6),
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
    records_path: Path,
    record_size: int,
) -> list[tuple[str, str, str]]:
    source, relation, target = edge
    buckets = relation_bucket_tokens(ids, relation, mode=args.semantic_bucket_mode)
    if args.max_query_buckets > 0:
        buckets = buckets[: args.max_query_buckets]
    if not _is_unknown(source):
        direction = "forward"
        entity_id = ids.entity_id(source)
    elif not _is_unknown(target):
        direction = "reverse"
        entity_id = ids.entity_id(target)
    else:
        raise SystemExit("each SealPIR edge must bind either source or target")

    out: set[tuple[str, str, str]] = set()
    for bucket in buckets:
        db_index = directory.get(f"{direction}:{entity_id}:{bucket}")
        if db_index is None:
            continue
        record = _sealpir_roundtrip(args, records_path, db_index, record_size)
        for encoded_edge in record["edges"]:
            out.add(tuple(encoded_edge))
    return sorted(out)


def _sealpir_roundtrip(
    args: argparse.Namespace,
    records_path: Path,
    db_index: int,
    record_size: int,
) -> dict[str, object]:
    command = [
        str(args.sealpir_roundtrip),
        "--records-jsonl",
        str(records_path),
        "--index",
        str(db_index),
        "--record-size",
        str(record_size),
        "--poly-modulus-degree",
        str(args.poly_modulus_degree),
        "--logt",
        str(args.logt),
        "--recursion",
        str(args.recursion),
    ]
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=args.timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.stderr.strip() or "SealPIR roundtrip failed")
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise SystemExit("SealPIR roundtrip produced no output")
    return json.loads(lines[-1])["record_json"]


def _join_paths(
    retrieved_by_edge: list[list[tuple[str, str, str]]],
    topk: int,
) -> list[dict[str, object]]:
    if len(retrieved_by_edge) == 1:
        return [{"score": 1.0, "edges": [list(edge)]} for edge in retrieved_by_edge[0][:topk]]
    candidates = []
    for left in retrieved_by_edge[0]:
        for right in retrieved_by_edge[1]:
            if left[2] == right[0]:
                candidates.append({"score": 1.0, "edges": [list(left), list(right)]})
    candidates.sort(key=lambda item: json.dumps(item["edges"], sort_keys=True))
    return candidates


def _parse_edges(values: list[str]) -> list[tuple[str, str, str]]:
    edges = []
    for value in values:
        parts = tuple(part.strip() for part in value.split("|"))
        if len(parts) != 3 or any(not part for part in parts):
            raise SystemExit(f"invalid --edge value: {value!r}")
        edges.append(parts)
    if len(edges) not in (1, 2):
        raise SystemExit("this SealPIR runner supports one-hop or two-hop path queries")
    return edges  # type: ignore[return-value]


def _is_unknown(value: str) -> bool:
    return value.strip().upper().startswith(UNKNOWN_PREFIX)


if __name__ == "__main__":
    raise SystemExit(main())
