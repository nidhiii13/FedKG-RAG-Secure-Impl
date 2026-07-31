#!/usr/bin/env python3
"""Batch numeric threshold-PIR lookup with persistent shard services."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_lattigo_threshold_pir_bucket_query import simplify_query_edges
from scripts.run_numeric_pir_mpspdz_query import (
    _decode_selected_paths,
    _load_numeric_records,
    _numeric_edge_requests,
    _parse_metrics,
    _parse_selected_slots,
    _resolve_repo_relative,
    _run_mpspdz,
    _slice_shared_record,
    _write_mpspdz_instance,
)
from src.crypto.hmac_ids import HmacIdProvider
from src.pir.lattigo_threshold_service import LattigoThresholdPirService


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Persistent-shard numeric PIR + MP-SPDZ batch runner.")
    parser.add_argument("--index-dir", required=True, type=Path)
    parser.add_argument("--queries-jsonl", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--append", action="store_true")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--max-queries", type=int, default=10)
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--semantic-bucket-mode", choices=("alias", "lsh", "hybrid"), default="alias")
    parser.add_argument("--max-query-buckets", type=int, default=1)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--parties", type=int, default=3)
    parser.add_argument("--threshold", type=int, default=2)
    parser.add_argument("--share-modulus", type=int)
    parser.add_argument("--go-routines", type=int, default=8)
    parser.add_argument(
        "--mp-spdz-protocol",
        choices=("semi", "atlas"),
        default="semi",
        help="MP-SPDZ protocol backend for bounded traversal/top-k after PIR.",
    )
    parser.add_argument(
        "--setup-parallelism",
        type=int,
        default=1,
        help="Number of persistent PIR shard services to start concurrently. "
        "Higher values reduce setup wall time but use more CPU/RAM.",
    )
    parser.add_argument(
        "--shard-parallelism",
        type=int,
        default=1,
        help="Number of persistent PIR shard services to query concurrently. "
        "Security is unchanged because every shard is still queried.",
    )
    parser.add_argument("--mp-spdz-home", type=Path, default=Path("external/MP-SPDZ"))
    parser.add_argument("--instances-dir", type=Path, default=Path("/tmp/fedkg-numeric-pir-mpspdz-batch"))
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--debug-plan", action="store_true")
    parser.add_argument(
        "--lattigo-pir",
        type=Path,
        default=Path("tools/lattigo_threshold_pir/lattigo-fedkg-threshold-pir"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.mp_spdz_home = _resolve_repo_relative(args.mp_spdz_home)
    ids = HmacIdProvider.from_env(args.key_env)
    metadata = json.loads((args.index_dir / "metadata.json").read_text())
    if metadata.get("record_format") != "json-u64-array":
        raise SystemExit("numeric batch runner requires build_numeric_pir_bucket_index.py output")
    directory = json.loads((args.index_dir / "directory.json").read_text())
    id_map = json.loads((args.index_dir / "id_map.json").read_text())
    shards = metadata.get("shards") or []
    shard_records = [_load_numeric_records(args.index_dir / str(shard["path"])) for shard in shards]
    record_size = int(metadata["record_size"])
    logical_record_size = int(metadata.get("logical_record_size", record_size))
    page_capacity = int(metadata.get("page_capacity", 1))
    edge_cap = int(metadata["max_edges_per_record"])
    plaintext_modulus = int(metadata.get("plaintext_modulus", 65537))
    args.share_modulus = int(args.share_modulus or plaintext_modulus)
    rows = _load_rows(args.queries_jsonl)[args.start :]
    if args.max_queries is not None:
        rows = rows[: args.max_queries]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.instances_dir.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.append else "w"
    summary = {"total": 0, "ok": 0, "errors": 0, "hits": 0, "pir": 0.0, "mpc": 0.0, "e2e": 0.0}

    setup_start = time.perf_counter()
    services = _start_shard_services(args, shards, record_size, plaintext_modulus)
    setup_seconds = time.perf_counter() - setup_start
    print(
        f"Persistent shard PIR services ready: shards={len(services)} setup={setup_seconds:.2f}s "
        f"record_size={record_size}",
        flush=True,
    )
    try:
        with args.output.open(mode, encoding="utf-8") as handle:
            for position, row in enumerate(rows, start=1):
                record = _run_one(
                    row,
                    args,
                    ids,
                    directory,
                    id_map,
                    shards,
                    shard_records,
                    services,
                    record_size,
                    logical_record_size,
                    page_capacity,
                    edge_cap,
                )
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                handle.flush()
                summary["total"] += 1
                summary["e2e"] += float(record.get("total_seconds", 0.0))
                summary["pir"] += float(record.get("pir", {}).get("time_seconds", 0.0))
                summary["mpc"] += float(record.get("mp_spdz", {}).get("metrics", {}).get("wall_time_seconds", 0.0))
                if record.get("error_message"):
                    summary["errors"] += 1
                else:
                    summary["ok"] += 1
                if record.get("correct"):
                    summary["hits"] += 1
                print(_progress(position, len(rows), record), flush=True)
    finally:
        for service in services:
            service.close()

    total = summary["total"] or 1
    print(
        json.dumps(
            {
                **summary,
                "setup_seconds": setup_seconds,
                "avg_e2e": summary["e2e"] / total,
                "avg_pir": summary["pir"] / total,
                "avg_mpc": summary["mpc"] / total,
                "hit_rate": summary["hits"] / total,
                "output": str(args.output),
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


def _start_shard_services(
    args: argparse.Namespace,
    shards: list[dict],
    record_size: int,
    plaintext_modulus: int,
) -> list[LattigoThresholdPirService]:
    services: list[LattigoThresholdPirService | None] = [None for _ in shards]

    def start_one(shard_index: int) -> tuple[int, LattigoThresholdPirService]:
        shard = shards[shard_index]
        return shard_index, LattigoThresholdPirService(
            executable=args.lattigo_pir,
            records_jsonl=args.index_dir / str(shard["path"]),
            record_size=record_size,
            parties=args.parties,
            threshold=args.threshold,
            go_routines=args.go_routines,
            record_format="json-u64-array",
            plaintext_modulus=plaintext_modulus,
            cwd=ROOT,
        )

    started_services: list[LattigoThresholdPirService] = []
    try:
        parallelism = max(1, min(int(args.setup_parallelism), len(shards)))
        if parallelism == 1:
            for shard_index in range(len(shards)):
                index, service = start_one(shard_index)
                services[index] = service
                started_services.append(service)
        else:
            with ThreadPoolExecutor(max_workers=parallelism) as executor:
                futures = [executor.submit(start_one, shard_index) for shard_index in range(len(shards))]
                for future in as_completed(futures):
                    index, service = future.result()
                    services[index] = service
                    started_services.append(service)
    except Exception:
        for service in started_services:
            service.close()
        raise
    return [service for service in services if service is not None]


def _run_one(
    row: dict,
    args: argparse.Namespace,
    ids: HmacIdProvider,
    directory: dict[str, dict[str, int]],
    id_map: dict,
    shards: list[dict],
    shard_records: list[list[list[int]]],
    services: list[LattigoThresholdPirService],
    record_size: int,
    logical_record_size: int,
    page_capacity: int,
    edge_cap: int,
) -> dict:
    started = time.perf_counter()
    try:
        original_edges = [tuple(str(part) for part in edge) for edge in row.get("query_graph", [])]
        edges, simplification = simplify_query_edges(original_edges)
        if len(edges) not in (1, 2):
            raise ValueError("numeric PIR MP-SPDZ batch supports one-hop or two-hop query graphs")
        edge_requests = _numeric_edge_requests(edges, ids, args, directory, len(shards))

        pir_start = time.perf_counter()
        shared_records, plaintext_records, requested_rows = _retrieve_with_services(
            services,
            shard_records,
            edge_requests,
            args.parties,
            args.share_modulus,
            args.shard_parallelism,
            logical_record_size,
        )
        pir_seconds = time.perf_counter() - pir_start

        instance_dir = args.instances_dir / f"query_{int(row.get('index', 0)):05d}_{int(time.time() * 1000)}"
        mpc_start = time.perf_counter()
        _write_mpspdz_instance(
            shared_records,
            instance_dir,
            record_count=len(edges),
            records_per_edge=len(shards),
            record_size=logical_record_size,
            logical_record_size=logical_record_size,
            page_capacity=1,
            edge_cap=edge_cap,
            party_count=args.parties,
            share_modulus=args.share_modulus,
            topk=args.topk,
        )
        stdout = _run_mpspdz(
            instance_dir,
            args.mp_spdz_home,
            args.parties,
            args.timeout,
            protocol=args.mp_spdz_protocol,
        )
        mpc_seconds = time.perf_counter() - mpc_start
        edge_total = len(shards) * edge_cap
        selected_slots = _parse_selected_slots(stdout, sentinel=edge_total * edge_total)
        selected_paths = _decode_selected_paths(selected_slots, plaintext_records, edge_cap, len(shards), id_map)
        hit = _groundtruth_hit(selected_paths, row.get("groundtruths", []))
        payload = {
            "index": row.get("index"),
            "query": row.get("query"),
            "groundtruths": row.get("groundtruths", []),
            "query_graph": row.get("query_graph", []),
            "effective_query": [list(edge) for edge in edges],
            "query_simplification": simplification,
            "pir": {
                "response": "additive numeric record shares",
                "shard_count": len(shards),
                "record_size": record_size,
                "logical_record_size": logical_record_size,
                "page_capacity": page_capacity,
                "edge_cap": edge_cap,
                "time_seconds": pir_seconds,
            },
            "mp_spdz": {
                "program": "secure_numeric_pir_record_topk",
                "protocol": args.mp_spdz_protocol,
                "selected_slots": selected_slots,
                "metrics": {**_parse_metrics(stdout), "wall_time_seconds": mpc_seconds},
            },
            "selected_paths": selected_paths,
            "selected_path_count": len(selected_paths),
            "correct": hit,
            "total_seconds": time.perf_counter() - started,
        }
        if args.debug_plan:
            payload["pir"]["requested_rows_per_edge"] = requested_rows
        return payload
    except Exception as exc:
        return {
            "index": row.get("index"),
            "query": row.get("query"),
            "groundtruths": row.get("groundtruths", []),
            "query_graph": row.get("query_graph", []),
            "selected_paths": [],
            "selected_path_count": 0,
            "correct": False,
            "total_seconds": time.perf_counter() - started,
            "error_message": str(exc)[:1000],
        }


def _retrieve_with_services(
    services: list[LattigoThresholdPirService],
    shard_records: list[list[list[int]]],
    edge_requests: list[list[int]],
    share_parties: int,
    share_modulus: int,
    shard_parallelism: int,
    logical_record_size: int,
) -> tuple[list[dict], list[list[list[int]]], list[list[dict[str, int]]]]:
    shared_by_edge: list[list[dict | None]] = [[None for _ in services] for _ in edge_requests]
    plaintext_by_edge: list[list[list[int]]] = [[[] for _ in services] for _ in edge_requests]

    def retrieve_shard(shard_index: int) -> tuple[int, list[int], list[dict]]:
        service = services[shard_index]
        indices = [edge_requests[edge_index][shard_index]["row"] for edge_index in range(len(edge_requests))]
        response = service.retrieve_shared(indices, share_parties=share_parties, share_modulus=share_modulus)
        return shard_index, indices, list(response.get("records", []))

    parallelism = max(1, min(int(shard_parallelism), len(services)))
    if parallelism == 1:
        shard_results = [retrieve_shard(shard_index) for shard_index in range(len(services))]
    else:
        shard_results = []
        with ThreadPoolExecutor(max_workers=parallelism) as executor:
            futures = [executor.submit(retrieve_shard, shard_index) for shard_index in range(len(services))]
            for future in as_completed(futures):
                shard_results.append(future.result())

    for shard_index, indices, records in shard_results:
        if len(records) != len(edge_requests):
            raise RuntimeError(
                f"shard {shard_index} returned {len(records)} records for {len(edge_requests)} edge requests"
            )
        for edge_index, record in enumerate(records):
            offset = edge_requests[edge_index][shard_index]["offset"]
            shared_by_edge[edge_index][shard_index] = _slice_shared_record(record, offset, logical_record_size)
            start = offset * logical_record_size
            end = start + logical_record_size
            plaintext_by_edge[edge_index][shard_index] = shard_records[shard_index][indices[edge_index]][start:end]
    flat_shared = []
    for edge_records in shared_by_edge:
        for record in edge_records:
            if record is None:
                raise RuntimeError("missing shared PIR record")
            flat_shared.append(record)
    return flat_shared, plaintext_by_edge, edge_requests


def _groundtruth_hit(paths: list[dict], groundtruths: list[str]) -> bool:
    if not groundtruths:
        return False
    needles = {str(value).lower() for value in groundtruths}
    payload = json.dumps(paths, ensure_ascii=False).lower()
    return any(needle in payload for needle in needles)


def _load_rows(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if not line.strip():
                continue
            row = json.loads(line)
            row.setdefault("index", index)
            row.setdefault("groundtruths", [])
            rows.append(row)
    return rows


def _progress(position: int, total: int, record: dict) -> str:
    status = "ERR" if record.get("error_message") else "OK"
    hit = "hit" if record.get("correct") else "miss"
    query = str(record.get("query") or "").replace("\n", " ")[:80]
    pir = float(record.get("pir", {}).get("time_seconds", 0.0))
    mpc = float(record.get("mp_spdz", {}).get("metrics", {}).get("wall_time_seconds", 0.0))
    return (
        f"[{position}/{total}] {status} index={record.get('index')} {hit} "
        f"paths={record.get('selected_path_count', 0)} pir={pir:.2f}s mpc={mpc:.2f}s "
        f"e2e={float(record.get('total_seconds', 0.0)):.2f}s query={query}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
