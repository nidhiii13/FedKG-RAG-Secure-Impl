#!/usr/bin/env python3
"""Batch Lattigo threshold-PIR retrieval with one persistent native setup."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_lattigo_threshold_pir_bucket_query import (
    _aggregate_and_rank,
    _edge_requests,
    _join_paths,
    _load_id_map,
    _records_for_edge,
    simplify_query_edges,
)
from src.crypto.hmac_ids import HmacIdProvider
from src.pir.lattigo_threshold_service import LattigoThresholdPirService


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Persistent batch runner for Lattigo threshold-PIR KG buckets.")
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
    parser.add_argument("--prio-aggregators", type=int, default=3)
    parser.add_argument("--candidate-capacity", type=int, default=256)
    parser.add_argument("--handle-key-env", default="FEDKG_PRIO_HANDLE_KEY")
    parser.add_argument("--query-nonce", default="lattigo-threshold-pir-batch")
    parser.add_argument("--prio-cli", type=Path, default=Path("tools/prio3_cli/target/release/fedkg-prio3-cli"))
    parser.add_argument("--go-routines", type=int, default=1)
    parser.add_argument(
        "--lattigo-pir",
        type=Path,
        default=Path("tools/lattigo_threshold_pir/lattigo-fedkg-threshold-pir"),
    )
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ids = HmacIdProvider.from_env(args.key_env)
    metadata = json.loads((args.index_dir / "metadata.json").read_text())
    directory = json.loads((args.index_dir / "directory.json").read_text())
    id_map = _load_id_map(args.index_dir)
    record_size = int(metadata["record_size"])
    rows = _load_rows(args.queries_jsonl)
    selected = rows[args.start :]
    if args.max_queries is not None:
        selected = selected[: args.max_queries]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.append else "w"
    summary = {"total": 0, "ok": 0, "errors": 0, "hits": 0, "retrieval_time": 0.0}

    service_start = time.perf_counter()
    with LattigoThresholdPirService(
        executable=args.lattigo_pir,
        records_jsonl=args.index_dir / "records.jsonl",
        record_size=record_size,
        parties=args.parties,
        threshold=args.threshold,
        go_routines=args.go_routines,
        cwd=ROOT,
    ) as service:
        setup_seconds = time.perf_counter() - service_start
        if not args.quiet:
            print(
                f"Lattigo threshold-PIR service ready: setup={setup_seconds:.2f}s "
                f"database={service.ready.get('database_size')} record_size={service.ready.get('record_size')}",
                flush=True,
            )
        with args.output.open(mode, encoding="utf-8") as handle:
            for position, row in enumerate(selected, start=1):
                record = _run_one(row, args, ids, directory, metadata, service, id_map)
                summary["total"] += 1
                summary["retrieval_time"] += float(record.get("retrieval_time", 0.0))
                if record.get("error_message"):
                    summary["errors"] += 1
                else:
                    summary["ok"] += 1
                if record.get("evidence_contains_groundtruth"):
                    summary["hits"] += 1
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                handle.flush()
                if not args.quiet:
                    print(_progress_line(position, len(selected), record), flush=True)

    if not args.quiet:
        avg = summary["retrieval_time"] / summary["total"] if summary["total"] else 0.0
        print(
            json.dumps(
                {
                    **summary,
                    "avg_retrieval_time": avg,
                    "hit_rate": summary["hits"] / summary["total"] if summary["total"] else 0.0,
                    "persistent_setup_seconds": setup_seconds,
                    "output": str(args.output),
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


def _run_one(
    row: dict,
    args: argparse.Namespace,
    ids: HmacIdProvider,
    directory: dict[str, int],
    metadata: dict,
    service: LattigoThresholdPirService,
    id_map: dict[str, str] | None,
) -> dict:
    start = time.perf_counter()
    query_graph = row.get("query_graph") or []
    try:
        original_edges = _parse_query_graph(query_graph)
        edges, simplification = simplify_query_edges(original_edges)
        requests = _edge_requests(edges, ids, args, directory)
        response = service.retrieve(sorted({request["index"] for request in requests}))
        records_by_index = {
            int(record["query_index"]): record["record_json"]
            for record in response.get("records", [])
        }
        retrieved = [
            _records_for_edge(requests, records_by_index, edge_index, id_map)
            for edge_index in range(len(edges))
        ]
        candidates = _join_paths(retrieved, args.topk)
        ranked = _aggregate_and_rank(candidates, args)
    except Exception as exc:
        return _error_record(row, query_graph, start, str(exc))

    hit = _encoded_groundtruth_hit(
        [candidate for candidate in candidates if candidate["candidate_id"] in set(ranked["selected_candidate_ids"])],
        row.get("groundtruths", []),
        ids,
    )
    return {
        "index": row.get("index"),
        "query": row.get("query"),
        "groundtruths": row.get("groundtruths", []),
        "query_graph": query_graph,
        "effective_query_graph": [list(edge) for edge in edges],
        "query_simplification": simplification,
        "retrieval_time": time.perf_counter() - start,
        "candidate_count": len(candidates),
        "selected_candidate_ids": ranked["selected_candidate_ids"],
        "selected_encoded_paths": [
            candidate for candidate in candidates if candidate["candidate_id"] in set(ranked["selected_candidate_ids"])
        ][: args.topk],
        "evidence_contains_groundtruth": hit,
        "correct": hit,
        "pir_backend": {
            "type": "lattigo-threshold-bgv-pir-persistent",
            "parties": args.parties,
            "threshold": args.threshold,
            "database_size": metadata["database_size"],
            "record_size": metadata["record_size"],
            "semantic_bucket_mode": metadata.get("semantic_bucket_mode"),
        },
        "post_retrieval_validation": ranked["validation"],
    }


def _parse_query_graph(query_graph: list) -> list[tuple[str, str, str]]:
    if len(query_graph) not in (1, 2):
        raise ValueError("this batch runner supports one-hop or two-hop query graphs")
    edges = []
    for edge in query_graph:
        if len(edge) != 3:
            raise ValueError(f"invalid query edge: {edge!r}")
        edges.append(tuple(str(part) for part in edge))
    return edges


def _error_record(row: dict, query_graph: list, start: float, message: str) -> dict:
    return {
        "index": row.get("index"),
        "query": row.get("query"),
        "groundtruths": row.get("groundtruths", []),
        "query_graph": query_graph,
        "retrieval_time": time.perf_counter() - start,
        "candidate_count": 0,
        "selected_encoded_paths": [],
        "evidence_contains_groundtruth": False,
        "correct": False,
        "error_message": message[:1000],
    }


def _encoded_groundtruth_hit(paths: list[dict], groundtruths: list[str], ids: HmacIdProvider) -> bool:
    if not groundtruths:
        return False
    encoded_groundtruths = {ids.entity_id(value) for value in groundtruths}
    payload = json.dumps(paths)
    return any(encoded in payload for encoded in encoded_groundtruths)


def _progress_line(position: int, total: int, record: dict) -> str:
    status = "ERR" if record.get("error_message") else "OK"
    hit = "hit" if record.get("evidence_contains_groundtruth") else "miss"
    query = str(record.get("query") or "").replace("\n", " ")[:90]
    return (
        f"[{position}/{total}] {status} index={record.get('index')} "
        f"{hit} candidates={record.get('candidate_count', 0)} "
        f"retrieval={record.get('retrieval_time', 0.0):.2f}s query={query}"
    )


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


if __name__ == "__main__":
    raise SystemExit(main())
