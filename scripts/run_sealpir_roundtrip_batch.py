#!/usr/bin/env python3
"""Batch runner for native SealPIR roundtrip bucket retrieval."""

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch native SealPIR roundtrip retrieval.")
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
    parser.add_argument(
        "--sealpir-roundtrip",
        type=Path,
        default=Path("build/fedkg-sealpir-cli/fedkg-sealpir-roundtrip"),
    )
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = _load_rows(args.queries_jsonl)
    selected = rows[args.start :]
    if args.max_queries is not None:
        selected = selected[: args.max_queries]

    ids = HmacIdProvider.from_env(args.key_env)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.append else "w"
    summary = {
        "total": 0,
        "ok": 0,
        "errors": 0,
        "hits": 0,
        "retrieval_time": 0.0,
    }
    with args.output.open(mode, encoding="utf-8") as handle:
        for position, row in enumerate(selected, start=1):
            record = _run_one(row, args, ids)
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
                    "output": str(args.output),
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


def _run_one(row: dict, args: argparse.Namespace, ids: HmacIdProvider) -> dict:
    start = time.perf_counter()
    query_graph = row.get("query_graph") or []
    command = [
        sys.executable,
        str(ROOT / "scripts" / "run_sealpir_roundtrip_bucket_query.py"),
        "--index-dir",
        str(args.index_dir),
        "--output",
        "/tmp/fedkg-sealpir-batch-last.json",
        "--semantic-bucket-mode",
        args.semantic_bucket_mode,
        "--max-query-buckets",
        str(args.max_query_buckets),
        "--topk",
        str(args.topk),
        "--sealpir-roundtrip",
        str(args.sealpir_roundtrip),
        "--timeout",
        str(args.timeout),
    ]
    for edge in query_graph:
        if len(edge) != 3:
            return _error_record(row, query_graph, start, f"invalid query edge: {edge!r}")
        command.extend(["--edge", "|".join(str(part) for part in edge)])

    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=args.timeout + 5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _error_record(row, query_graph, start, "SealPIR query timed out")

    elapsed = time.perf_counter() - start
    if completed.returncode != 0:
        return _error_record(row, query_graph, start, completed.stderr.strip() or completed.stdout.strip())
    payload = json.loads(completed.stdout)
    hit = _encoded_groundtruth_hit(payload.get("selected_encoded_paths", []), row.get("groundtruths", []), ids)
    return {
        "index": row.get("index"),
        "query": row.get("query"),
        "groundtruths": row.get("groundtruths", []),
        "query_graph": query_graph,
        "retrieval_time": elapsed,
        "sealpir_timing": payload.get("timing_seconds", {}),
        "candidate_count": payload.get("candidate_count", 0),
        "selected_encoded_paths": payload.get("selected_encoded_paths", []),
        "evidence_contains_groundtruth": hit,
        "correct": hit,
        "pir_backend": payload.get("pir_backend", {}),
    }


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
