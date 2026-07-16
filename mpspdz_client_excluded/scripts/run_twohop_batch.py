#!/usr/bin/env python3
"""Run a JSONL batch of bounded two-hop MP-SPDZ E2E queries."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_query(line: str) -> tuple[list[str], str | None]:
    payload = json.loads(line)
    if "edges" in payload:
        edges = payload["edges"]
    elif "query_graph" in payload:
        edges = payload["query_graph"]
    else:
        raise ValueError("query row must contain 'edges' or 'query_graph'")
    if len(edges) != 2:
        raise ValueError("batch runner currently expects exactly two edges")
    edge_text = ["|".join(edge) if isinstance(edge, list) else str(edge) for edge in edges]
    return edge_text, payload.get("query") or payload.get("question")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--queries-jsonl", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-queries", type=int)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--rows-per-party", type=int, default=16)
    parser.add_argument("--path-capacity", type=int, default=8)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    parser.add_argument("--instances-dir", default="/tmp/fedkg-mpspdz-batch")
    parser.add_argument("--semantic-relations", action="store_true")
    args = parser.parse_args()

    env = os.environ.copy()
    if not env.get("FEDKG_SETUP_KEY"):
        raise SystemExit("FEDKG_SETUP_KEY is required")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    instances_dir = Path(args.instances_dir)
    instances_dir.mkdir(parents=True, exist_ok=True)

    total = 0
    ok = 0
    with Path(args.queries_jsonl).open() as input_file, output_path.open("w") as output_file:
        for index, line in enumerate(input_file):
            if index < args.start_index:
                continue
            if args.max_queries is not None and total >= args.max_queries:
                break
            total += 1
            question = None
            try:
                edges, question = _load_query(line)
                instance_dir = instances_dir / f"query_{index:05d}"
                cmd = [
                    sys.executable,
                    str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "run_twohop_e2e.py"),
                    "--manifest",
                    args.manifest,
                    "--edge",
                    edges[0],
                    "--edge",
                    edges[1],
                    "--output-dir",
                    str(instance_dir),
                    "--rows-per-party",
                    str(args.rows_per_party),
                    "--path-capacity",
                    str(args.path_capacity),
                    "--topk",
                    str(args.topk),
                    "--mp-spdz-home",
                    args.mp_spdz_home,
                ]
                if args.semantic_relations:
                    cmd.append("--semantic-relations")
                result = subprocess.run(
                    cmd,
                    cwd=REPO_ROOT,
                    env=env,
                    check=True,
                    text=True,
                    capture_output=True,
                )
                payload = json.loads(result.stdout)
                record = {
                    "index": index,
                    "status": "ok",
                    "question": question,
                    "edges": edges,
                    **payload,
                }
                ok += 1
                selected = payload["controlled_reveal"]["selected_path_count"]
                elapsed = payload.get("total_e2e_seconds")
                print(f"[{total}] OK index={index} selected={selected} e2e={elapsed:.2f}s")
            except Exception as exc:
                record = {
                    "index": index,
                    "status": "error",
                    "question": question,
                    "error": str(exc),
                }
                print(f"[{total}] ERR index={index} error={exc}")
            output_file.write(json.dumps(record) + "\n")
            output_file.flush()

    print(json.dumps({"total": total, "ok": ok, "errors": total - ok, "output": str(output_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
