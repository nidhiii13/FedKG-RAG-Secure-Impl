#!/usr/bin/env python3
"""Run mixed one-hop/two-hop MP-SPDZ batch queries for MetaQA comparison."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_edges(payload: dict) -> list[str]:
    edges = payload.get("query_graph") or payload.get("edges")
    if not edges:
        raise ValueError("row must contain query_graph or edges")
    return ["|".join(edge) if isinstance(edge, list) else str(edge) for edge in edges]


def _revealed_text(payload: dict) -> list[str]:
    reveal = payload.get("controlled_reveal", {})
    values = []
    for candidate in reveal.get("selected_candidates", []):
        values.append(str(candidate.get("display", "")))
    for path in reveal.get("selected_paths", []):
        for edge in path.get("edges", []):
            values.extend(str(part) for part in edge)
    return values


def _contains_groundtruth(payload: dict, groundtruths: list[str]) -> bool:
    if not groundtruths:
        return False
    haystack = "\n".join(_revealed_text(payload)).lower()
    return any(str(answer).lower() in haystack for answer in groundtruths)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--queries-jsonl", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-queries", type=int, default=250)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--onehop-rows-per-party", type=int, default=16)
    parser.add_argument("--candidate-capacity", type=int, default=32)
    parser.add_argument("--left-rows-per-party", type=int, default=4)
    parser.add_argument("--right-rows-per-party", type=int, default=8)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    parser.add_argument("--instances-dir", default="/tmp/fedkg-mpspdz-mixed-batch")
    parser.add_argument("--semantic-relations", action="store_true")
    parser.add_argument("--prioritize-query-rows", action="store_true")
    parser.add_argument("--private-tables", action="store_true")
    args = parser.parse_args()

    env = os.environ.copy()
    if not env.get("FEDKG_SETUP_KEY"):
        raise SystemExit("FEDKG_SETUP_KEY is required")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    instances_dir = Path(args.instances_dir)
    instances_dir.mkdir(parents=True, exist_ok=True)

    total = ok = correct = 0
    with Path(args.queries_jsonl).open() as input_file, output_path.open("w") as output_file:
        for index, line in enumerate(input_file):
            if index < args.start_index:
                continue
            if total >= args.max_queries:
                break
            total += 1
            row = json.loads(line)
            question = row.get("query") or row.get("question")
            groundtruths = row.get("groundtruths") or row.get("answers") or []
            try:
                edges = _load_edges(row)
                instance_dir = instances_dir / f"query_{index:05d}"
                if instance_dir.exists():
                    shutil.rmtree(instance_dir)
                if len(edges) == 1:
                    kind = "onehop"
                    cmd = [
                        sys.executable,
                        str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "run_onehop_e2e.py"),
                        "--manifest",
                        args.manifest,
                        "--edge",
                        edges[0],
                        "--output-dir",
                        str(instance_dir),
                        "--rows-per-party",
                        str(args.onehop_rows_per_party),
                        "--candidate-capacity",
                        str(args.candidate_capacity),
                        "--topk",
                        str(args.topk),
                        "--mp-spdz-home",
                        args.mp_spdz_home,
                    ]
                elif len(edges) == 2:
                    kind = "twohop_split"
                    cmd = [
                        sys.executable,
                        str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "run_twohop_split_edge_join_e2e.py"),
                        "--manifest",
                        args.manifest,
                        "--edge",
                        edges[0],
                        "--edge",
                        edges[1],
                        "--output-dir",
                        str(instance_dir),
                        "--left-rows-per-party",
                        str(args.left_rows_per_party),
                        "--right-rows-per-party",
                        str(args.right_rows_per_party),
                        "--topk",
                        str(args.topk),
                        "--mp-spdz-home",
                        args.mp_spdz_home,
                    ]
                    if args.prioritize_query_rows:
                        cmd.append("--prioritize-query-rows")
                    if args.private_tables:
                        cmd.append("--private-tables")
                else:
                    raise ValueError(f"unsupported query graph length: {len(edges)}")

                if args.semantic_relations:
                    cmd.append("--semantic-relations")

                result = subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=True, text=True, capture_output=True)
                payload = json.loads(result.stdout)
                is_correct = _contains_groundtruth(payload, groundtruths)
                correct += int(is_correct)
                ok += 1
                m = payload.get("mp_spdz", {}).get("metrics", {})
                record = {
                    "index": index,
                    "status": "ok",
                    "kind": kind,
                    "query": question,
                    "groundtruths": groundtruths,
                    "query_graph": row.get("query_graph") or row.get("edges"),
                    "federated_correct": row.get("federated_correct"),
                    "federated_retrieval_time": row.get("federated_retrieval_time"),
                    "mp_spdz_correct": is_correct,
                    "mp_spdz_total_e2e_seconds": payload.get("total_e2e_seconds"),
                    "mp_spdz_mpc_time_seconds": m.get("mpc_time_seconds"),
                    "mp_spdz_global_data_mb": m.get("global_data_mb"),
                    "mp_spdz_rounds": m.get("rounds"),
                    "payload": payload,
                }
                print(
                    f"[{total}/{args.max_queries}] OK index={index} {kind} "
                    f"correct={is_correct} e2e={payload.get('total_e2e_seconds'):.2f}s"
                )
            except Exception as exc:
                stderr = None
                stdout = None
                if isinstance(exc, subprocess.CalledProcessError):
                    stderr = exc.stderr
                    stdout = exc.stdout
                record = {
                    "index": index,
                    "status": "error",
                    "query": question,
                    "groundtruths": groundtruths,
                    "query_graph": row.get("query_graph") or row.get("edges"),
                    "error": str(exc),
                    "stdout": stdout,
                    "stderr": stderr,
                }
                print(f"[{total}/{args.max_queries}] ERR index={index} error={exc}")
            output_file.write(json.dumps(record, ensure_ascii=False) + "\n")
            output_file.flush()

    print(json.dumps({"total": total, "ok": ok, "errors": total - ok, "correct": correct, "output": str(output_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
