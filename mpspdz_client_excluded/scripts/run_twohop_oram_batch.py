#!/usr/bin/env python3
"""Run and score several queries in one initialized MP-SPDZ ORAM session."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from decode_mpspdz_oram_output import _load_vaults, _resolve
from run_twohop_e2e import _parse_mpspdz_metrics


REPO_ROOT = Path(__file__).resolve().parents[2]
PREPARER = REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "prepare_metaqa_oram_batch_inputs.py"
RUNNER = REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "run_mpspdz_oram_instance.sh"
OUTPUT_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")


def _canonical(value: object) -> str:
    return " ".join(str(value).strip().lower().split())


def _parse_batch_handles(output: str, query_count: int) -> list[list[tuple[int, int]]]:
    handles = [[] for _ in range(query_count)]
    in_table = False
    for line in output.splitlines():
        if line.strip() == "query rank left_evidence_handle right_evidence_handle":
            in_table = True
            continue
        if not in_table:
            continue
        match = OUTPUT_RE.match(line)
        if not match:
            continue
        query_index = int(match.group(1))
        left, right = int(match.group(3)), int(match.group(4))
        if left:
            handles[query_index].append((left, right))
    return handles


def _decode_paths(handle_pairs: list[tuple[int, int]], vaults: list[dict]) -> list[dict]:
    paths = []
    for rank, (left_handle, right_handle) in enumerate(handle_pairs):
        left = _resolve(left_handle, vaults)
        right = _resolve(right_handle, vaults)
        edges = [[left["source"], left["relation"], left["target"]]]
        if right is not None:
            edges.append([right["source"], right["relation"], right["target"]])
        paths.append({"rank": rank, "edges": edges})
    return paths


def _retrieved_entities(paths: list[dict]) -> set[str]:
    return {
        _canonical(entity)
        for path in paths
        for source, _, target in path["edges"]
        for entity in (source, target)
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--index-dir", required=True)
    parser.add_argument("--queries-jsonl", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--instance-dir", required=True)
    parser.add_argument("--max-queries", type=int, default=10)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--max-candidates", type=int, default=64)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    args = parser.parse_args()
    env = os.environ.copy()
    if not env.get("FEDKG_SETUP_KEY"):
        raise SystemExit("FEDKG_SETUP_KEY is required")

    started = time.perf_counter()
    prepare = subprocess.run(
        [
            sys.executable,
            str(PREPARER),
            "--manifest",
            args.manifest,
            "--index-dir",
            args.index_dir,
            "--queries-jsonl",
            args.queries_jsonl,
            "--output-dir",
            args.instance_dir,
            "--max-queries",
            str(args.max_queries),
            "--start-index",
            str(args.start_index),
            "--max-candidates",
            str(args.max_candidates),
            "--topk",
            str(args.topk),
        ],
        cwd=REPO_ROOT,
        env=env,
        check=True,
        text=True,
        capture_output=True,
    )
    mapping = json.loads(prepare.stdout)
    run_env = env.copy()
    run_env["MP_SPDZ_HOME"] = args.mp_spdz_home
    mpc = subprocess.run(
        ["bash", str(RUNNER), args.instance_dir],
        cwd=REPO_ROOT,
        env=run_env,
        check=True,
        text=True,
        capture_output=True,
    )
    raw_output = Path(args.instance_dir) / "mp_spdz_output.txt"
    raw_output.write_text(mpc.stdout)
    handles = _parse_batch_handles(mpc.stdout, len(mapping["queries"]))
    vaults = _load_vaults(mapping)
    metrics = _parse_mpspdz_metrics(mpc.stdout)

    records = []
    for query, query_handles in zip(mapping["queries"], handles):
        paths = _decode_paths(query_handles, vaults)
        retrieved = _retrieved_entities(paths)
        groundtruths = [_canonical(value) for value in query["groundtruths"]]
        correct = any(value in retrieved for value in groundtruths)
        records.append(
            {
                **query,
                "correct": correct,
                "candidate_paths": len(paths),
                "retrieved_entities": sorted(retrieved),
                "selected_paths": paths,
            }
        )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(json.dumps(record) + "\n" for record in records))
    correct = sum(record["correct"] for record in records)
    summary = {
        "queries": len(records),
        "correct": correct,
        "hit_at_k": correct / len(records) if records else 0.0,
        "topk": args.topk,
        "wall_seconds": time.perf_counter() - started,
        "mp_spdz_metrics": metrics,
        "output": str(output_path),
        "instance_dir": args.instance_dir,
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
