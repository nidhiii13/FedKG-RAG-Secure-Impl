#!/usr/bin/env python3
"""Run bounded edge-table two-hop MP-SPDZ join, private top-k, and reveal."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from run_twohop_e2e import _parse_mpspdz_metrics, _run


REPO_ROOT = Path(__file__).resolve().parents[2]


def _parse_pair_slots(output: str, sentinel: int) -> list[int]:
    slots: list[int] = []
    in_table = False
    for line in output.splitlines():
        if line.strip() == "rank selected_edge_pair_slot":
            in_table = True
            continue
        if not in_table:
            continue
        parts = line.split()
        if len(parts) != 2 or not all(part.isdigit() for part in parts):
            if slots:
                break
            continue
        slot = int(parts[1])
        if slot != sentinel:
            slots.append(slot)
    return slots


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--edge", required=True, action="append")
    parser.add_argument("--output-dir")
    parser.add_argument("--edge-rows-per-party", type=int, default=64)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    parser.add_argument("--semantic-relations", action="store_true")
    parser.add_argument("--prioritize-query-rows", action="store_true")
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()

    if len(args.edge) != 2:
        raise SystemExit("two-hop edge-join e2e requires exactly two --edge values")

    env = os.environ.copy()
    if not env.get("FEDKG_SETUP_KEY"):
        raise SystemExit("FEDKG_SETUP_KEY is required")

    if args.output_dir:
        instance_dir = Path(args.output_dir)
        instance_dir.mkdir(parents=True, exist_ok=True)
        temp_context = None
    else:
        temp_context = tempfile.TemporaryDirectory(prefix="fedkg-mpspdz-edge-join-")
        instance_dir = Path(temp_context.name)

    try:
        prepare_cmd = [
            sys.executable,
            str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "prepare_metaqa_twohop_edge_join_mpspdz_inputs.py"),
            "--manifest",
            args.manifest,
            "--edge",
            args.edge[0],
            "--edge",
            args.edge[1],
            "--output-dir",
            str(instance_dir),
            "--edge-rows-per-party",
            str(args.edge_rows_per_party),
            "--topk",
            str(args.topk),
        ]
        if args.semantic_relations:
            prepare_cmd.append("--semantic-relations")
        if args.prioritize_query_rows:
            prepare_cmd.append("--prioritize-query-rows")

        started = time.perf_counter()
        prepare = _run(prepare_cmd, env=env, cwd=REPO_ROOT)
        mapping = json.loads(prepare.stdout)

        run_env = env.copy()
        run_env["MP_SPDZ_HOME"] = args.mp_spdz_home
        run_cmd = [
            "bash",
            str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "run_mpspdz_instance.sh"),
            str(instance_dir),
        ]
        mpc_run = _run(run_cmd, env=run_env, cwd=REPO_ROOT)
        elapsed = time.perf_counter() - started
        raw_output_path = instance_dir / "mp_spdz_output.txt"
        raw_output_path.write_text(mpc_run.stdout)

        total_edge_rows = mapping["total_edge_rows"]
        selected_pair_slots = _parse_pair_slots(mpc_run.stdout, sentinel=total_edge_rows * total_edge_rows)
        decode_cmd = [
            sys.executable,
            str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "decode_mpspdz_edge_join_output.py"),
            "--mapping",
            str(instance_dir / "public_mapping.json"),
        ]
        for slot in selected_pair_slots:
            decode_cmd.extend(["--slot", str(slot)])
        reveal = _run(decode_cmd, env=env, cwd=REPO_ROOT)

        print(
            json.dumps(
                {
                    "instance_dir": str(instance_dir),
                    "query": mapping["query"],
                    "mp_spdz": {
                        "program": "secure_kg_twohop_edge_join_topk",
                        "raw_output": str(raw_output_path),
                        "selected_pair_slots": selected_pair_slots,
                        "metrics": _parse_mpspdz_metrics(mpc_run.stdout),
                    },
                    "total_e2e_seconds": elapsed,
                    "data_parties": mapping["data_parties"],
                    "controlled_reveal": json.loads(reveal.stdout),
                },
                indent=2,
            )
        )
    finally:
        if temp_context is not None and args.keep_temp:
            temp_context = None
        elif temp_context is not None:
            temp_context.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
