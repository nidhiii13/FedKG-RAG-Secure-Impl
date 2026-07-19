#!/usr/bin/env python3
"""Run query preparation, ORAM retrieval, MPC join/top-k, and reveal."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from run_twohop_e2e import _parse_mpspdz_metrics, _run


REPO_ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--index-dir", required=True)
    parser.add_argument("--edge", required=True, action="append")
    parser.add_argument("--output-dir")
    parser.add_argument("--max-candidates", type=int, default=64)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--semantic-relations", action="store_true")
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()
    if len(args.edge) != 2:
        raise SystemExit("ORAM two-hop e2e requires exactly two --edge values")
    env = os.environ.copy()
    if not env.get("FEDKG_SETUP_KEY"):
        raise SystemExit("FEDKG_SETUP_KEY is required")

    if args.output_dir:
        instance_dir = Path(args.output_dir)
        instance_dir.mkdir(parents=True, exist_ok=True)
        temp_context = None
    else:
        temp_context = tempfile.TemporaryDirectory(prefix="fedkg-mpspdz-oram-")
        instance_dir = Path(temp_context.name)

    try:
        prepare_cmd = [
            sys.executable,
            str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "prepare_metaqa_twohop_oram_mpspdz_inputs.py"),
            "--manifest",
            args.manifest,
            "--index-dir",
            args.index_dir,
            "--edge",
            args.edge[0],
            "--edge",
            args.edge[1],
            "--output-dir",
            str(instance_dir),
            "--max-candidates",
            str(args.max_candidates),
            "--topk",
            str(args.topk),
        ]
        if args.semantic_relations:
            prepare_cmd.append("--semantic-relations")

        started = time.perf_counter()
        prepare = _run(prepare_cmd, env=env, cwd=REPO_ROOT)
        mapping = json.loads(prepare.stdout)
        run_env = env.copy()
        run_env["MP_SPDZ_HOME"] = args.mp_spdz_home
        mpc_run = _run(
            [
                "bash",
                str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "run_mpspdz_oram_instance.sh"),
                str(instance_dir),
            ],
            env=run_env,
            cwd=REPO_ROOT,
        )
        elapsed = time.perf_counter() - started
        raw_output = instance_dir / "mp_spdz_output.txt"
        raw_output.write_text(mpc_run.stdout)
        reveal = _run(
            [
                sys.executable,
                str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "decode_mpspdz_oram_output.py"),
                "--mapping",
                str(instance_dir / "query_gateway_receipt.json"),
                "--mp-spdz-output",
                str(raw_output),
            ],
            env=env,
            cwd=REPO_ROOT,
        )
        print(
            json.dumps(
                {
                    "instance_dir": str(instance_dir),
                    "query": mapping["query"],
                    "mp_spdz": {
                        "program": "secure_kg_twohop_oram_join_topk",
                        "raw_output": str(raw_output),
                        "metrics": _parse_mpspdz_metrics(mpc_run.stdout),
                    },
                    "total_e2e_seconds": elapsed,
                    "security_model": mapping["security_note"],
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
