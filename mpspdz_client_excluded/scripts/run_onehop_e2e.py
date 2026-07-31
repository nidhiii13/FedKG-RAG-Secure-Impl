#!/usr/bin/env python3
"""Run bounded one-hop MP-SPDZ lookup and decode selected candidates."""

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
    parser.add_argument("--edge", required=True)
    parser.add_argument("--output-dir")
    parser.add_argument("--rows-per-party", type=int, default=16)
    parser.add_argument("--candidate-capacity", type=int, default=32)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    parser.add_argument("--semantic-relations", action="store_true")
    parser.add_argument("--private-tables", action="store_true")
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()

    env = os.environ.copy()
    if not env.get("FEDKG_SETUP_KEY"):
        raise SystemExit("FEDKG_SETUP_KEY is required")

    if args.output_dir:
        instance_dir = Path(args.output_dir)
        instance_dir.mkdir(parents=True, exist_ok=True)
        temp_context = None
    else:
        temp_context = tempfile.TemporaryDirectory(prefix="fedkg-mpspdz-onehop-")
        instance_dir = Path(temp_context.name)

    try:
        prepare_cmd = [
            sys.executable,
            str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "prepare_metaqa_mpspdz_inputs.py"),
            "--manifest",
            args.manifest,
            "--edge",
            args.edge,
            "--output-dir",
            str(instance_dir),
            "--rows-per-party",
            str(args.rows_per_party),
            "--candidate-capacity",
            str(args.candidate_capacity),
        ]
        if args.semantic_relations:
            prepare_cmd.append("--semantic-relations")
        if args.private_tables:
            prepare_cmd.append("--private-tables")

        started = time.perf_counter()
        prepare = _run(prepare_cmd, env=env, cwd=REPO_ROOT)
        mapping = json.loads(prepare.stdout)

        run_env = env.copy()
        run_env["MP_SPDZ_HOME"] = args.mp_spdz_home
        mpc_run = _run(
            [
                "bash",
                str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "run_mpspdz_instance.sh"),
                str(instance_dir),
            ],
            env=run_env,
            cwd=REPO_ROOT,
        )
        elapsed = time.perf_counter() - started
        raw_output_path = instance_dir / "mp_spdz_output.txt"
        raw_output_path.write_text(mpc_run.stdout)

        reveal = _run(
            [
                sys.executable,
                str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "decode_mpspdz_onehop_output.py"),
                "--mapping",
                str(instance_dir / "public_mapping.json"),
                "--mp-spdz-output",
                str(raw_output_path),
                "--topk",
                str(args.topk),
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
                        "program": "secure_kg_lookup_topk",
                        "raw_output": str(raw_output_path),
                        "metrics": _parse_mpspdz_metrics(mpc_run.stdout),
                    },
                    "total_e2e_seconds": elapsed,
                    "candidate_count": len(mapping.get("candidates", [])),
                    "private_tables": mapping.get("private_tables", False),
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
