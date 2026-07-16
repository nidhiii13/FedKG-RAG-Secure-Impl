#!/usr/bin/env python3
"""Run bounded two-hop MP-SPDZ retrieval, private top-k, and controlled reveal."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
NO_SELECTION_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s*$")
TIME_RE = re.compile(r"Time\s*=\s*([0-9.]+)\s+seconds")
PARTY_DATA_RE = re.compile(r"Data sent\s*=\s*([0-9.]+)\s+MB\s+in\s+~?(\d+)\s+rounds")
GLOBAL_DATA_RE = re.compile(r"Global data sent\s*=\s*([0-9.]+)\s+MB")


def _run(cmd: list[str], *, env: dict[str, str], cwd: Path, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        capture_output=capture,
    )


def _parse_selected_slots(output: str, sentinel: int) -> list[int]:
    slots: list[int] = []
    in_table = False
    for line in output.splitlines():
        if line.strip() == "rank selected_path_slot":
            in_table = True
            continue
        if not in_table:
            continue
        match = NO_SELECTION_RE.match(line)
        if not match:
            if slots:
                break
            continue
        slot = int(match.group(2))
        if slot != sentinel:
            slots.append(slot)
    return slots


def _parse_mpspdz_metrics(output: str) -> dict:
    time_match = TIME_RE.search(output)
    party_data_match = PARTY_DATA_RE.search(output)
    global_data_match = GLOBAL_DATA_RE.search(output)
    return {
        "mpc_time_seconds": float(time_match.group(1)) if time_match else None,
        "party0_data_mb": float(party_data_match.group(1)) if party_data_match else None,
        "rounds": int(party_data_match.group(2)) if party_data_match else None,
        "global_data_mb": float(global_data_match.group(1)) if global_data_match else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--edge", required=True, action="append")
    parser.add_argument("--output-dir")
    parser.add_argument("--rows-per-party", type=int, default=256)
    parser.add_argument("--path-capacity", type=int, default=64)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    parser.add_argument("--keep-temp", action="store_true")
    parser.add_argument("--semantic-relations", action="store_true")
    args = parser.parse_args()

    if len(args.edge) != 2:
        raise SystemExit("two-hop e2e requires exactly two --edge values")

    env = os.environ.copy()
    if not env.get("FEDKG_SETUP_KEY"):
        raise SystemExit("FEDKG_SETUP_KEY is required")

    if args.output_dir:
        instance_dir = Path(args.output_dir)
        instance_dir.mkdir(parents=True, exist_ok=True)
        temp_context = None
    else:
        temp_context = tempfile.TemporaryDirectory(prefix="fedkg-mpspdz-twohop-")
        instance_dir = Path(temp_context.name)

    try:
        prepare_cmd = [
            sys.executable,
            str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "prepare_metaqa_twohop_mpspdz_inputs.py"),
            "--manifest",
            args.manifest,
            "--edge",
            args.edge[0],
            "--edge",
            args.edge[1],
            "--output-dir",
            str(instance_dir),
            "--rows-per-party",
            str(args.rows_per_party),
            "--path-capacity",
            str(args.path_capacity),
            "--reveal-mode",
            "topk",
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
        run_cmd = [
            "bash",
            str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "run_mpspdz_instance.sh"),
            str(instance_dir),
        ]
        mpc_run = _run(run_cmd, env=run_env, cwd=REPO_ROOT)
        elapsed = time.perf_counter() - started
        raw_output_path = instance_dir / "mp_spdz_output.txt"
        raw_output_path.write_text(mpc_run.stdout)

        selected_slots = _parse_selected_slots(mpc_run.stdout, sentinel=args.path_capacity)
        metrics = _parse_mpspdz_metrics(mpc_run.stdout)
        decode_cmd = [
            sys.executable,
            str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "decode_mpspdz_topk_output.py"),
            "--mapping",
            str(instance_dir / "public_mapping.json"),
        ]
        for slot in selected_slots:
            decode_cmd.extend(["--slot", str(slot)])
        reveal = _run(decode_cmd, env=env, cwd=REPO_ROOT)
        reveal_payload = json.loads(reveal.stdout)

        result = {
            "instance_dir": str(instance_dir),
            "query": mapping["query"],
            "mp_spdz": {
                "program": "secure_kg_twohop_private_topk",
                "raw_output": str(raw_output_path),
                "selected_slots": selected_slots,
                "metrics": metrics,
            },
            "total_e2e_seconds": elapsed,
            "candidate_path_count": len(mapping.get("paths", [])),
            "data_parties": mapping["data_parties"],
            "controlled_reveal": reveal_payload,
        }
        print(json.dumps(result, indent=2))
    finally:
        if temp_context is not None and args.keep_temp:
            # Prevent cleanup by intentionally dropping ownership after reporting
            # the path. The caller can inspect the instance directory.
            temp_context = None
        elif temp_context is not None:
            temp_context.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
