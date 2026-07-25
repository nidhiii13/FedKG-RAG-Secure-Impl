#!/usr/bin/env python3
"""Hybrid private lookup + validated aggregation retrieval.

This is the practical-speed path:

1. two non-colluding DPF/FSS evaluators perform private lookup over replicated
   HMAC-only indexes;
2. encoded graph traversal creates opaque candidate contributions;
3. Prio3 validates/aggregates padded score/support vectors;
4. local validation ranks reconstructed aggregates.

The final ranking/reconstruction step is intentionally labelled as local
validation. A production deployment should replace it with a share-preserving
Prio-to-MPC/GC ranking bridge.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_role_separated_secure_retrieval.py"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run DPF/FSS private lookup followed by Prio3 candidate aggregation."
    )
    parser.add_argument("--store-0", required=True, type=Path)
    parser.add_argument("--store-1", required=True, type=Path)
    parser.add_argument("--edge", action="append", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--query-nonce", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--relation-capacity", type=int, default=128)
    parser.add_argument("--entity-capacity", type=int, default=65536)
    parser.add_argument("--candidate-capacity", type=int, default=256)
    parser.add_argument("--prio-aggregators", type=int, default=3)
    parser.add_argument("--semantic-bucket-mode", choices=("alias", "lsh", "hybrid"), default="hybrid")
    parser.add_argument("--embedding-backend", choices=("hashing", "simgrag"), default="hashing")
    parser.add_argument("--embedding-config", type=Path)
    parser.add_argument("--embedding-model-path", type=Path)
    parser.add_argument("--embedding-device")
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--handle-key-env", default="FEDKG_PRIO_HANDLE_KEY")
    parser.add_argument("--fss-cli", type=Path, default=Path("build/fss_cli/fedkg-fss-cli"))
    parser.add_argument("--prio-cli", type=Path, default=Path("tools/prio3_cli/target/release/fedkg-prio3-cli"))
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--eval-batch-size", type=int, default=256)
    parser.add_argument(
        "--allow-local-validation-reconstruction",
        action="store_true",
        help="Acknowledge local aggregate reconstruction/ranking in this validation command.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.allow_local_validation_reconstruction:
        raise SystemExit(
            "--allow-local-validation-reconstruction is required. "
            "This command validates the hybrid design locally; production must keep "
            "Prio aggregates secret-shared into MPC/GC ranking."
        )

    command = [
        sys.executable,
        str(RUNNER),
        "--store-0",
        str(args.store_0),
        "--store-1",
        str(args.store_1),
        "--request-id",
        args.request_id,
        "--query-nonce",
        args.query_nonce,
        "--topk",
        str(args.topk),
        "--relation-capacity",
        str(args.relation_capacity),
        "--entity-capacity",
        str(args.entity_capacity),
        "--candidate-capacity",
        str(args.candidate_capacity),
        "--prio-aggregators",
        str(args.prio_aggregators),
        "--semantic-bucket-mode",
        args.semantic_bucket_mode,
        "--embedding-backend",
        args.embedding_backend,
        "--key-env",
        args.key_env,
        "--handle-key-env",
        args.handle_key_env,
        "--fss-cli",
        str(args.fss_cli),
        "--prio-cli",
        str(args.prio_cli),
        "--timeout",
        str(args.timeout),
        "--eval-batch-size",
        str(args.eval_batch_size),
        "--allow-local-reconstruction",
    ]
    for edge in args.edge:
        command.extend(["--edge", edge])
    if args.embedding_config is not None:
        command.extend(["--embedding-config", str(args.embedding_config)])
    if args.embedding_model_path is not None:
        command.extend(["--embedding-model-path", str(args.embedding_model_path)])
    if args.embedding_device is not None:
        command.extend(["--embedding-device", args.embedding_device])

    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, end="")
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, end="")
        return completed.returncode

    payload = json.loads(completed.stdout)
    payload["hybrid_backend"] = {
        "lookup": "two-non-colluding-dpf-fss-evaluators",
        "aggregation": "prio3-validated-candidate-vectors",
        "ranking": "local-validation-reconstruction",
        "production_ranking_requirement": "replace local reconstruction with MPC/GC top-k over aggregate shares",
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
