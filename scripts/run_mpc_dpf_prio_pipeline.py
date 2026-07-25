#!/usr/bin/env python3
"""MPC query-share bridge + DPF lookup + Prio aggregation pipeline.

This command is intentionally separate from the older FSS and MP-SPDZ commands.
It validates the practical hybrid architecture:

1. create additive shares for HMAC-encoded query graph tokens;
2. locally verify the query-share bridge, then invoke the specialized DPF/FSS
   lookup backend;
3. aggregate candidate vectors with Prio3;
4. rank locally for validation.

The production gap is explicit in the output: the query-share bridge and final
ranking are local validation stages today. The lookup and aggregation backends
remain the existing native implementations.
"""

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
from src.gateway.query_share_bridge import MpcQueryShareBridge


RUNNER = ROOT / "scripts" / "run_role_separated_secure_retrieval.py"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run MPC-style query sharing, DPF/FSS lookup, and Prio3 aggregation."
    )
    parser.add_argument("--store-0", required=True, type=Path)
    parser.add_argument("--store-1", required=True, type=Path)
    parser.add_argument("--edge", action="append", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--query-nonce", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mpc-query-parties", type=int, default=3)
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
        help="Acknowledge local query-share verification and local aggregate ranking.",
    )
    return parser.parse_args()


def parse_edges(values: list[str]) -> list[tuple[str, str, str]]:
    edges = []
    for value in values:
        parts = tuple(part.strip() for part in value.split("|"))
        if len(parts) != 3 or any(not part for part in parts):
            raise SystemExit(f"invalid --edge value: {value!r}")
        edges.append(parts)
    return edges  # type: ignore[return-value]


def main() -> int:
    args = parse_args()
    if not args.allow_local_validation_reconstruction:
        raise SystemExit(
            "--allow-local-validation-reconstruction is required. This command "
            "keeps the MPC query-share bridge and final ranking local for validation."
        )

    total_start = time.perf_counter()
    edges = parse_edges(args.edge)

    share_start = time.perf_counter()
    query_shares = MpcQueryShareBridge(
        HmacIdProvider.from_env(args.key_env),
        share_count=args.mpc_query_parties,
    ).share_edges(edges)
    share_seconds = time.perf_counter() - share_start

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

    lookup_start = time.perf_counter()
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    lookup_seconds = time.perf_counter() - lookup_start
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, end="")
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, end="")
        return completed.returncode

    payload = json.loads(completed.stdout)
    payload["hybrid_backend"] = {
        "query_share_owner": "mpc-query-committee-local-validation",
        "lookup": "two-non-colluding-dpf-fss-evaluators",
        "aggregation": "prio3-validated-candidate-vectors",
        "ranking": "local-validation-reconstruction-compatible-with-gc-topk-contract",
        "production_requirement": (
            "network-separated MPC parties should retain query shares and feed "
            "Prio aggregate shares into distributed GC/MPC top-k"
        ),
    }
    payload["mpc_query_share_bridge"] = query_shares.public_metadata()
    payload["timing_seconds"] = {
        "query_share_bridge": round(share_seconds, 6),
        "dpf_lookup_prio_aggregation_and_local_ranking": round(lookup_seconds, 6),
        "total": round(time.perf_counter() - total_start, 6),
    }

    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
