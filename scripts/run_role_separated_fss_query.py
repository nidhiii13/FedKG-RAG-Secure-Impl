#!/usr/bin/env python3
"""Run one local query through two role-separated native FSS evaluators."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aggregation.prio3_candidates import SessionCandidateHandleProvider
from src.crypto.fss_cli_backend import FssCliBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.role_separated_fss_query import RoleSeparatedFssQueryOrchestrator
from src.party.frontier_index import frontier_token
from src.runtime.fss_evaluator_service import FssEvaluatorService, FssEvaluatorStore
from src.runtime.fss_projection_builder import OpaqueIndexProjectionBuilder


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an exact query through two replicated opaque FSS evaluator stores."
    )
    parser.add_argument("--store-0", required=True, type=Path)
    parser.add_argument("--store-1", required=True, type=Path)
    parser.add_argument(
        "--domain",
        required=True,
        choices=(
            "entity",
            "relation",
            "type",
            "frontier",
            "relation_bucket",
            "entity_bucket",
        ),
    )
    query = parser.add_mutually_exclusive_group(required=True)
    query.add_argument("--alpha", help="Already encoded HMAC domain point.")
    query.add_argument("--label", help="Plaintext label encoded inside this trusted local gateway command.")
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--query-nonce", required=True)
    parser.add_argument("--capacity", required=True, type=int)
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--handle-key-env", default="FEDKG_PRIO_HANDLE_KEY")
    parser.add_argument(
        "--fss-cli",
        type=Path,
        default=Path("build/fss_cli/fedkg-fss-cli"),
    )
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--eval-batch-size", type=int, default=256)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    stores = [FssEvaluatorStore.load(path) for path in (args.store_0, args.store_1)]
    if {store.evaluator_index for store in stores} != {0, 1}:
        raise SystemExit("the two stores must have evaluator indices 0 and 1")
    backend = FssCliBackend.from_executable(
        args.fss_cli,
        timeout_seconds=args.timeout,
        max_eval_batch_size=args.eval_batch_size,
    )
    services = [FssEvaluatorService(store, backend) for store in stores]

    if args.alpha:
        alpha = args.alpha
    else:
        ids = HmacIdProvider.from_env(args.key_env)
        encoders = {
            "entity": ids.entity_id,
            "relation": ids.relation_id,
            "type": ids.type_id,
            "frontier": lambda label: frontier_token(ids, label),
            "relation_bucket": ids.relation_bucket_id,
            "entity_bucket": lambda label: ids.id_for("entity_bucket", label),
        }
        alpha = encoders[args.domain](args.label)

    handle_key = os.environ.get(args.handle_key_env)
    if handle_key is None:
        raise SystemExit(f"{args.handle_key_env} must be set")
    builder = OpaqueIndexProjectionBuilder(
        stores[0].index,
        SessionCandidateHandleProvider(
            handle_key.encode("utf-8"),
            args.query_nonce.encode("utf-8"),
        ),
    )
    result = RoleSeparatedFssQueryOrchestrator(backend, services, builder).query(
        args.request_id,
        args.domain,
        alpha,
        args.capacity,
    )
    print(
        json.dumps(
            {
                "request_id": result.request_id,
                "domain": result.domain,
                "candidate_values": result.candidate_values,
                "nonzero_candidate_slots": result.combined_slots.nonzero_slots,
                "slot_count": len(result.combined_slots.slot_handles),
                "universe_digest": result.combined_slots.universe_digest,
                "projection_digest": result.combined_slots.projection_digest,
                "local_role_separated_simulation": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
