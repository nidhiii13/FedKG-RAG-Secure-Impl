#!/usr/bin/env python3
"""Run one query through N role-separated multi-party FSS evaluator stores.

The N-party analogue of scripts/run_role_separated_fss_query.py: key
generation, dispatch to every evaluator, and combination all run in this one
trusted client-side process (a local role-separation simulation). Evaluator
count and threshold come from the store manifests and must be covered exactly
by the supplied --store flags; --party-count / --threshold, when given, are
cross-checked against the manifests and the command fails closed on mismatch.

Example:
  FEDKG_PRIO_HANDLE_KEY=... FEDKG_SETUP_KEY=... \
  python3 multiparty_fss/tools/run_multiparty_fss_query.py \
    --store /tmp/mpfss/mp_fss_0 --store /tmp/mpfss/mp_fss_1 --store /tmp/mpfss/mp_fss_2 \
    --party-count 3 --domain entity --label "Kismet" \
    --request-id req-1 --query-nonce 0123456789abcdef --capacity 8
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aggregation.prio3_candidates import SessionCandidateHandleProvider
from src.crypto.hmac_ids import HmacIdProvider
from src.party.frontier_index import frontier_token

from multiparty_fss.errors import MultipartyFssError
from multiparty_fss.orchestrator import MultipartyFssQueryOrchestrator
from multiparty_fss.requests import EVALUATION_DOMAINS
from multiparty_fss.service import (
    MultipartyFssEvaluatorService,
    MultipartyFssEvaluatorStore,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an exact query through N replicated multi-party FSS stores."
    )
    parser.add_argument(
        "--store",
        action="append",
        required=True,
        type=Path,
        help="Evaluator store directory; repeat once per evaluator.",
    )
    parser.add_argument("--party-count", type=int, default=None)
    parser.add_argument("--threshold", type=int, default=None)
    parser.add_argument("--domain", required=True, choices=EVALUATION_DOMAINS)
    query = parser.add_mutually_exclusive_group(required=True)
    query.add_argument("--alpha", help="Already encoded opaque HMAC domain point.")
    query.add_argument(
        "--label",
        help="Plaintext label encoded inside this trusted local gateway command.",
    )
    parser.add_argument("--beta", type=int, default=1)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--query-nonce", required=True)
    parser.add_argument("--capacity", required=True, type=int)
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--handle-key-env", default="FEDKG_PRIO_HANDLE_KEY")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        stores = [MultipartyFssEvaluatorStore.load(path) for path in args.store]
    except MultipartyFssError as exc:
        raise SystemExit(str(exc)) from exc
    if args.party_count is not None and args.party_count != len(stores):
        raise SystemExit(
            f"--party-count {args.party_count} does not match {len(stores)} --store flags"
        )
    manifest_counts = {store.party_count for store in stores}
    if len(manifest_counts) != 1 or next(iter(manifest_counts)) != len(stores):
        raise SystemExit(
            "supplied stores do not form one complete N-party evaluator set"
        )
    if args.threshold is not None:
        manifest_thresholds = {store.threshold for store in stores}
        if manifest_thresholds != {args.threshold}:
            raise SystemExit(
                "--threshold does not match the threshold recorded in the store manifests"
            )

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
    handles = SessionCandidateHandleProvider(
        handle_key.encode("utf-8"), args.query_nonce.encode("utf-8")
    )
    services = [MultipartyFssEvaluatorService(store) for store in stores]
    try:
        result = MultipartyFssQueryOrchestrator(services, handles).query(
            args.request_id,
            args.domain,
            alpha,
            args.capacity,
            beta=args.beta,
        )
    except MultipartyFssError as exc:
        raise SystemExit(str(exc)) from exc
    print(
        json.dumps(
            {
                "request_id": result.request_id,
                "domain": result.domain,
                "party_count": result.party_count,
                "threshold": result.threshold,
                "construction": "bgi15-mpdpf-p0",
                "output_group": "xor64",
                "candidate_values": result.candidate_values,
                "nonzero_candidate_slots": result.combined.nonzero_slots,
                "slot_count": len(result.combined.slot_handles),
                "universe_digest": result.combined.universe_digest,
                "projection_digest": result.combined.projection_digest,
                "local_role_separated_simulation": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
