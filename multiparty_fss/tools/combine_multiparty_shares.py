#!/usr/bin/env python3
"""Combine exactly N multi-party FSS evaluator responses from JSON stdin.

The N-party analogue of scripts/combine_fss_candidate_shares.py. The expected
party count and threshold are EXPLICIT configuration (--party-count,
--threshold): they are never inferred from how many responses arrive, so a
dropped or injected response fails closed instead of silently redefining the
protocol.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from multiparty_fss.errors import MultipartyFssError
from multiparty_fss.params import honest_majority_threshold
from multiparty_fss.requests import MpFssCoordinator, MpFssEvaluatorResponse


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Combine exactly N projected multi-party FSS evaluator responses."
    )
    parser.add_argument("--party-count", required=True, type=int)
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Claimed corruption bound t; default floor((N-1)/2) (honest majority).",
    )
    parser.add_argument("--request-id", default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    threshold = (
        args.threshold
        if args.threshold is not None
        else honest_majority_threshold(args.party_count)
    )
    try:
        payload = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        raise SystemExit("input must be valid JSON")
    if not isinstance(payload, list):
        raise SystemExit("input must be a JSON array of evaluator responses")
    try:
        responses = [MpFssEvaluatorResponse.from_dict(item) for item in payload]
        combined = MpFssCoordinator(args.party_count, threshold).combine(
            responses, expected_request_id=args.request_id
        )
    except MultipartyFssError as exc:
        raise SystemExit(str(exc)) from exc
    print(
        json.dumps(
            {
                "request_id": combined.request_id,
                "domain": combined.domain,
                "party_count": args.party_count,
                "threshold": threshold,
                "keygen_id": combined.keygen_id,
                "universe_digest": combined.universe_digest,
                "projection_digest": combined.projection_digest,
                "slot_handles": list(combined.slot_handles),
                "candidate_values": combined.values,
                "nonzero_candidate_slots": combined.nonzero_slots,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
