#!/usr/bin/env python3
"""Run the isolated local Prio3 candidate aggregation pipeline."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aggregation.prio3_backend import Prio3LocalBackend
from src.aggregation.prio3_candidates import (
    CandidateContribution,
    CandidateVectorConfig,
    PrioCandidateAggregator,
    SessionCandidateHandleProvider,
)
from src.orchestration.prio_candidate_pipeline import LocalPrioCandidatePipeline
from src.runtime.secure_roles import SecureRoleTopology


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Locally validate n-aggregator Prio3 candidate aggregation."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument(
        "--topology",
        type=Path,
        help="Role topology; when provided, party and evaluator counts come from this file.",
    )
    parser.add_argument(
        "--prio-cli",
        type=Path,
        default=Path("tools/prio3_cli/target/release/fedkg-prio3-cli"),
    )
    parser.add_argument("--aggregation-backend", choices=("prio3",), default="prio3")
    parser.add_argument("--prio-aggregators", type=int)
    parser.add_argument("--lookup-evaluators", type=int)
    parser.add_argument("--capacity", type=int, required=True)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--score-scale", type=int, default=1_000_000)
    parser.add_argument("--score-bits", type=int, default=32)
    parser.add_argument("--support-bits", type=int, default=16)
    parser.add_argument("--query-nonce", required=True, help="At least 16 characters; unique per query.")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument(
        "--allow-local-reconstruction",
        action="store_true",
        help="Acknowledge that this validation command reveals aggregate values locally.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.allow_local_reconstruction:
        raise SystemExit("--allow-local-reconstruction is required for this validation backend")
    setup_key = os.environ.get("FEDKG_PRIO_HANDLE_KEY")
    if setup_key is None:
        raise SystemExit("FEDKG_PRIO_HANDLE_KEY must be set")

    payload = json.loads(args.input.read_text())
    party_ids = payload.get("party_ids")
    rows = payload.get("contributions")
    if not isinstance(party_ids, list) or not all(isinstance(item, str) for item in party_ids):
        raise SystemExit("input party_ids must be an array of strings")
    if not isinstance(rows, list):
        raise SystemExit("input contributions must be an array")
    try:
        contributions = [
            CandidateContribution(
                party_id=row["party_id"],
                candidate_id=row["candidate_id"],
                score=float(row["score"]),
                support=int(row["support"]),
            )
            for row in rows
        ]
    except (KeyError, TypeError, ValueError) as exc:
        raise SystemExit(f"invalid contribution row: {exc}") from exc

    topology = SecureRoleTopology.from_json(args.topology) if args.topology else None
    if topology is not None:
        topology.validate_contributor_ids(party_ids)
        if args.lookup_evaluators is not None and args.lookup_evaluators != len(topology.fss_evaluators):
            raise SystemExit("--lookup-evaluators does not match the role topology")
        if args.prio_aggregators is not None and args.prio_aggregators != len(topology.prio_aggregators):
            raise SystemExit("--prio-aggregators does not match the role topology")
    lookup_evaluator_count = len(topology.fss_evaluators) if topology else (args.lookup_evaluators or 2)
    prio_aggregator_count = len(topology.prio_aggregators) if topology else (args.prio_aggregators or 3)

    backend = Prio3LocalBackend.from_executable(args.prio_cli, timeout_seconds=args.timeout)
    aggregator = PrioCandidateAggregator(
        backend,
        CandidateVectorConfig(
            aggregator_count=prio_aggregator_count,
            capacity=args.capacity,
            score_scale=args.score_scale,
            score_bits=args.score_bits,
            support_bits=args.support_bits,
        ),
        SessionCandidateHandleProvider(
            setup_key.encode("utf-8"),
            args.query_nonce.encode("utf-8"),
        ),
    )
    result = LocalPrioCandidatePipeline(aggregator).run(
        party_ids,
        contributions,
        k=args.topk,
        lookup_evaluator_count=lookup_evaluator_count,
    )
    print(
        json.dumps(
            {
                "selected_candidate_ids": result.selected_candidate_ids,
                "selected_handles": result.selected_handles,
                "candidate_aggregates": [
                    {
                        "candidate_id": candidate.candidate_id,
                        "handle": candidate.handle,
                        "presence_count": candidate.presence_count,
                        "score_sum": candidate.score_sum,
                        "support_sum": candidate.support_sum,
                        "average_score": candidate.average_score,
                    }
                    for candidate in result.aggregates
                ],
                "party_count": result.aggregation.party_count,
                "prio_aggregator_count": result.aggregation.aggregator_count,
                "topology": str(args.topology) if args.topology else None,
                "security": result.security.__dict__,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
