#!/usr/bin/env python3
"""Replicate plaintext-free opaque index snapshots to N multi-party FSS stores.

Consumes opaque snapshot JSON files (as produced by the existing
scripts/export_opaque_fss_snapshots.py pipeline or written directly by
OpaqueIndexSnapshot.write) and replicates them, byte-identically, into one
store per evaluator with an N-party manifest binding (party_index,
party_count, threshold, ordered evaluator IDs).

Example:
  python3 multiparty_fss/tools/export_multiparty_snapshots.py \
    --snapshot /tmp/snapshots/partition-a.json \
    --snapshot /tmp/snapshots/partition-b.json \
    --evaluator mp_fss_0 --evaluator mp_fss_1 --evaluator mp_fss_2 \
    --output-dir /tmp/fedkg-mpfss-stores
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.party.opaque_index_snapshot import OpaqueIndexSnapshot

from multiparty_fss.params import honest_majority_threshold
from multiparty_fss.replication import (
    replicate_opaque_snapshots_multiparty,
    verify_multiparty_replicas,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replicate opaque snapshots to N multi-party FSS evaluator stores."
    )
    parser.add_argument(
        "--snapshot",
        action="append",
        required=True,
        type=Path,
        help="Opaque snapshot JSON file; repeat once per partition.",
    )
    parser.add_argument(
        "--evaluator",
        action="append",
        required=True,
        help="Evaluator role ID; repeat once per evaluator, in party-index order.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Claimed corruption bound t; default floor((N-1)/2) (honest majority).",
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    snapshots = [OpaqueIndexSnapshot.from_json(path) for path in args.snapshot]
    manifests = replicate_opaque_snapshots_multiparty(
        snapshots,
        args.evaluator,
        args.output_dir,
        threshold=args.threshold,
    )
    verify_multiparty_replicas(manifests)
    party_count = len(args.evaluator)
    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "party_count": party_count,
                "threshold": (
                    args.threshold
                    if args.threshold is not None
                    else honest_majority_threshold(party_count)
                ),
                "evaluator_ids": list(args.evaluator),
                "partition_count": len(snapshots),
                "stores": {
                    evaluator_id: str(args.output_dir / evaluator_id)
                    for evaluator_id in args.evaluator
                },
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
