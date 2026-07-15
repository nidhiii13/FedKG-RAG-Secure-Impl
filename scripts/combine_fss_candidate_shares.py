#!/usr/bin/env python3
"""Combine two projected FSS evaluator responses from JSON stdin."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.runtime.fss_candidate_projection import (
    ProjectedFssCoordinator,
    ProjectedFssEvaluatorResponse,
)


def main() -> int:
    payload = json.loads(sys.stdin.read())
    if not isinstance(payload, list) or len(payload) != 2:
        raise SystemExit("input must be an array containing exactly two projected responses")
    try:
        responses = [ProjectedFssEvaluatorResponse.from_mapping(item) for item in payload]
        combined = ProjectedFssCoordinator().combine(responses)
    except (TypeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(
        json.dumps(
            {
                "request_id": combined.request_id,
                "domain": combined.domain,
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

