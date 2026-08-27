#!/usr/bin/env python3
"""Evaluate one multi-party FSS key share against one replicated opaque store.

One process = one evaluator role (the N-party analogue of
scripts/run_fss_evaluator.py). Reads a single MpFssEvaluatorRequest JSON
object on stdin, validates every binding against this store's manifest, and
writes a single MpFssEvaluatorResponse JSON object to stdout. All validation
failures exit nonzero with a message that never contains key material.
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
from multiparty_fss.requests import MpFssEvaluatorRequest
from multiparty_fss.service import (
    MultipartyFssEvaluatorService,
    MultipartyFssEvaluatorStore,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one multi-party FSS evaluator request from JSON stdin."
    )
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--evaluator-id", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        payload = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        raise SystemExit("request must be valid JSON")
    try:
        store = MultipartyFssEvaluatorStore.load(
            args.store, expected_evaluator_id=args.evaluator_id
        )
        request = MpFssEvaluatorRequest.from_dict(payload)
        response = MultipartyFssEvaluatorService(store).evaluate(request)
    except MultipartyFssError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(response.to_dict(), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
