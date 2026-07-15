#!/usr/bin/env python3
"""Evaluate one native DPF share against one replicated opaque index store."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.crypto.dpf import DpfKeyShare
from src.crypto.fss_cli_backend import FssCliBackend
from src.runtime.fss_evaluator_service import (
    FssEvaluatorRequest,
    FssEvaluatorService,
    FssEvaluatorStore,
)
from src.runtime.fss_candidate_projection import CandidateProjection


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one role-separated FSS evaluator request from JSON stdin."
    )
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--evaluator-id", required=True)
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
    payload = json.loads(sys.stdin.read())
    if not isinstance(payload, dict):
        raise SystemExit("request must be a JSON object")
    request_id = payload.get("request_id")
    domain = payload.get("domain")
    key_payload = payload.get("key_share")
    projection_payload = payload.get("projection")
    if not isinstance(request_id, str) or not request_id:
        raise SystemExit("request_id must be a non-empty string")
    if domain not in ("entity", "relation", "type", "frontier"):
        raise SystemExit("domain must be entity, relation, type, or frontier")
    if not isinstance(key_payload, dict):
        raise SystemExit("key_share must be a JSON object")

    store = FssEvaluatorStore.load(args.store, expected_evaluator_id=args.evaluator_id)
    backend = FssCliBackend.from_executable(
        args.fss_cli,
        timeout_seconds=args.timeout,
        max_eval_batch_size=args.eval_batch_size,
    )
    service = FssEvaluatorService(store, backend)
    request = FssEvaluatorRequest(
        request_id=request_id,
        domain=domain,
        key_share=DpfKeyShare(args.evaluator_id, key_payload),
    )
    response = (
        service.evaluate_projected(request, CandidateProjection.from_mapping(projection_payload))
        if projection_payload is not None
        else service.evaluate(request)
    )
    print(json.dumps(response.as_dict(), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
