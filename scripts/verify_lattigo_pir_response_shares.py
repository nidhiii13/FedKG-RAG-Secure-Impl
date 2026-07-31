#!/usr/bin/env python3
"""Verify Lattigo threshold-PIR response sharing against plaintext retrieval.

This is a test/debug tool. It locally recombines shares only to prove that the
native PIR service can emit additive shares of the selected fixed record. The
production path should feed these shares to MPC parties instead of recombining
them in Python.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.pir.lattigo_threshold_service import LattigoThresholdPirService


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify PIR response byte-share bridge.")
    parser.add_argument("--index-dir", required=True, type=Path)
    parser.add_argument("--index", required=True, type=int)
    parser.add_argument("--parties", type=int, default=3)
    parser.add_argument("--threshold", type=int, default=2)
    parser.add_argument("--share-parties", type=int, default=3)
    parser.add_argument("--share-modulus", type=int, default=65537)
    parser.add_argument("--go-routines", type=int, default=8)
    parser.add_argument(
        "--lattigo-pir",
        type=Path,
        default=Path("tools/lattigo_threshold_pir/lattigo-fedkg-threshold-pir"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    metadata = json.loads((args.index_dir / "metadata.json").read_text())
    record_size = int(metadata["record_size"])
    started = time.perf_counter()
    with LattigoThresholdPirService(
        executable=args.lattigo_pir,
        records_jsonl=args.index_dir / "records.jsonl",
        record_size=record_size,
        parties=args.parties,
        threshold=args.threshold,
        go_routines=args.go_routines,
        cwd=ROOT,
    ) as service:
        plaintext_response = service.retrieve([args.index])
        shared_response = service.retrieve_shared(
            [args.index],
            share_parties=args.share_parties,
            share_modulus=args.share_modulus,
        )

    plaintext_record = plaintext_response["records"][0]["record_json"]
    shared_record = shared_response["records"][0]
    reconstructed = combine_byte_shares(
        shared_record["record_byte_shares"],
        args.share_modulus,
    )
    reconstructed_record = decode_record(reconstructed)
    reconstructed_json = json.loads(reconstructed_record)
    payload = {
        "index": args.index,
        "record_size": record_size,
        "share_parties": args.share_parties,
        "share_modulus": args.share_modulus,
        "matches_plaintext": reconstructed_json == plaintext_record,
        "plaintext_length": len(reconstructed_record),
        "shared_record_length": shared_record.get("record_length"),
        "elapsed_seconds": time.perf_counter() - started,
        "bridge_note": (
            "This script recombines shares only for verification. In the secure pipeline, "
            "record_byte_shares should be passed as private MPC inputs."
        ),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["matches_plaintext"] else 1


def combine_byte_shares(shares: list[list[int]], modulus: int) -> list[int]:
    if not shares:
        return []
    width = len(shares[0])
    if any(len(row) != width for row in shares):
        raise ValueError("all share rows must have equal width")
    return [sum(row[index] for row in shares) % modulus for index in range(width)]


def decode_record(values: list[int]) -> str:
    out = bytearray()
    for value in values:
        if value == 0:
            break
        if value > 255:
            raise ValueError(f"decoded byte is outside uint8 range: {value}")
        out.append(value)
    return out.decode("utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
