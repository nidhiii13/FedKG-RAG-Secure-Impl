#!/usr/bin/env python3
"""Decode one-hop candidate slots from MP-SPDZ output."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


ROW_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$")


def _parse_candidates(output: str) -> list[tuple[int, int, int]]:
    rows = []
    in_table = False
    for line in output.splitlines():
        if line.strip() == "candidate_slot support score":
            in_table = True
            continue
        if not in_table:
            continue
        match = ROW_RE.match(line)
        if not match:
            if rows:
                break
            continue
        slot, support, score = map(int, match.groups())
        if support > 0:
            rows.append((slot, support, score))
    return rows


def decode(mapping: dict, rows: list[tuple[int, int, int]], topk: int | None) -> dict:
    candidates_by_slot = {candidate["slot"]: candidate for candidate in mapping.get("candidates", [])}
    selected = []
    for rank, (slot, support, score) in enumerate(sorted(rows, key=lambda item: (-item[1], item[2], item[0]))):
        if topk is not None and rank >= topk:
            break
        candidate = candidates_by_slot.get(slot)
        if not candidate:
            continue
        selected.append(
            {
                "rank": rank,
                "slot": slot,
                "support": support,
                "score": score,
                "display": candidate["display"],
                "entity_id": candidate["entity_id"],
            }
        )
    return {
        "query": mapping["query"],
        "selected_candidate_count": len(selected),
        "selected_candidates": selected,
        "reveal_policy": "Only candidate slots with positive aggregate support are decoded.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mapping", required=True)
    parser.add_argument("--mp-spdz-output", required=True)
    parser.add_argument("--topk", type=int)
    args = parser.parse_args()

    mapping = json.loads(Path(args.mapping).read_text())
    rows = _parse_candidates(Path(args.mp_spdz_output).read_text())
    print(json.dumps(decode(mapping, rows, args.topk), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
