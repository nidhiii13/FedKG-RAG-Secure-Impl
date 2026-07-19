#!/usr/bin/env python3
"""Decode selected split edge-pair slots from MP-SPDZ output."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


PAIR_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s*$")


def _parse_slots(output: str | None, sentinel: int) -> list[int]:
    if not output:
        return []
    slots: list[int] = []
    in_table = False
    for line in output.splitlines():
        if line.strip() == "rank selected_split_pair_slot":
            in_table = True
            continue
        if not in_table:
            continue
        match = PAIR_RE.match(line)
        if not match:
            if slots:
                break
            continue
        slot = int(match.group(2))
        if slot != sentinel:
            slots.append(slot)
    return slots


def _table_row(tables: list[dict], rows_per_party: int, global_slot: int) -> dict:
    party_index = global_slot // rows_per_party
    row_index = global_slot % rows_per_party
    return tables[party_index]["rows"][row_index]


def decode(mapping: dict, selected_pair_slots: list[int]) -> dict:
    right_total = mapping["right_total_rows"]
    selected_paths = []
    for rank, pair_slot in enumerate(selected_pair_slots):
        left_slot = pair_slot // right_total
        right_slot = pair_slot % right_total
        left = _table_row(mapping["left_tables"], mapping["left_rows_per_party"], left_slot)
        right = _table_row(mapping["right_tables"], mapping["right_rows_per_party"], right_slot)
        if left.get("padding") or right.get("padding"):
            continue
        selected_paths.append(
            {
                "rank": rank,
                "pair_slot": pair_slot,
                "left_edge_slot": left_slot,
                "right_edge_slot": right_slot,
                "edges": [
                    [left["source"], left["relation"], left["target"]],
                    [right["source"], right["relation"], right["target"]],
                ],
                "encoded_ids": {
                    "source_id": left["source_id"],
                    "middle_id": left["target_id"],
                    "target_id": right["target_id"],
                },
            }
        )
    return {
        "query": mapping["query"],
        "selected_path_count": len(selected_paths),
        "selected_paths": selected_paths,
        "reveal_policy": "Only selected top-k split edge-pair slots are decoded to plaintext evidence.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mapping", required=True)
    parser.add_argument("--mp-spdz-output")
    parser.add_argument("--slot", action="append", type=int, default=[])
    args = parser.parse_args()

    mapping = json.loads(Path(args.mapping).read_text())
    slots = list(args.slot)
    if args.mp_spdz_output:
        slots.extend(_parse_slots(Path(args.mp_spdz_output).read_text(), mapping["pair_capacity"]))
    print(json.dumps(decode(mapping, slots), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
