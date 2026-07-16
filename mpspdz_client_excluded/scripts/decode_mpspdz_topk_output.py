#!/usr/bin/env python3
"""Decode selected MP-SPDZ top-k path slots into controlled evidence reveal."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


TOPK_LINE_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s*$")


def _load_mapping(path: Path) -> dict:
    with path.open() as handle:
        return json.load(handle)


def _parse_slots(text: str, sentinel: int) -> list[tuple[int, int]]:
    slots: list[tuple[int, int]] = []
    in_table = False
    for line in text.splitlines():
        if line.strip() == "rank selected_path_slot":
            in_table = True
            continue
        if not in_table:
            continue
        match = TOPK_LINE_RE.match(line)
        if not match:
            if slots:
                break
            continue
        rank = int(match.group(1))
        slot = int(match.group(2))
        if slot != sentinel:
            slots.append((rank, slot))
    return slots


def _path_by_slot(mapping: dict) -> dict[int, dict]:
    return {int(path["slot"]): path for path in mapping.get("paths", [])}


def _reveal_path(rank: int, path: dict) -> dict:
    return {
        "rank": rank,
        "slot": path["slot"],
        "path_id": path["path_id"],
        "edges": [
            [path["source"], path["relation_1"], path["middle"]],
            [path["middle"], path["relation_2"], path["target"]],
        ],
        "encoded_ids": {
            "source_id": path["source_id"],
            "middle_id": path["middle_id"],
            "target_id": path["target_id"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mapping", required=True, help="Path to public_mapping.json")
    parser.add_argument(
        "--mp-spdz-output",
        help="Text file containing MP-SPDZ stdout. If omitted, stdin is used unless --slot is passed.",
    )
    parser.add_argument(
        "--slot",
        action="append",
        type=int,
        help="Selected slot to reveal. Can be repeated. Bypasses output parsing.",
    )
    args = parser.parse_args()

    mapping = _load_mapping(Path(args.mapping))
    sentinel = int(mapping["path_capacity"])
    paths = _path_by_slot(mapping)

    if args.slot is not None:
        selected_slots = [(rank, slot) for rank, slot in enumerate(args.slot) if slot != sentinel]
    else:
        if args.mp_spdz_output:
            output_text = Path(args.mp_spdz_output).read_text()
        else:
            output_text = sys.stdin.read()
        selected_slots = _parse_slots(output_text, sentinel=sentinel)

    selected_paths = []
    missing_slots = []
    for rank, slot in selected_slots:
        path = paths.get(slot)
        if path is None:
            missing_slots.append({"rank": rank, "slot": slot})
            continue
        selected_paths.append(_reveal_path(rank, path))

    result = {
        "query": mapping.get("query"),
        "selected_path_count": len(selected_paths),
        "selected_paths": selected_paths,
        "missing_slots": missing_slots,
        "reveal_policy": "Only selected top-k path slots are decoded to plaintext evidence.",
    }
    print(json.dumps(result, indent=2))
    return 1 if missing_slots else 0


if __name__ == "__main__":
    raise SystemExit(main())

