#!/usr/bin/env python3
"""Controlled reveal for selected evidence handles from the ORAM MPC path."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


OUTPUT_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$")


def parse_handles(output: str) -> list[tuple[int, int]]:
    handles: list[tuple[int, int]] = []
    in_table = False
    for line in output.splitlines():
        if line.strip() == "rank left_evidence_handle right_evidence_handle":
            in_table = True
            continue
        if not in_table:
            continue
        match = OUTPUT_RE.match(line)
        if not match:
            if handles:
                break
            continue
        left, right = int(match.group(2)), int(match.group(3))
        if left:
            handles.append((left, right))
    return handles


def _load_vaults(mapping: dict) -> list[dict]:
    root = Path(mapping["index_dir"])
    return [
        json.loads((root / party["party_id"] / "evidence_vault.json").read_text())
        for party in mapping["data_parties"]
    ]


def _resolve(handle: int, vaults: list[dict]) -> dict | None:
    if handle == 0:
        return None
    matches = [vault[str(handle)] for vault in vaults if str(handle) in vault]
    if not matches:
        raise ValueError(f"selected evidence handle {handle} is absent from all party vaults")
    if any(match != matches[0] for match in matches[1:]):
        raise ValueError(f"selected evidence handle {handle} resolves inconsistently")
    return matches[0]


def decode(mapping: dict, handles: list[tuple[int, int]]) -> dict:
    vaults = _load_vaults(mapping)
    paths = []
    for rank, (left_handle, right_handle) in enumerate(handles):
        left = _resolve(left_handle, vaults)
        right = _resolve(right_handle, vaults)
        edges = [[left["source"], left["relation"], left["target"]]]
        if right is not None:
            edges.append([right["source"], right["relation"], right["target"]])
        paths.append(
            {
                "rank": rank,
                "edges": edges,
                "evidence_handles": [left_handle] + ([right_handle] if right_handle else []),
            }
        )
    return {
        "query": mapping["query"],
        "selected_path_count": len(paths),
        "selected_paths": paths,
        "reveal_policy": (
            "Only evidence handles selected inside MPC are resolved against party-local vaults; "
            "party ownership is not included in the output."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mapping", required=True)
    parser.add_argument("--mp-spdz-output", required=True)
    args = parser.parse_args()
    mapping = json.loads(Path(args.mapping).read_text())
    handles = parse_handles(Path(args.mp_spdz_output).read_text())
    print(json.dumps(decode(mapping, handles), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
