#!/usr/bin/env python3
"""Query-independent hashed adjacency indexes for MP-SPDZ ORAM retrieval."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from prepare_metaqa_mpspdz_inputs import FIELD_MASK, _canonical_text, _hmac_int
from prepare_metaqa_twohop_edge_join_mpspdz_inputs import _all_edges


EMPTY_DIRECTORY_ROW = (0, 0, 0, 0, 0, 0)
EMPTY_EDGE_ROW = (0, 0, 0, 0, 0)


def next_power_of_two(value: int) -> int:
    if value < 1:
        return 1
    return 1 << (value - 1).bit_length()


def directory_slot(
    setup_key: str,
    mode: str,
    direction: int,
    entity_id: int,
    relation_id: int,
    capacity: int,
) -> int:
    if capacity <= 0 or capacity & (capacity - 1):
        raise ValueError("directory capacity must be a positive power of two")
    message = f"oram-directory:{mode}:{direction}:{entity_id}:{relation_id}".encode()
    digest = hmac.new(setup_key.encode(), message, hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big") & (capacity - 1)


def probe_slots(base_slot: int, capacity: int, probe_limit: int) -> list[int]:
    return [(base_slot + probe) & (capacity - 1) for probe in range(probe_limit)]


def evidence_handle(setup_key: str, source: str, relation: str, target: str) -> int:
    message = ":".join(
        (
            "evidence",
            _canonical_text(source),
            _canonical_text(relation),
            _canonical_text(target),
        )
    ).encode()
    digest = hmac.new(setup_key.encode(), message, hashlib.sha256).digest()
    value = int.from_bytes(digest[:8], "big") & FIELD_MASK
    return value or 1


def logical_edges(
    graph: dict,
    allowed_relations: set[str] | None = None,
) -> list[tuple[int, str, str, str]]:
    """Return both directed views without using any online query value."""

    rows: set[tuple[int, str, str, str]] = set()
    for source, relation, target in _all_edges(graph):
        source, relation, target = str(source), str(relation), str(target)
        if allowed_relations is not None and _canonical_text(relation) not in allowed_relations:
            continue
        rows.add((0, source, relation, target))
        rows.add((1, target, relation, source))
    return sorted(
        rows,
        key=lambda row: (
            row[0],
            _canonical_text(row[1]),
            _canonical_text(row[2]),
            _canonical_text(row[3]),
        ),
    )


def _group_rows(
    rows: Iterable[tuple[int, str, str, str]],
    *,
    mode: str,
) -> dict[tuple[int, str, str], list[tuple[int, str, str, str]]]:
    grouped: dict[tuple[int, str, str], list[tuple[int, str, str, str]]] = defaultdict(list)
    for direction, source, relation, target in rows:
        entity = source if mode == "source" else target
        grouped[(direction, _canonical_text(entity), _canonical_text(relation))].append(
            (direction, source, relation, target)
        )
    return dict(grouped)


def _build_directory(
    setup_key: str,
    mode: str,
    grouped: dict[tuple[int, str, str], list[tuple[int, str, str, str]]],
    *,
    load_factor: float,
    capacity: int | None = None,
    read_padding: int = 64,
) -> tuple[list[tuple[int, int, int, int, int, int]], list[tuple[int, int, int, int, int]], dict[str, dict], int]:
    if not 0 < load_factor <= 0.75:
        raise ValueError("directory load factor must be in (0, 0.75]")
    minimum_capacity = next_power_of_two(max(2, math.ceil(len(grouped) / load_factor)))
    capacity = capacity or minimum_capacity
    if capacity < minimum_capacity or capacity & (capacity - 1):
        raise ValueError(
            f"directory capacity {capacity} must be a power of two >= {minimum_capacity}"
        )
    directory = [EMPTY_DIRECTORY_ROW] * capacity
    edges: list[tuple[int, int, int, int, int]] = []
    vault: dict[str, dict] = {}
    max_probe = 0

    for (direction, entity, relation), group in sorted(grouped.items()):
        entity_id = _hmac_int(setup_key, "entity", entity)
        relation_id = _hmac_int(setup_key, "relation", relation)
        offset = len(edges)
        for _, source, edge_relation, target in group:
            handle = evidence_handle(setup_key, source, edge_relation, target)
            previous = vault.get(str(handle))
            evidence = {"source": source, "relation": edge_relation, "target": target}
            if previous is not None and previous != evidence:
                raise ValueError("evidence-handle collision")
            vault[str(handle)] = evidence
            edges.append(
                (
                    _hmac_int(setup_key, "entity", source),
                    _hmac_int(setup_key, "relation", edge_relation),
                    _hmac_int(setup_key, "entity", target),
                    handle,
                    1,
                )
            )

        base = directory_slot(setup_key, mode, direction, entity_id, relation_id, capacity)
        for probe in range(capacity):
            slot = (base + probe) & (capacity - 1)
            if directory[slot] == EMPTY_DIRECTORY_ROW:
                directory[slot] = (entity_id, relation_id, direction, offset, len(group), 1)
                max_probe = max(max_probe, probe + 1)
                break
        else:
            raise ValueError("hashed adjacency directory is full")

    # Secret offset+i reads remain in range even for the final adjacency list.
    max_degree = max((len(group) for group in grouped.values()), default=1)
    edges.extend([EMPTY_EDGE_ROW] * max(max_degree, read_padding))
    return directory, edges, vault, max_probe


def build_party_index(
    graph: dict,
    setup_key: str,
    *,
    allowed_relations: set[str] | None = None,
    load_factor: float = 0.5,
    source_directory_capacity: int | None = None,
    target_directory_capacity: int | None = None,
    read_padding: int = 64,
) -> dict:
    rows = logical_edges(graph, allowed_relations)
    source_grouped = _group_rows(rows, mode="source")
    target_grouped = _group_rows(rows, mode="target")
    source_directory, source_edges, source_vault, source_probe = _build_directory(
        setup_key,
        "source",
        source_grouped,
        load_factor=load_factor,
        capacity=source_directory_capacity,
        read_padding=read_padding,
    )
    target_directory, target_edges, target_vault, target_probe = _build_directory(
        setup_key,
        "target",
        target_grouped,
        load_factor=load_factor,
        capacity=target_directory_capacity,
        read_padding=read_padding,
    )
    vault = dict(source_vault)
    vault.update(target_vault)
    return {
        "format": "fedkg-mpspdz-oram-index-v1",
        "source_directory": source_directory,
        "target_directory": target_directory,
        "source_edges": source_edges,
        "target_edges": target_edges,
        "evidence_vault": vault,
        "stats": {
            "logical_edges": len(rows),
            "source_keys": len(source_grouped),
            "target_keys": len(target_grouped),
            "source_directory_capacity": len(source_directory),
            "target_directory_capacity": len(target_directory),
            "source_edge_capacity": len(source_edges),
            "target_edge_capacity": len(target_edges),
            "source_max_degree": max((len(v) for v in source_grouped.values()), default=0),
            "target_max_degree": max((len(v) for v in target_grouped.values()), default=0),
            "source_probe_limit": source_probe,
            "target_probe_limit": target_probe,
            "read_padding": read_padding,
        },
    }


def write_party_index(index: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    private_payload = {key: value for key, value in index.items() if key != "evidence_vault"}
    index_path = output_dir / "oram_index.json"
    vault_path = output_dir / "evidence_vault.json"
    index_path.write_text(json.dumps(private_payload))
    vault_path.write_text(json.dumps(index["evidence_vault"]))
    index_path.chmod(0o600)
    vault_path.chmod(0o600)


def read_party_index(index_dir: Path) -> dict:
    payload = json.loads((index_dir / "oram_index.json").read_text())
    if payload.get("format") != "fedkg-mpspdz-oram-index-v1":
        raise ValueError(f"unsupported ORAM index format in {index_dir}")
    return payload
