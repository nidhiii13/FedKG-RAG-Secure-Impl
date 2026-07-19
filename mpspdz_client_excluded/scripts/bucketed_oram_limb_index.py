#!/usr/bin/env python3
"""Multi-limb HMAC adjacency indexes for MP-SPDZ ORAM retrieval."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from prepare_metaqa_mpspdz_inputs import FIELD_MASK, _canonical_text
from prepare_metaqa_twohop_edge_join_mpspdz_inputs import _all_edges


ID_LIMBS = 4
LIMB_BITS = 32
ID_EFFECTIVE_BITS = ID_LIMBS * LIMB_BITS
LIMB_MASK = (1 << LIMB_BITS) - 1
EMPTY_DIRECTORY_ROW = (0,) * (ID_LIMBS * 2 + 4)
EMPTY_EDGE_ROW = (0,) * (ID_LIMBS * 3 + 2)
EMPTY_ENTITY_DIRECTORY_ROW = (0,) * (ID_LIMBS + 4)
EMPTY_RELATION_BUCKET_DIRECTORY_ROW = (0,) * (ID_LIMBS + 3)
EMPTY_RELATION_BUCKET_EDGE_ROW = (0,) * (ID_LIMBS + 1)


def next_power_of_two(value: int) -> int:
    if value < 1:
        return 1
    return 1 << (value - 1).bit_length()


def hmac_limbs(setup_key: str, namespace: str, value: str, *, limbs: int = ID_LIMBS) -> tuple[int, ...]:
    if limbs < 1 or limbs > 8:
        raise ValueError("limbs must be in [1, 8]")
    message = f"{namespace}:{_canonical_text(value)}".encode("utf-8")
    digest = hmac.new(setup_key.encode("utf-8"), message, hashlib.sha256).digest()
    return tuple(
        int.from_bytes(digest[index * 4 : (index + 1) * 4], "big") & LIMB_MASK
        for index in range(limbs)
    )


def directory_slot_limb(
    setup_key: str,
    mode: str,
    direction: int,
    entity_id: tuple[int, ...],
    relation_id: tuple[int, ...],
    capacity: int,
) -> int:
    if capacity <= 0 or capacity & (capacity - 1):
        raise ValueError("directory capacity must be a positive power of two")
    entity = ":".join(str(value) for value in entity_id)
    relation = ":".join(str(value) for value in relation_id)
    message = f"oram-directory:{mode}:{direction}:{entity}:{relation}".encode()
    digest = hmac.new(setup_key.encode(), message, hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big") & (capacity - 1)


def entity_directory_slot_limb(
    setup_key: str,
    mode: str,
    direction: int,
    entity_id: tuple[int, ...],
    capacity: int,
) -> int:
    if capacity <= 0 or capacity & (capacity - 1):
        raise ValueError("directory capacity must be a positive power of two")
    entity = ":".join(str(value) for value in entity_id)
    message = f"oram-entity-directory:{mode}:{direction}:{entity}".encode()
    digest = hmac.new(setup_key.encode(), message, hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big") & (capacity - 1)


def relation_bucket_slot_limb(
    setup_key: str,
    bucket_id: tuple[int, ...],
    capacity: int,
) -> int:
    if capacity <= 0 or capacity & (capacity - 1):
        raise ValueError("bucket directory capacity must be a positive power of two")
    bucket = ":".join(str(value) for value in bucket_id)
    message = f"oram-relation-bucket-directory:{bucket}".encode()
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
) -> dict[tuple[int, str, str], list[tuple[int, str, str, str]]]:
    grouped: dict[tuple[int, str, str], list[tuple[int, str, str, str]]] = defaultdict(list)
    for direction, source, relation, target in rows:
        grouped[(direction, _canonical_text(source), _canonical_text(relation))].append(
            (direction, source, relation, target)
        )
    return dict(grouped)


def _group_rows_by_entity(
    rows: Iterable[tuple[int, str, str, str]],
) -> dict[tuple[int, str], list[tuple[int, str, str, str]]]:
    grouped: dict[tuple[int, str], list[tuple[int, str, str, str]]] = defaultdict(list)
    for direction, source, relation, target in rows:
        grouped[(direction, _canonical_text(source))].append((direction, source, relation, target))
    return dict(grouped)


def _build_source_directory(
    setup_key: str,
    grouped: dict[tuple[int, str, str], list[tuple[int, str, str, str]]],
    *,
    load_factor: float,
    capacity: int | None = None,
    read_padding: int = 64,
) -> tuple[list[tuple[int, ...]], list[tuple[int, ...]], dict[str, dict], int]:
    if not 0 < load_factor <= 0.75:
        raise ValueError("directory load factor must be in (0, 0.75]")
    minimum_capacity = next_power_of_two(max(2, math.ceil(len(grouped) / load_factor)))
    capacity = capacity or minimum_capacity
    if capacity < minimum_capacity or capacity & (capacity - 1):
        raise ValueError(
            f"directory capacity {capacity} must be a power of two >= {minimum_capacity}"
        )
    directory = [EMPTY_DIRECTORY_ROW] * capacity
    edges: list[tuple[int, ...]] = []
    vault: dict[str, dict] = {}
    max_probe = 0

    for (direction, entity, relation), group in sorted(grouped.items()):
        entity_id = hmac_limbs(setup_key, "entity", entity)
        relation_id = hmac_limbs(setup_key, "relation", relation)
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
                    *hmac_limbs(setup_key, "entity", source),
                    *hmac_limbs(setup_key, "relation", edge_relation),
                    *hmac_limbs(setup_key, "entity", target),
                    handle,
                    1,
                )
            )

        base = directory_slot_limb(setup_key, "source", direction, entity_id, relation_id, capacity)
        for probe in range(capacity):
            slot = (base + probe) & (capacity - 1)
            if directory[slot] == EMPTY_DIRECTORY_ROW:
                directory[slot] = (*entity_id, *relation_id, direction, offset, len(group), 1)
                max_probe = max(max_probe, probe + 1)
                break
        else:
            raise ValueError("hashed adjacency directory is full")

    max_degree = max((len(group) for group in grouped.values()), default=1)
    edges.extend([EMPTY_EDGE_ROW] * max(max_degree, read_padding))
    return directory, edges, vault, max_probe


def _build_entity_directory(
    setup_key: str,
    grouped: dict[tuple[int, str], list[tuple[int, str, str, str]]],
    *,
    load_factor: float,
    capacity: int | None = None,
    read_padding: int = 64,
) -> tuple[list[tuple[int, ...]], list[tuple[int, ...]], dict[str, dict], int]:
    if not 0 < load_factor <= 0.75:
        raise ValueError("directory load factor must be in (0, 0.75]")
    minimum_capacity = next_power_of_two(max(2, math.ceil(len(grouped) / load_factor)))
    capacity = capacity or minimum_capacity
    if capacity < minimum_capacity or capacity & (capacity - 1):
        raise ValueError(
            f"entity directory capacity {capacity} must be a power of two >= {minimum_capacity}"
        )
    directory = [EMPTY_ENTITY_DIRECTORY_ROW] * capacity
    edges: list[tuple[int, ...]] = []
    vault: dict[str, dict] = {}
    max_probe = 0

    for (direction, entity), group in sorted(grouped.items()):
        entity_id = hmac_limbs(setup_key, "entity", entity)
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
                    *hmac_limbs(setup_key, "entity", source),
                    *hmac_limbs(setup_key, "relation", edge_relation),
                    *hmac_limbs(setup_key, "entity", target),
                    handle,
                    1,
                )
            )

        base = entity_directory_slot_limb(setup_key, "entity-source", direction, entity_id, capacity)
        for probe in range(capacity):
            slot = (base + probe) & (capacity - 1)
            if directory[slot] == EMPTY_ENTITY_DIRECTORY_ROW:
                directory[slot] = (*entity_id, direction, offset, len(group), 1)
                max_probe = max(max_probe, probe + 1)
                break
        else:
            raise ValueError("hashed entity directory is full")

    max_degree = max((len(group) for group in grouped.values()), default=1)
    edges.extend([EMPTY_EDGE_ROW] * max(max_degree, read_padding))
    return directory, edges, vault, max_probe


def _build_relation_bucket_directory(
    setup_key: str,
    bucket_to_relations: dict[str, set[str]],
    *,
    load_factor: float,
    capacity: int | None = None,
    read_padding: int = 8,
) -> tuple[list[tuple[int, ...]], list[tuple[int, ...]], int]:
    if not 0 < load_factor <= 0.75:
        raise ValueError("bucket load factor must be in (0, 0.75]")
    minimum_capacity = next_power_of_two(max(2, math.ceil(len(bucket_to_relations) / load_factor)))
    capacity = capacity or minimum_capacity
    if capacity < minimum_capacity or capacity & (capacity - 1):
        raise ValueError(
            f"relation bucket directory capacity {capacity} must be a power of two >= {minimum_capacity}"
        )
    directory = [EMPTY_RELATION_BUCKET_DIRECTORY_ROW] * capacity
    edges: list[tuple[int, ...]] = []
    max_probe = 0

    for bucket, relations in sorted(bucket_to_relations.items()):
        bucket_id = hmac_limbs(setup_key, "relation_bucket", bucket)
        offset = len(edges)
        for relation in sorted(relations):
            edges.append((*hmac_limbs(setup_key, "relation", relation), 1))
        base = relation_bucket_slot_limb(setup_key, bucket_id, capacity)
        for probe in range(capacity):
            slot = (base + probe) & (capacity - 1)
            if directory[slot] == EMPTY_RELATION_BUCKET_DIRECTORY_ROW:
                directory[slot] = (*bucket_id, offset, len(relations), 1)
                max_probe = max(max_probe, probe + 1)
                break
        else:
            raise ValueError("hashed relation bucket directory is full")

    max_degree = max((len(relations) for relations in bucket_to_relations.values()), default=1)
    edges.extend([EMPTY_RELATION_BUCKET_EDGE_ROW] * max(max_degree, read_padding))
    return directory, edges, max_probe


def build_party_index(
    graph: dict,
    setup_key: str,
    *,
    allowed_relations: set[str] | None = None,
    load_factor: float = 0.5,
    source_directory_capacity: int | None = None,
    read_padding: int = 64,
) -> dict:
    rows = logical_edges(graph, allowed_relations)
    grouped = _group_rows(rows)
    source_directory, source_edges, vault, source_probe = _build_source_directory(
        setup_key,
        grouped,
        load_factor=load_factor,
        capacity=source_directory_capacity,
        read_padding=read_padding,
    )
    return {
        "format": "fedkg-mpspdz-oram-limb-index-v1",
        "id_limbs": ID_LIMBS,
        "source_directory": source_directory,
        "source_edges": source_edges,
        "evidence_vault": vault,
        "stats": {
            "logical_edges": len(rows),
            "source_keys": len(grouped),
            "source_directory_capacity": len(source_directory),
            "source_edge_capacity": len(source_edges),
            "source_max_degree": max((len(v) for v in grouped.values()), default=0),
            "source_probe_limit": source_probe,
            "read_padding": read_padding,
            "id_effective_bits": ID_EFFECTIVE_BITS,
        },
    }


def build_private_semantic_party_index(
    graph: dict,
    setup_key: str,
    *,
    relation_bucket_fn,
    allowed_relations: set[str] | None = None,
    load_factor: float = 0.5,
    entity_directory_capacity: int | None = None,
    relation_bucket_directory_capacity: int | None = None,
    read_padding: int = 64,
    relation_candidate_padding: int = 8,
) -> dict:
    rows = logical_edges(graph, allowed_relations)
    entity_grouped = _group_rows_by_entity(rows)
    entity_directory, entity_edges, vault, entity_probe = _build_entity_directory(
        setup_key,
        entity_grouped,
        load_factor=load_factor,
        capacity=entity_directory_capacity,
        read_padding=read_padding,
    )

    present_relations = {
        _canonical_text(relation)
        for _, _, relation, _ in rows
        if allowed_relations is None or _canonical_text(relation) in allowed_relations
    }
    bucket_to_relations: dict[str, set[str]] = defaultdict(set)
    for relation in present_relations:
        for bucket in relation_bucket_fn(relation):
            bucket_to_relations[bucket].add(relation)
    relation_bucket_directory, relation_bucket_edges, bucket_probe = _build_relation_bucket_directory(
        setup_key,
        dict(bucket_to_relations),
        load_factor=load_factor,
        capacity=relation_bucket_directory_capacity,
        read_padding=relation_candidate_padding,
    )
    return {
        "format": "fedkg-mpspdz-oram-limb-private-semantic-index-v1",
        "id_limbs": ID_LIMBS,
        "entity_directory": entity_directory,
        "entity_edges": entity_edges,
        "relation_bucket_directory": relation_bucket_directory,
        "relation_bucket_edges": relation_bucket_edges,
        "evidence_vault": vault,
        "stats": {
            "logical_edges": len(rows),
            "entity_keys": len(entity_grouped),
            "entity_directory_capacity": len(entity_directory),
            "entity_edge_capacity": len(entity_edges),
            "entity_max_degree": max((len(v) for v in entity_grouped.values()), default=0),
            "entity_probe_limit": entity_probe,
            "relation_bucket_keys": len(bucket_to_relations),
            "relation_bucket_directory_capacity": len(relation_bucket_directory),
            "relation_bucket_edge_capacity": len(relation_bucket_edges),
            "relation_bucket_max_degree": max((len(v) for v in bucket_to_relations.values()), default=0),
            "relation_bucket_probe_limit": bucket_probe,
            "read_padding": read_padding,
            "relation_candidate_padding": relation_candidate_padding,
            "id_effective_bits": ID_EFFECTIVE_BITS,
        },
    }


def write_private_semantic_party_index(index: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    private_payload = {key: value for key, value in index.items() if key != "evidence_vault"}
    index_path = output_dir / "oram_limb_private_semantic_index.json"
    vault_path = output_dir / "evidence_vault.json"
    index_path.write_text(json.dumps(private_payload))
    vault_path.write_text(json.dumps(index["evidence_vault"]))
    index_path.chmod(0o600)
    vault_path.chmod(0o600)


def read_private_semantic_party_index(index_dir: Path) -> dict:
    payload = json.loads((index_dir / "oram_limb_private_semantic_index.json").read_text())
    if payload.get("format") != "fedkg-mpspdz-oram-limb-private-semantic-index-v1":
        raise ValueError(f"unsupported private semantic ORAM limb index format in {index_dir}")
    if int(payload.get("id_limbs", 0)) != ID_LIMBS:
        raise ValueError(f"unsupported limb count in {index_dir}")
    return payload


def write_party_index(index: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    private_payload = {key: value for key, value in index.items() if key != "evidence_vault"}
    index_path = output_dir / "oram_limb_index.json"
    vault_path = output_dir / "evidence_vault.json"
    index_path.write_text(json.dumps(private_payload))
    vault_path.write_text(json.dumps(index["evidence_vault"]))
    index_path.chmod(0o600)
    vault_path.chmod(0o600)


def read_party_index(index_dir: Path) -> dict:
    payload = json.loads((index_dir / "oram_limb_index.json").read_text())
    if payload.get("format") != "fedkg-mpspdz-oram-limb-index-v1":
        raise ValueError(f"unsupported ORAM limb index format in {index_dir}")
    if int(payload.get("id_limbs", 0)) != ID_LIMBS:
        raise ValueError(f"unsupported limb count in {index_dir}")
    return payload
