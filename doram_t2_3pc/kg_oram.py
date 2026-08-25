"""KG-specific owner preparation for the recursive read-only ORAM backend."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from .oram_layout import OwnerOramStack, build_owner_oram_stack
from .packed import pack_edge
from .relation_pages import RelationPageConfig, _grouped_edges


@dataclass(frozen=True)
class OwnerKgOram:
    owner: str
    records: list[list[int]]
    stack: OwnerOramStack


def dense_key_address(config: RelationPageConfig, entity: int, relation: int) -> int:
    """Public affine key encoding; the same expression is used on secret values."""

    return config.dense_directory_index(entity, relation)


def build_owner_adjacency_records(
    config: RelationPageConfig,
    owner: str,
    edges: list[dict[str, Any]],
) -> list[list[int]]:
    """Build one lossless fixed-width record for every ``(entity, relation)``.

    Owners remain in separate ORAMs.  Every record has ``slots_per_key`` packed
    edge fields, including all-zero padding, so a path trace cannot reveal an
    owner's contribution count.  Preparation fails rather than truncating.
    """

    grouped = _grouped_edges(config, owner, edges)
    width = config.pages.slots_per_key
    records = [
        [0] * width
        for _ in range(config.base.entity_count * config.relation_count)
    ]
    for (source, relation), values in grouped.items():
        if len(values) > width:
            raise ValueError(
                f"owner {owner!r} has {len(values)} edges at entity slot "
                f"{source}, relation ID {relation}; ORAM record width is {width}"
            )
        packed = [
            pack_edge(config.base, target, edge_relation, evidence, score, 1)
            for target, edge_relation, evidence, score in sorted(values)
        ]
        packed.extend([0] * (width - len(packed)))
        records[dense_key_address(config, source, relation)] = packed
    return records


def build_owner_kg_oram(
    config: RelationPageConfig,
    owner: str,
    edges: list[dict[str, Any]],
    *,
    chi: int = 256,
    base_threshold: int = 64,
    rng: secrets.SystemRandom | None = None,
    statistical_security_bits: int = 80,
) -> OwnerKgOram:
    records = build_owner_adjacency_records(config, owner, edges)
    if len(records) < 2:
        raise ValueError("KG ORAM logical keyspace must contain at least two records")
    stack = build_owner_oram_stack(
        records,
        chi=chi,
        base_threshold=base_threshold,
        rng=rng,
        statistical_security_bits=statistical_security_bits,
    )
    return OwnerKgOram(owner=owner, records=records, stack=stack)
