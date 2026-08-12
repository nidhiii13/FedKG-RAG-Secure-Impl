from __future__ import annotations

from typing import Any

from .config import EDGE_FIELDS, PublicConfig
from .prepare import owner_plain_vector


def evaluate_cleartext(
    config: PublicConfig,
    owner_edges: dict[str, list[dict[str, Any]]],
    query: dict[str, str],
) -> list[dict[str, int]]:
    """Cleartext specification used only for correctness tests, never deployment."""
    if set(owner_edges) != set(config.owners):
        raise ValueError("reference input must contain every configured owner exactly once")
    vectors = {
        owner: owner_plain_vector(config, owner, owner_edges[owner]) for owner in config.owners
    }
    source = config.entities[query["source"]]
    relation_1 = config.relations[query["relation_1"]]
    relation_2 = config.relations[query["relation_2"]]
    width = config.fanout_per_owner * len(EDGE_FIELDS)

    def block(entity: int) -> list[tuple[int, int, int, int, int]]:
        result = []
        for owner in config.owners:
            values = vectors[owner]
            start = entity * width
            for edge in range(config.fanout_per_owner):
                offset = start + edge * len(EDGE_FIELDS)
                result.append(tuple(values[offset : offset + len(EDGE_FIELDS)]))
        return result

    candidates = []
    for first_index, first in enumerate(block(source)):
        target, relation, left_handle, first_score, valid = first
        second = block(target if valid and relation == relation_1 else 0)
        for second_index, edge in enumerate(second):
            _, next_relation, right_handle, second_score, next_valid = edge
            if valid and next_valid and relation == relation_1 and next_relation == relation_2:
                candidates.append(
                    (
                        -(first_score + second_score),
                        first_index * config.block_edges + second_index,
                        left_handle,
                        right_handle,
                    )
                )
    candidates.sort()
    results = []
    for rank in range(config.top_k):
        if rank < len(candidates):
            negative_score, _, left, right = candidates[rank]
            results.append(
                {
                    "valid": 1,
                    "left_evidence": left,
                    "right_evidence": right,
                    "score": -negative_score,
                }
            )
        else:
            results.append({"valid": 0, "left_evidence": 0, "right_evidence": 0, "score": 0})
    return results
