from __future__ import annotations

from collections import Counter
from typing import Any

from .config import PublicConfig


Record = tuple[int, int, int, int, int]
ZERO_RECORD: Record = (0, 0, 0, 0, 0)


def _checked_int(
    value: Any,
    *,
    name: str,
    upper_exclusive: int,
    reserve_zero: bool = False,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    lower = 1 if reserve_zero else 0
    if not lower <= value < upper_exclusive:
        raise ValueError(f"{name} must be in [{lower}, {upper_exclusive})")
    return value


def _raw_owner_buckets(
    config: PublicConfig,
    owner: str,
    edges: list[dict[str, Any]],
) -> list[list[Record]]:
    """Build the bounded clear layout without calling either serializer."""

    buckets: list[list[Record]] = [[] for _ in range(config.entity_count)]
    relation_counts: Counter[tuple[int, int]] = Counter()
    for row_number, edge in enumerate(edges, start=1):
        if not isinstance(edge, dict) or set(edge) != {
            "source",
            "relation",
            "target",
            "evidence",
            "score",
        }:
            raise ValueError(
                f"edge {row_number} must contain exactly "
                "source/relation/target/evidence/score"
            )
        try:
            source = config.entities[edge["source"]]
            target = config.entities[edge["target"]]
            relation = config.relations[edge["relation"]]
        except (KeyError, TypeError) as exc:
            raise ValueError(
                f"edge {row_number} uses an unknown ontology item"
            ) from exc
        evidence = _checked_int(
            edge["evidence"],
            name=f"edge {row_number} evidence",
            upper_exclusive=1 << config.evidence_bits,
            reserve_zero=True,
        )
        score = _checked_int(
            edge["score"],
            name=f"edge {row_number} score",
            upper_exclusive=1 << config.score_bits,
        )
        buckets[source].append((target, relation, evidence, score, 1))
        relation_counts[(source, relation)] += 1
        if relation_counts[(source, relation)] > config.relation_frontier_per_owner:
            raise ValueError(
                f"owner {owner!r} exceeds relation_fanout_per_owner at "
                f"entity slot {source}, relation ID {relation}"
            )

    for source, bucket in enumerate(buckets):
        if len(bucket) > config.fanout_per_owner:
            raise ValueError(
                f"owner {owner!r} has {len(bucket)} edges at entity slot "
                f"{source}; public bound is {config.fanout_per_owner}"
            )
        bucket.extend(
            [ZERO_RECORD] * (config.fanout_per_owner - len(bucket))
        )
    return buckets


def evaluate_cleartext(
    config: PublicConfig,
    owner_edges: dict[str, list[dict[str, Any]]],
    query: dict[str, str],
) -> list[dict[str, int]]:
    """Independent raw-edge oracle used for correctness tests only.

    This deliberately does not call ``owner_plain_vector()``,
    ``packed_owner_vector()``, ``pack_edge()``, or ``unpack_edge()``. A packing
    bug therefore cannot automatically reproduce itself in the expected
    result. It still enforces the declared public capacities because those are
    part of the implemented functionality.
    """

    if set(owner_edges) != set(config.owners):
        raise ValueError(
            "reference input must contain every configured owner exactly once"
        )
    if not isinstance(query, dict) or set(query) != {
        "source",
        "relation_1",
        "relation_2",
    }:
        raise ValueError("query must contain exactly source/relation_1/relation_2")
    try:
        source = config.entities[query["source"]]
        relation_1 = config.relations[query["relation_1"]]
        relation_2 = config.relations[query["relation_2"]]
    except (KeyError, TypeError) as exc:
        raise ValueError("query uses an unknown ontology item") from exc

    owner_buckets = {
        owner: _raw_owner_buckets(config, owner, owner_edges[owner])
        for owner in config.owners
    }

    def block(entity: int) -> list[Record]:
        return [
            edge
            for owner in config.owners
            for edge in owner_buckets[owner][entity]
        ]

    # Record the exact public slot used by stable top-k tie-breaking. The
    # compact circuit reserves a fixed relation frontier for every owner;
    # validity of those owner-specific slots remains secret.
    first_frontier: list[tuple[int, int, int, int]] = []
    if config.uses_frontier_compaction:
        relation_frontier = config.relation_frontier_per_owner
        for owner_index, owner in enumerate(config.owners):
            matches = [
                edge
                for edge in owner_buckets[owner][source]
                if edge[4] and edge[0] and edge[1] == relation_1
            ]
            if len(matches) > relation_frontier:
                raise AssertionError(
                    "validated owner relation frontier exceeds its public bound"
                )
            for local_index, (target, _, handle, score, _) in enumerate(matches):
                compact_index = owner_index * relation_frontier + local_index
                first_frontier.append((compact_index, target, handle, score))
    else:
        for first_index, (target, relation, handle, score, valid) in enumerate(
            block(source)
        ):
            if valid and target and relation == relation_1:
                first_frontier.append((first_index, target, handle, score))

    candidates: list[tuple[int, int, int, int, int]] = []
    for first_index, target, left_handle, first_score in first_frontier:
        for second_index, (
            terminal,
            relation,
            right_handle,
            second_score,
            valid,
        ) in enumerate(block(target)):
            if valid and terminal and relation == relation_2:
                candidates.append(
                    (
                        -(first_score + second_score),
                        first_index * config.block_edges + second_index,
                        left_handle,
                        right_handle,
                        terminal,
                    )
                )
    candidates.sort()

    selected: list[tuple[int, int, int, int, int]] = []
    selected_terminals: set[int] = set()
    for candidate in candidates:
        terminal = candidate[4]
        if config.deduplicate_terminal_answers and terminal in selected_terminals:
            continue
        selected.append(candidate)
        selected_terminals.add(terminal)
        if len(selected) == config.top_k:
            break

    results: list[dict[str, int]] = []
    for rank in range(config.top_k):
        if rank < len(selected):
            negative_score, _, left, right, _ = selected[rank]
            results.append(
                {
                    "valid": 1,
                    "left_evidence": left,
                    "right_evidence": right,
                    "score": -negative_score,
                }
            )
        else:
            results.append(
                {
                    "valid": 0,
                    "left_evidence": 0,
                    "right_evidence": 0,
                    "score": 0,
                }
            )
    return results
