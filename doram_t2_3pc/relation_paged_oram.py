"""Relation-paged recursive-ORAM composition.

This module is deliberately separate from both executable backends:

* :mod:`relation_pages` remains the linear-scan relation-paged backend;
* :mod:`kg_oram` remains the wide-record KG-ORAM experiment.

The composition here reuses the *actual* owner relation-page layout.  For each
owner it builds two independently randomized recursive read-only ORAM stacks:

1. a directory ORAM whose logical key is ``(entity, relation)`` and whose
   payload is the packed ``(page_base, page_count)`` descriptor;
2. a page-pool ORAM whose payload is one fixed-size packed adjacency page.

A logical KG lookup always performs one directory access followed by exactly
``pages_per_key`` page accesses.  Offsets beyond the secret page count access
reserved dummy page zero.  Consequently neither the number of pages belonging
to a key nor an absent owner contribution changes the public access schedule.

This file implements owner preparation, an executable cleartext model of the
two recursive accesses, an end-to-end oracle, and a public cost report.  It is
the integration boundary for a generated MP-SPDZ circuit; it does not by itself
claim that the dual-stack access has run under MPC.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from .oram_layout import OwnerOramStack, build_owner_oram_stack, stack_lookup
from .packed import unpack_edge
from .relation_pages import (
    EMPTY_DESCRIPTOR,
    OwnerPageLayout,
    RelationPageConfig,
    build_owner_page_layout,
)


@dataclass(frozen=True)
class OwnerRelationPagedOram:
    """One owner's relation directory and page pool in separate ORAMs."""

    owner: str
    layout: OwnerPageLayout
    directory_stack: OwnerOramStack
    page_stack: OwnerOramStack


def _require_dense_layout(config: RelationPageConfig) -> None:
    # The current type-blocked layout has a primary directory plus a hashed
    # residual.  Supporting it needs a third ORAM and a private tag check; do
    # not silently give it dense semantics.
    if config.uses_hybrid_directory or config.pages.uses_compact_directory:
        raise ValueError(
            "relation-paged ORAM currently requires the dense affine directory; "
            "type-blocked/compact residual lookup is not yet integrated"
        )
    if config.directory_rows < 2:
        raise ValueError("relation-paged ORAM directory must contain at least two rows")


def build_owner_relation_paged_oram(
    config: RelationPageConfig,
    owner: str,
    edges: list[dict[str, Any]],
    *,
    chi: int = 256,
    base_threshold: int = 64,
    rng: secrets.SystemRandom | None = None,
    statistical_security_bits: int = 80,
) -> OwnerRelationPagedOram:
    """Build both recursive stacks from the existing lossless page builder.

    All page-capacity and frontier checks are inherited from
    :func:`build_owner_page_layout`; this function never rebuilds, truncates, or
    reorders edge records independently.
    """

    _require_dense_layout(config)
    layout = build_owner_page_layout(config, owner, edges)
    directory_records = [[descriptor] for descriptor in layout.directory]
    page_records = [list(page) for page in layout.pages]
    directory_stack = build_owner_oram_stack(
        directory_records,
        chi=chi,
        base_threshold=base_threshold,
        rng=rng,
        statistical_security_bits=statistical_security_bits,
    )
    page_stack = build_owner_oram_stack(
        page_records,
        chi=chi,
        base_threshold=base_threshold,
        rng=rng,
        statistical_security_bits=statistical_security_bits,
    )
    return OwnerRelationPagedOram(
        owner=owner,
        layout=layout,
        directory_stack=directory_stack,
        page_stack=page_stack,
    )


def read_owner_relation_pages(
    config: RelationPageConfig,
    owner: OwnerRelationPagedOram,
    entity: int,
    relation: int,
) -> list[int]:
    """Model the fixed-schedule dual-ORAM read for one owner.

    The returned vector is page-major and has exactly ``slots_per_key`` packed
    fields.  In MPC, ``entity``, ``relation``, the descriptor, and every page
    address are secret values; this cleartext model only fixes the semantics.
    """

    _require_dense_layout(config)
    if owner.owner not in config.base.owners:
        raise ValueError("ORAM owner is not in the public federation")
    address = config.dense_directory_index(entity, relation)
    descriptor_record = stack_lookup(owner.directory_stack, address)
    if descriptor_record is None or len(descriptor_record) != 1:
        raise AssertionError("directory ORAM did not return one descriptor")
    descriptor = descriptor_record[0]
    page_base, page_count = config.unpack_descriptor(descriptor)
    if not 0 <= page_count <= config.pages.pages_per_key:
        raise AssertionError("directory ORAM returned an invalid page count")
    if page_count and not 1 <= page_base < config.pages.page_budget:
        raise AssertionError("directory ORAM returned an invalid non-empty page base")
    if page_base + page_count > config.pages.page_budget:
        raise AssertionError("directory ORAM page window exceeds the public budget")

    result: list[int] = []
    for offset in range(config.pages.pages_per_key):
        # A circuit uses active.if_else(page_base + offset, 0).  Page zero is a
        # real all-zero ORAM record, so inactive reads have the same shape.
        active = offset < page_count
        page_address = page_base + offset if active else 0
        page = stack_lookup(owner.page_stack, page_address)
        if page is None or len(page) != config.pages.page_size:
            raise AssertionError("page ORAM returned an invalid page record")
        result.extend(page)
    if len(result) != config.pages.slots_per_key:
        raise AssertionError("dual-ORAM lookup returned the wrong fixed width")
    return result


def evaluate_relation_paged_oram_cleartext(
    config: RelationPageConfig,
    owner_edges: dict[str, list[dict[str, Any]]],
    query: dict[str, str],
    *,
    chi: int = 256,
    base_threshold: int = 64,
    statistical_security_bits: int = 80,
) -> list[dict[str, int]]:
    """End-to-end oracle using only the two ORAM stacks for every KG read."""

    _require_dense_layout(config)
    if set(owner_edges) != set(config.base.owners):
        raise ValueError("owner input must contain every configured owner exactly once")
    if not isinstance(query, dict) or set(query) != {
        "source", "relation_1", "relation_2"
    }:
        raise ValueError("query must contain exactly source/relation_1/relation_2")
    try:
        source = config.base.entities[query["source"]]
        relation_1 = config.base.relations[query["relation_1"]]
        relation_2 = config.base.relations[query["relation_2"]]
    except (KeyError, TypeError) as exc:
        raise ValueError("query uses an unknown ontology item") from exc

    owners = {
        name: build_owner_relation_paged_oram(
            config,
            name,
            owner_edges[name],
            chi=chi,
            base_threshold=base_threshold,
            statistical_security_bits=statistical_security_bits,
        )
        for name in config.base.owners
    }

    def read_key(entity: int, relation: int, *, compact: bool):
        width = (
            config.pages.effective_frontier_per_owner
            if compact else config.pages.slots_per_key
        )
        result: list[tuple[int, int, int, int]] = []
        for owner_name in config.base.owners:
            packed = read_owner_relation_pages(
                config, owners[owner_name], entity, relation
            )
            slots: list[tuple[int, int, int, int]] = []
            for value in packed:
                if value == 0:
                    slots.append((0, 0, 0, 0))
                    continue
                target, edge_relation, evidence, score, valid = unpack_edge(
                    config.base, value
                )
                slots.append(
                    (target, edge_relation, evidence, score)
                    if valid and target else (0, 0, 0, 0)
                )
            if compact:
                matches = [slot for slot in slots if slot[0]]
                if len(matches) > width:
                    raise AssertionError("owner frontier exceeds its checked bound")
                slots = matches + [(0, 0, 0, 0)] * (width - len(matches))
            result.extend(slots)
        return result

    frontier = read_key(source, relation_1, compact=True)
    if config.pages.uses_global_frontier:
        matches = [slot for slot in frontier if slot[0]]
        width = config.pages.global_frontier
        if len(matches) > width:
            raise AssertionError("global frontier exceeds its checked bound")
        frontier = matches + [(0, 0, 0, 0)] * (width - len(matches))

    second_width = len(config.base.owners) * config.pages.slots_per_key
    candidates: list[tuple[int, int, int, int, int]] = []
    for first_index, (middle, _, left_handle, first_score) in enumerate(frontier):
        if not middle:
            continue
        for second_index, (terminal, _, right_handle, second_score) in enumerate(
            read_key(middle, relation_2, compact=False)
        ):
            if terminal:
                candidates.append((
                    -(first_score + second_score),
                    first_index * second_width + second_index,
                    left_handle,
                    right_handle,
                    terminal,
                ))
    candidates.sort()

    selected: list[tuple[int, int, int, int, int]] = []
    seen: set[int] = set()
    for candidate in candidates:
        terminal = candidate[4]
        if config.base.deduplicate_terminal_answers and terminal in seen:
            continue
        selected.append(candidate)
        seen.add(terminal)
        if len(selected) == config.base.top_k:
            break
    output: list[dict[str, int]] = []
    for rank in range(config.base.top_k):
        if rank < len(selected):
            negative_score, _, left, right, _ = selected[rank]
            output.append({
                "valid": 1,
                "left_evidence": left,
                "right_evidence": right,
                "score": -negative_score,
            })
        else:
            output.append({
                "valid": 0,
                "left_evidence": 0,
                "right_evidence": 0,
                "score": 0,
            })
    return output


def _stack_path_entries(stack: OwnerOramStack) -> int:
    return len(stack.base) + sum(
        (tree.depth + 1) * tree.bucket_size for tree in stack.levels
    )


def relation_paged_oram_cost_report(
    config: RelationPageConfig,
    owner: OwnerRelationPagedOram,
    *,
    query_count: int,
) -> dict[str, int | float | bool]:
    """Report setup size and online access shape without mixing the two."""

    if query_count < 1:
        raise ValueError("query_count must be positive")
    owner_count = len(config.base.owners)
    frontier = config.pages.frontier_slots(owner_count)
    directory_reads_per_owner = query_count * (1 + frontier)
    page_reads_per_owner = directory_reads_per_owner * config.pages.pages_per_key
    directory_path = _stack_path_entries(owner.directory_stack)
    page_path = _stack_path_entries(owner.page_stack)
    online_path_entries_all_owners = owner_count * (
        directory_reads_per_owner * directory_path
        + page_reads_per_owner * page_path
    )
    shared_values_per_owner = (
        owner.directory_stack.shared_values() + owner.page_stack.shared_values()
    )
    # Comparable logical rows touched by the current linear backend. Packing
    # owners into one field can reduce products, so this is an entry-shape
    # comparison rather than a prediction of triples or bytes.
    linear_rows_all_owners = query_count * (1 + frontier) * (
        config.directory_rows
        + owner_count * config.pages.pages_per_key * config.pages.page_budget
    )
    return {
        "query_count": query_count,
        "owners": owner_count,
        "directory_logical_records": owner.directory_stack.size,
        "page_logical_records": owner.page_stack.size,
        "directory_reads_per_owner": directory_reads_per_owner,
        "page_reads_per_owner": page_reads_per_owner,
        "directory_path_entries_per_read": directory_path,
        "page_path_entries_per_read": page_path,
        "online_path_entries_all_owners": online_path_entries_all_owners,
        "linear_backend_rows_for_same_schedule": linear_rows_all_owners,
        "entry_touch_reduction": round(
            linear_rows_all_owners / online_path_entries_all_owners, 2
        ),
        "shared_values_per_owner": shared_values_per_owner,
        "shared_values_per_server_all_owners": shared_values_per_owner * owner_count,
        "setup_is_linear": True,
        "online_access_is_sublinear_in_directory_and_page_pool": True,
        "fresh_read_only_epoch_required": True,
    }


def planned_relation_paged_oram_cost_report(
    config: RelationPageConfig,
    *,
    query_count: int,
    chi: int = 256,
    base_threshold: int = 64,
    statistical_security_bits: int = 80,
) -> dict[str, int | float | bool | list[dict[str, int]]]:
    """Compute a data-independent capacity gate from public layout parameters.

    This deliberately reports structural work rather than predicting seconds or
    bytes.  In particular, the current replay-hiding read stash scans all prior
    public access slots at every recursive level.  That term is quadratic in an
    epoch's access count even though each fresh tree-path read is sublinear in
    the number of stored records.
    """

    if query_count < 1:
        raise ValueError("query_count must be positive")
    # Local import avoids making the owner-layout module depend on the circuit
    # generator during construction.
    from .relation_paged_oram_program import planned_shape

    shape = planned_shape(
        config,
        query_count,
        chi=chi,
        base_threshold=base_threshold,
        statistical_security_bits=statistical_security_bits,
    )
    owner_count = len(config.base.owners)
    frontier = config.pages.frontier_slots(owner_count)

    def stack_report(stack) -> tuple[list[dict[str, int]], int, int]:
        levels: list[dict[str, int]] = []
        path_entries = stack.base_entries
        for index, level in enumerate(stack.levels):
            touched = (level.depth + 1) * level.bucket_size
            path_entries += touched
            levels.append({
                "level": index,
                "logical_records": level.size,
                "bucket_size": level.bucket_size,
                "depth": level.depth,
                "path_entries": touched,
                "physical_slots": level.slots,
                "field_count": level.field_count,
            })
        # 0 + 1 + ... + (A-1), once at every recursive tree level.
        stash_comparisons = (
            len(stack.levels)
            * stack.max_accesses
            * (stack.max_accesses - 1)
            // 2
        )
        return levels, path_entries, stash_comparisons

    directory_levels, directory_path, directory_stash = stack_report(shape.directory)
    page_levels, page_path, page_stash = stack_report(shape.pages)
    path_entries_all_owners = owner_count * (
        shape.directory.max_accesses * directory_path
        + shape.pages.max_accesses * page_path
    )
    stash_comparisons_all_owners = owner_count * (directory_stash + page_stash)
    linear_rows_all_owners = query_count * (1 + frontier) * (
        config.directory_rows
        + owner_count * config.pages.pages_per_key * config.pages.page_budget
    )
    return {
        "query_count": query_count,
        "owners": owner_count,
        "frontier": frontier,
        "directory_logical_records": config.directory_rows,
        "page_logical_records": config.pages.pool_rows,
        "directory_accesses_per_owner": shape.directory.max_accesses,
        "page_accesses_per_owner": shape.pages.max_accesses,
        "directory_levels": directory_levels,
        "page_levels": page_levels,
        "directory_path_entries_per_logical_read": directory_path,
        "page_path_entries_per_logical_read": page_path,
        "online_path_entries_all_owners": path_entries_all_owners,
        "replay_stash_comparisons_all_owners": stash_comparisons_all_owners,
        "linear_backend_rows_for_same_schedule": linear_rows_all_owners,
        "path_entry_reduction_ignoring_stash": round(
            linear_rows_all_owners / path_entries_all_owners, 3
        ),
        "shared_values_per_owner": shape.owner_values,
        "shared_values_per_server_all_owners": shape.owner_values * owner_count,
        "query_values_per_server": query_count * 3,
        "setup_is_linear": True,
        "tree_path_access_is_sublinear_in_database_size": True,
        "current_epoch_stash_is_quadratic_in_access_count": True,
        "fresh_read_only_epoch_required": True,
    }
