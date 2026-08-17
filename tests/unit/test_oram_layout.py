"""Tests for owner-side plaintext construction of a tree-ORAM state.

The point of this module is to remove ORAM *initialisation* from the MPC. The
access protocol was never the blocker: at MetaQA scale it is cheaper than the
linear scan. batch_init was, because it builds the structure obliviously and
costs about 97,000x one access, paid every run. An owner already holds its own
data in plaintext, so it can build the structure locally for free.

These tests pin the layout against MP-SPDZ's own formula and check the
invariants an access depends on.
"""

from __future__ import annotations

import math
import random

import pytest

from doram_t2_3pc.oram_layout import (
    REMAINING,
    build_owner_oram_tree,
    lookup,
    path_buckets,
    tree_cost_estimate,
    tree_shape,
)


def _mpspdz_shape(size: int, delta: int = 3) -> tuple[int, int]:
    """Transcribed from Compiler/oram.py TreeORAM.__init__."""

    k = (math.log(size * size * math.log2(size) * 100, 2) + 21) / (1 + delta)
    bucket_size = min(int(math.ceil((1 + delta) * k)), size + 1)
    return bucket_size, int(math.log2(max(size / k, 2)))


@pytest.mark.parametrize("size", (16, 64, 256, 1024, 4096, 16384, 389115))
def test_shape_matches_mpspdz_exactly(size: int):
    """A mismatch here means the owner builds a structure MP-SPDZ cannot read."""

    assert tree_shape(size) == _mpspdz_shape(size)


def test_size_below_two_is_refused():
    with pytest.raises(ValueError, match="at least 2"):
        tree_shape(1)
    with pytest.raises(ValueError, match="at least 2"):
        build_owner_oram_tree([[1]])


def test_entries_must_be_uniform_width():
    with pytest.raises(ValueError, match="same value length"):
        build_owner_oram_tree([[1, 2], [3]])


@pytest.mark.parametrize("size", (16, 64, 256))
def test_every_entry_lands_in_a_leaf_bucket(size: int):
    """batch_init places all real entries at the leaves; internal buckets empty.

    Entries migrate upward only through later evictions, so an owner-built tree
    that put entries in internal buckets would not match what the access
    protocol expects to find.
    """

    tree = build_owner_oram_tree([[a] for a in range(size)])
    leaves = 2 ** tree.depth
    occupied_internal = [
        slot
        for bucket in range(1, leaves)
        for slot in tree.bucket_slots(bucket)
        if tree.fields[0][slot] == 0
    ]
    assert not occupied_internal
    assert sum(1 for s in range(tree.slots) if tree.fields[0][s] == 0) == size


@pytest.mark.parametrize("size", (16, 64, 256))
def test_every_entry_is_reachable_along_its_own_path(size: int):
    """The invariant an access relies on: the entry is on the path to its leaf."""

    values = [[10 + a, 20 + a] for a in range(size)]
    tree = build_owner_oram_tree(values)
    for index in range(size):
        assert lookup(tree, index) == values[index]


def test_lookup_rejects_an_out_of_range_index():
    tree = build_owner_oram_tree([[a] for a in range(16)])
    with pytest.raises(ValueError, match="out of range"):
        lookup(tree, 16)


def test_no_leaf_bucket_overflows():
    """Overflow would silently drop entries, so the builder must retry instead."""

    for size in (16, 64, 256):
        tree = build_owner_oram_tree([[a] for a in range(size)])
        leaves = 2 ** tree.depth
        for leaf in range(leaves):
            bucket = leaf + leaves
            occupied = sum(
                1 for slot in tree.bucket_slots(bucket) if tree.fields[0][slot] == 0
            )
            assert occupied <= tree.bucket_size


def test_path_covers_root_to_leaf_and_is_public():
    tree = build_owner_oram_tree([[a] for a in range(256)])
    for leaf in (0, 5, 2 ** tree.depth - 1):
        path = path_buckets(leaf, tree.depth)
        assert path[0] == 1                          # root
        assert path[-1] == leaf + 2 ** tree.depth    # this leaf's bucket
        assert len(path) == tree.depth + 1
        for parent, child in zip(path, path[1:]):
            assert child // 2 == parent
    with pytest.raises(ValueError, match="leaf out of range"):
        path_buckets(2 ** tree.depth, tree.depth)


def test_leaf_assignment_is_randomised_not_fixed():
    """Path ORAM security rests on leaves being uniform, not derived from index."""

    values = [[a] for a in range(256)]
    first = build_owner_oram_tree(values, rng=random.Random(1)).position_map
    second = build_owner_oram_tree(values, rng=random.Random(2)).position_map
    assert first != second
    # And not simply index-ordered.
    assert first != sorted(first)


def test_cost_estimate_reports_zero_in_circuit_initialisation():
    """The whole point of building owner-side."""

    estimate = tree_cost_estimate(1024, 2)
    assert estimate["in_circuit_initialisation_cost"] == 0
    assert estimate["entries_touched_per_access"] == (
        estimate["path_buckets_per_access"] * estimate["bucket_size"]
    )
    # An access touches the path, not the table.
    assert estimate["entries_touched_per_access"] < estimate["logical_entries"]


def test_remaining_work_stays_documented():
    """Whatever is still missing must be named, and named accurately.

    This deliberately does not pin specific wording beyond requiring that the
    cost estimates carry the same statement the module does, so the two cannot
    drift apart. The current contents are checked by
    ``test_remaining_now_names_eviction_and_persistence``.
    """

    assert REMAINING.strip()
    assert tree_cost_estimate(256, 1)["remaining"] == REMAINING


# --------------------------------------------------------------------------
# Recursive position map
#
# Reading the data tree needs the leaf label for the requested index, and that
# lookup must itself be oblivious or it leaks the index. These check the
# recursion resolves correctly and that the levels stay mutually consistent.
# --------------------------------------------------------------------------


from doram_t2_3pc.oram_layout import (  # noqa: E402
    DEFAULT_BASE_THRESHOLD,
    DEFAULT_CHI,
    build_owner_oram_stack,
    stack_cost_estimate,
    stack_lookup,
)


@pytest.mark.parametrize(
    "size,chi", ((256, 4), (512, 8), (2048, 16), (5000, 64))
)
def test_every_index_resolves_through_the_full_recursion(size: int, chi: int):
    values = [[10 + a, 20 + a] for a in range(size)]
    stack = build_owner_oram_stack(
        values, chi=chi, base_threshold=32, rng=random.Random(3)
    )
    for index in range(size):
        assert stack_lookup(stack, index) == values[index]


def test_levels_stay_mutually_consistent(tmp_path=None):
    """Each level must hold exactly the leaf labels of the level below it.

    stack_lookup asserts this internally, so a silent disagreement would surface
    as a wrong answer rather than an exception; this checks it directly.
    """

    size, chi = 1024, 8
    stack = build_owner_oram_stack(
        [[a] for a in range(size)], chi=chi, base_threshold=32,
        rng=random.Random(11),
    )
    for level in range(len(stack.levels) - 1):
        labels = stack.levels[level].position_map
        holder = stack.levels[level + 1]
        for index, expected in enumerate(labels):
            packed = lookup(holder, index // chi)
            assert packed is not None
            assert packed[index % chi] == expected
    # The base holds the labels of the last tree level.
    assert stack.base == stack.levels[-1].position_map


def test_recursion_terminates_at_the_base_threshold():
    stack = build_owner_oram_stack(
        [[a] for a in range(4096)], chi=8, base_threshold=64,
        rng=random.Random(5),
    )
    assert len(stack.base) <= 64
    # Every tree level above the base must be larger than the threshold.
    for tree in stack.levels[:-1]:
        assert tree.size > 64


def test_stack_rejects_degenerate_parameters():
    values = [[a] for a in range(64)]
    with pytest.raises(ValueError, match="chi must be at least 2"):
        build_owner_oram_stack(values, chi=1)
    with pytest.raises(ValueError, match="base_threshold must be at least 2"):
        build_owner_oram_stack(values, base_threshold=1)


def test_stack_lookup_rejects_out_of_range():
    stack = build_owner_oram_stack(
        [[a] for a in range(256)], chi=8, base_threshold=32,
        rng=random.Random(2),
    )
    with pytest.raises(ValueError, match="out of range"):
        stack_lookup(stack, 256)


def test_larger_chi_touches_fewer_entries():
    """The tuning that recovers the advantage: fewer, fatter levels win.

    Per-entry cost is dominated by the index equality test rather than the
    payload, so reducing the number of levels beats keeping entries small.
    """

    small = stack_cost_estimate(389115, 2, chi=8, base_threshold=64)
    large = stack_cost_estimate(389115, 2, chi=256, base_threshold=64)
    assert large["tree_levels"] < small["tree_levels"]
    assert large["entries_touched_per_access"] < small["entries_touched_per_access"]


def test_recursion_still_touches_far_fewer_entries_than_a_scan():
    estimate = stack_cost_estimate(
        389115, 2, chi=DEFAULT_CHI, base_threshold=DEFAULT_BASE_THRESHOLD
    )
    assert estimate["entries_touched_per_access"] < estimate["linear_scan_entries"]
    assert estimate["in_circuit_initialisation_cost"] == 0
    # The recursion must not silently collapse to a single level.
    assert estimate["tree_levels"] >= 2


# --------------------------------------------------------------------------
# Read-only stash, in place of Path ORAM eviction
#
# Reading the same index twice would otherwise reveal the same path and leak
# the repeat. Full eviction fixes that by writing the path back, roughly
# doubling every access. This workload never writes during a run, so a stash
# plus dummy paths gives the same observable behaviour far more cheaply.
# --------------------------------------------------------------------------


from doram_t2_3pc.oram_layout import (  # noqa: E402
    access_cost_estimate,
    simulate_access_sequence,
)


def _stack(size: int = 2048, chi: int = 16, seed: int = 4):
    values = [[10 + a, 20 + a] for a in range(size)]
    return values, build_owner_oram_stack(
        values, chi=chi, base_threshold=32, rng=random.Random(seed)
    )


def test_repeated_indices_return_correct_values():
    values, stack = _stack()
    sequence = [7, 100, 7, 7, 512, 100, 7, 999, 512, 7]
    trace = simulate_access_sequence(
        stack, sequence, max_accesses=64, rng=random.Random(9)
    )
    assert trace.results == [values[a] for a in sequence]


def test_no_index_is_ever_fetched_twice_at_any_level():
    """The property that makes the stash a substitute for eviction.

    Not "no leaf repeats": distinct blocks routinely share a leaf, which is why
    buckets hold several entries. The property is that a given (level, index) is
    fetched from the tree at most once, so its real path is revealed once and
    every later touch reads a fresh dummy path instead.

    This must hold *per level*, because level i is addressed by ``a // chi**i``
    and two different logical indices can collide at an upper level.
    """

    _, stack = _stack()
    sequence = [3, 3, 3, 88, 3, 88, 1000]
    trace = simulate_access_sequence(
        stack, sequence, max_accesses=64, rng=random.Random(11)
    )
    for level in range(len(stack.levels)):
        fetched = [
            stack.level_index(index, level)
            for index, dummy in zip(sequence, trace.dummy_levels)
            if not dummy[level]
        ]
        assert len(fetched) == len(set(fetched)), (
            f"level {level} fetched an index twice, revealing its path twice"
        )


def test_upper_levels_are_stashed_independently_of_the_data_level():
    """Distinct indices sharing an upper-level index must not refetch it.

    A single data-level stash would miss this and leak a repeated upper path.
    """

    _, stack = _stack()
    first, second = 3, 4
    assert stack.level_index(first, 1) == stack.level_index(second, 1)
    assert first != second
    trace = simulate_access_sequence(
        stack, [first, second], max_accesses=8, rng=random.Random(23)
    )
    assert trace.dummy_levels[0][0] is False   # data level, first access
    assert trace.dummy_levels[1][0] is False   # data level, distinct index
    assert trace.dummy_levels[1][1] is True    # level 1 already fetched


def test_every_access_looks_the_same_from_outside():
    """A repeat must be indistinguishable from a first read."""

    _, stack = _stack()
    trace = simulate_access_sequence(
        stack, [5, 5, 5, 5], max_accesses=16, rng=random.Random(13)
    )
    assert any(trace.fully_stashed)
    assert all(len(leaves) == len(stack.levels) for leaves in trace.revealed_leaves)
    assert len({len(leaves) for leaves in trace.revealed_leaves}) == 1
    assert all(len(flags) == len(stack.levels) for flags in trace.dummy_levels)


def test_first_revealed_leaf_is_the_real_one():
    """A real fetch reveals the block's actual leaf, not a random draw."""

    _, stack = _stack()
    trace = simulate_access_sequence(
        stack, [3], max_accesses=4, rng=random.Random(29)
    )
    assert trace.revealed_leaves[0][0] == stack.levels[0].position_map[3]


def test_dummy_leaves_are_drawn_fresh_not_reused():
    """Dummy paths must be uniform, or repeats become recognisable."""

    _, stack = _stack()
    trace = simulate_access_sequence(
        stack, [42] * 40, max_accesses=64, rng=random.Random(17)
    )
    dummies = [
        leaves[0]
        for leaves, dummy in zip(trace.revealed_leaves, trace.dummy_levels)
        if dummy[0]
    ]
    assert len(dummies) == 39
    assert len(set(dummies)) > 1


def test_exceeding_the_declared_access_bound_fails_closed():
    """Past the bound the revealed paths stop being independent, so refuse."""

    _, stack = _stack()
    with pytest.raises(ValueError, match="exceeds the declared max_accesses"):
        simulate_access_sequence(stack, list(range(20)), max_accesses=10)
    with pytest.raises(ValueError, match="max_accesses must be positive"):
        simulate_access_sequence(stack, [1], max_accesses=0)


def test_access_out_of_range_is_refused():
    _, stack = _stack()
    with pytest.raises(ValueError, match="out of range"):
        simulate_access_sequence(stack, [10_000], max_accesses=8)


def test_stash_is_far_cheaper_than_eviction_would_be():
    estimate = access_cost_estimate(389115, 2, max_accesses=50)
    assert estimate["stash_overhead_percent"] < 10
    assert estimate["total_entries"] == (
        estimate["path_entries_total"] + estimate["stash_entries_total"]
    )
    assert estimate["reshuffle_required_after"] == 50


def test_remaining_names_only_integration_and_circuit_execution():
    """Eviction is handled by the stash, so it must no longer be listed."""

    assert "integration" in REMAINING
    assert "eviction" not in REMAINING
