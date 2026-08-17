"""The compact directory layout, and the sparsity below which it is a loss.

The headline result here is negative and must stay test-enforced: sizing the
directory to the key count instead of the keyspace is *not* a general win. It
pays for itself only once the dense keyspace is tens of times larger than the
number of keys, and below that the tag comparison it requires costs more than
the padding it removes.
"""

from __future__ import annotations

import pytest

from doram_t2_3pc.compact_directory import (
    HASH_WORD_BITS,
    MULTIPLIER,
    CompactDirectoryPlan,
    bucket_of,
    dense_products,
    key_tag,
    lookup_products,
    measure_load,
    plan_capacity,
)


def test_bucket_count_must_be_a_power_of_two():
    """The circuit reads the index out of a bit slice, which needs 2^k."""

    for bad in (0, 3, 6, 100, 1000):
        with pytest.raises(ValueError, match="power of two"):
            bucket_of(1, bad)
    for good in (1, 2, 64, 4096):
        assert 0 <= bucket_of(1, good) < good


def test_hash_truncates_the_product_before_taking_high_bits():
    """Regression: the mod-then-shift order is the whole hash.

    Taking the high bits of the *untruncated* product returns the high bits of
    a small input, which is zero for every realistic key -- every key lands in
    bucket 0 and the directory degenerates to one bucket sized for all of it.
    This asserts the spread that the correct order produces.
    """

    for buckets in (8, 64, 256):
        used = {bucket_of(tag, buckets) for tag in range(1, 20001)}
        assert len(used) == buckets, (
            f"only {len(used)} of {buckets} buckets reachable -- the product is "
            "probably not being truncated to HASH_WORD_BITS before shifting"
        )

    # And state the broken formula explicitly so it cannot creep back.
    width = 6
    broken = {((tag * MULTIPLIER) >> (HASH_WORD_BITS + 40 - width)) for tag in range(1, 5000)}
    assert broken == {0}, "the guard above is only meaningful if this is degenerate"


def test_hash_spreads_sequential_and_strided_keys():
    """Real key sets are structured: a hub's keys are consecutive tags, and a
    single relation across many entities is an arithmetic progression of stride
    relation_count. Both must spread."""

    buckets = 64
    ideal = 3000 / buckets
    for stride in (1, 18, 1117, 3800):
        loads: dict[int, int] = {}
        for step in range(3000):
            b = bucket_of(1 + step * stride, buckets)
            loads[b] = loads.get(b, 0) + 1
        assert max(loads.values()) < 4 * ideal, (
            f"stride {stride} concentrates: max load {max(loads.values())} "
            f"against ideal {ideal:.0f}"
        )


def test_key_tag_is_never_zero_and_rejects_bad_relations():
    """Zero marks an empty slot, so no real key may collide with it."""

    assert key_tag(0, 1, 18) == 1
    for relation in (0, 19, -1):
        with pytest.raises(ValueError, match="relation"):
            key_tag(5, relation, 18)
    with pytest.raises(ValueError, match="non-negative"):
        key_tag(-1, 1, 18)


def test_measure_load_is_per_owner_not_federation_wide():
    """Owner i only ever writes its own columns, so capacity is sized per owner.

    A federation-wide count would demand capacity for keys two owners both hold,
    which they store separately -- and would also require the owners to compare
    key sets, which they must never do.
    """

    shared = [key_tag(e, 1, 4) for e in range(1, 40)]
    worst, per_owner = measure_load({"a": shared, "b": list(shared)}, 8)
    assert per_owner[0] == per_owner[1]
    assert worst == per_owner[0], "worst must be the per-owner max, not their sum"


def test_plan_sizes_slots_to_the_measured_maximum():
    tags = {f"o{i}": [key_tag(e, 1 + e % 4, 4) for e in range(1 + i, 400, 3)]
            for i in range(3)}
    plan = plan_capacity(tags, frontier_addresses=9)
    assert plan.slots == plan.max_load
    assert plan.headroom == 0
    assert plan.total_slots >= plan.total_keys
    assert plan.slack >= 1.0
    # A plan is only usable if every owner's worst bucket fits.
    worst, _ = measure_load(tags, plan.buckets)
    assert worst <= plan.slots


# The layouts actually measured, with the plan plan_capacity chose for each.
# Pinned as data so the verdict is the cost model's on real shapes, rather than
# whatever a synthetic key set happens to produce.
#  label, entity_count, relation_count, owners, frontier, buckets, slots, keys
MEASURED = [
    ("metaqa eval", 6573, 18, 3, 3, 128, 96, 17360),
    ("webqsp n=20", 217, 376, 5, 15, 32, 34, 2984),
    ("webqsp eval", 1529, 1117, 5, 15, 64, 101, 25242),
    ("webqsp full", 203027, 7600, 5, 15, 256, 687, 780394),
]


def _pair(row):
    label, entities, relations, owners, frontier, buckets, slots, keys = row
    plan = CompactDirectoryPlan(buckets=buckets, slots=slots, owner_count=owners,
                                max_load=slots, total_keys=keys)
    compact = lookup_products(plan, frontier_addresses=frontier)
    dense = dense_products(entities, relations, frontier_addresses=frontier,
                           folded=True)
    return dense, compact, entities * relations / keys


@pytest.mark.parametrize("row", MEASURED, ids=lambda r: r[0])
def test_compact_pays_only_at_high_sparsity(row):
    """The central negative result: this layout is not a general improvement.

    It removes padding but adds a tag comparison per fetched slot. Below roughly
    40x sparsity the comparison costs more than the padding saved, and on every
    fixture small enough to execute in MPC the compact directory is SLOWER.
    """

    dense, compact, sparsity = _pair(row)
    wins = dense > compact
    assert wins == (sparsity > 40), (
        f"{row[0]}: sparsity {sparsity:.1f}, dense {dense:,}, compact {compact:,} "
        "-- the crossover moved; re-measure before quoting either side"
    )


def test_metaqa_is_the_recorded_loss():
    """MetaQA has 18 relations, so its dense table is already nearly full."""

    dense, compact, sparsity = _pair(MEASURED[0])
    assert sparsity < 10
    assert compact > dense
    assert dense / compact == pytest.approx(0.73, abs=0.02)


def test_full_scale_webqsp_is_the_case_that_motivates_it():
    dense, compact, sparsity = _pair(MEASURED[3])
    assert sparsity > 1000
    assert dense / compact == pytest.approx(100, rel=0.05)


def test_planner_reproduces_the_recorded_webqsp_slack():
    """plan_capacity on a balanced 5-owner key set of the measured size should
    land near the slack the real WebQSP fixture produced (1.28)."""

    import random

    rng = random.Random(11)
    per_owner = 25242 // 5
    tags = {f"o{i}": [rng.randrange(1, 1529 * 1117) for _ in range(per_owner)]
            for i in range(5)}
    plan = plan_capacity(tags, frontier_addresses=15)
    assert 1.1 <= plan.slack <= 1.7, f"slack {plan.slack} away from the measured 1.28"


def test_dense_baseline_is_the_folded_circuit_not_the_unfolded_one():
    """Comparing against the unfolded cost would overstate the gain ~8x."""

    folded = dense_products(1000, 500, frontier_addresses=15, folded=True)
    unfolded = dense_products(1000, 500, frontier_addresses=15, folded=False)
    assert unfolded > folded * 5
    # The default must be the honest baseline.
    assert dense_products(1000, 500, frontier_addresses=15) == folded


def test_slack_reported_with_the_plan():
    plan = CompactDirectoryPlan(buckets=64, slots=10, owner_count=5,
                                max_load=10, total_keys=1000)
    assert plan.total_slots == 3200
    assert plan.slack == 3.2
    assert plan.as_dict()["slack"] == 3.2


# --------------------------------------------------------------------------
# Capacity must be derivable from public inputs alone
# --------------------------------------------------------------------------


def test_public_bound_does_not_depend_on_the_keys():
    """The whole point: same public inputs -> same s, whatever the keys are.

    plan_capacity sizes s to the measured worst-case load, which makes s a public
    parameter derived from private data. This asserts the alternative really is
    data-independent, because that is the property the leakage argument rests on.
    """

    from doram_t2_3pc.compact_directory import public_capacity_bound

    first = public_capacity_bound(5048, 64, 5)
    second = public_capacity_bound(5048, 64, 5)
    assert first == second
    # Two federations with the same key COUNT get the same s even though their
    # measured maxima differ.
    clustered = {f"o{i}": [1 + j * 64 for j in range(200)] for i in range(5)}
    spread = {f"o{i}": [key_tag(e, 1 + e % 7, 7) for e in range(1, 201)]
              for i in range(5)}
    measured_clustered, _ = measure_load(clustered, 16)
    measured_spread, _ = measure_load(spread, 16)
    assert public_capacity_bound(200, 16, 5) >= max(
        measured_clustered, measured_spread
    ), "the public bound must cover both distributions"


def test_public_bound_is_larger_than_measured_and_the_gap_narrows():
    """Not leaking costs padding, and the cost falls as the key count grows."""

    from doram_t2_3pc.compact_directory import public_capacity_bound

    cases = [(200, 16, 19), (5048, 64, 101), (156079, 256, 687)]
    gaps = []
    for keys, buckets, measured in cases:
        bound = public_capacity_bound(keys, buckets, 5)
        assert bound > measured, (
            f"bound {bound} must exceed the measured max {measured}"
        )
        gaps.append(bound / measured)
    assert gaps[0] > gaps[-1], "the padding premium should shrink with scale"
    assert gaps[-1] < 1.5


def test_public_bound_holds_empirically():
    """A bound that the data exceeds would drop edges, not just cost slack."""

    import random

    rng = random.Random(3)
    from doram_t2_3pc.compact_directory import public_capacity_bound

    keys, buckets = 5048, 64
    bound = public_capacity_bound(keys, buckets, 5)
    worst = 0
    for _ in range(12):
        counts: dict[int, int] = {}
        for _ in range(keys):
            slot = rng.randrange(1, 10 ** 9) % buckets
            counts[slot] = counts.get(slot, 0) + 1
        worst = max(worst, max(counts.values()))
    assert worst <= bound


def test_public_bound_searches_above_the_mean():
    """Regression: bounding the tail from slots=1 returned 1 for large inputs.

    The geometric tail bound is only valid past the mean -- far below it the
    first term is tiny while the tail it bounds is essentially 1. An earlier
    version accepted slots=1 for 5,048 keys in 64 buckets, a mean load of 79.
    """

    from doram_t2_3pc.compact_directory import public_capacity_bound

    for keys, buckets in ((5048, 64), (156079, 256), (1000, 8)):
        bound = public_capacity_bound(keys, buckets, 5)
        assert bound >= keys / buckets, (
            f"bound {bound} is below the mean load {keys / buckets:.1f}"
        )
