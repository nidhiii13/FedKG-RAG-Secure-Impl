"""EXPERIMENTAL owner-side plaintext construction of an MP-SPDZ tree-ORAM state.

Why this exists
---------------
``benchmarks/doram_viability_under_dishonest_majority.json`` measured MP-SPDZ's
``RecursiveORAM`` under Semi and found the per-access cost is genuinely good: at
MetaQA scale it is about 2.65x *cheaper* than the linear scan, because access is
``O(log^2 N)`` where the scan is ``O(N)``. The blocker was never the access
protocol. It was ``batch_init``, which builds the ORAM **obliviously** with an
in-circuit shuffle and sort, costing roughly 97,000x a single access and paid on
every program run.

That obliviousness is unnecessary here. Each data owner already holds its own
edges in plaintext. It can assign random leaf labels and fill buckets locally,
for free, then secret-share the finished structure. The servers see only shares
and never learn the permutation; the owner learns nothing it did not already
know. In-circuit initialisation then costs nothing but loading shares.

Threat model is unchanged: three servers, static passive adversary corrupting any
two, 3-of-3 additive sharing, no dealer, no trusted setup, no FSS.

What this module covers, and what it does not
---------------------------------------------
``build_owner_oram_tree`` builds one tree level. ``build_owner_oram_stack``
recursively builds the position map down to a small, linearly scanned secret
base. ``oram_access_program.py`` now executes that recursion in MP-SPDZ and has
passed a real Temi run, including a repeated logical address.

The remaining boundary is integration: the standalone access circuit has not
yet replaced the relation-paged first and second scans, and the read-only state
must be freshly randomized and re-shared after its declared access epoch. See
``REMAINING``.

Layout being reproduced
-----------------------
Read out of ``Compiler/oram.py`` rather than assumed:

* buckets are heap-indexed with the root at 1, so leaf ``l`` lives in bucket
  ``l + 2**D`` and bucket 0 is unused;
* bucket ``b`` occupies flat slots ``[b * bucket_size, (b+1) * bucket_size)``;
* an entry is ``(is_empty, logical_index, leaf, *values)``;
* fields are stored **column-major**: ``ram.l[j]`` holds field ``j`` for every
  slot;
* after ``batch_init`` every real entry sits in a **leaf** bucket and internal
  buckets are entirely empty. Entries migrate upward only through later
  evictions.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass


REMAINING = (
    "integration with the relation-paged KG backend and measured large-scale "
    "execution; the recursive read-only access circuit is executable, but its "
    "state must be freshly randomized and re-shared after every bounded epoch"
)

# Packing factor for the position map. Each level stores CHI leaf labels per
# entry, so the number of levels is log_CHI(N). A larger factor means fewer
# levels, and the per-entry cost is dominated by the index equality test rather
# than the payload, so fewer-and-fatter beats more-and-thinner. Swept in
# benchmarks/owner_side_oram_construction.json: chi=8 yields 1.20x over a linear
# scan at MetaQA scale, chi=256 yields 2.16x.
DEFAULT_CHI = 256

# Below this size a level is stored flat and read with a linear scan, which is
# cheaper than a tree once the tree's own path exceeds the table.
DEFAULT_BASE_THRESHOLD = 64


def tree_shape(size: int, delta: int = 3) -> tuple[int, int]:
    """Return ``(bucket_size, depth)`` exactly as ``TreeORAM.__init__`` does.

    Reproduced rather than imported: MP-SPDZ's Compiler package is only usable
    inside a compilation, and the owner runs this offline on its own machine.
    ``test_oram_layout`` pins this against the real formula.
    """

    if size < 2:
        raise ValueError("ORAM size must be at least 2")
    k = (math.log(size * size * math.log2(size) * 100, 2) + 21) / (1 + delta)
    bucket_size = min(int(math.ceil((1 + delta) * k)), size + 1)
    depth = int(math.log2(max(size / k, 2)))
    return bucket_size, depth


def leaf_overflow_log2_bound(size: int, bucket_size: int, depth: int) -> float:
    """Chernoff/union upper bound for any leaf exceeding ``bucket_size``.

    Leaf labels are independent uniform values before the builder conditions on
    successful placement.  Conditioning changes their joint distribution by at
    most the rejected-event probability.  The binary KL Chernoff bound below,
    unioned over all leaves, gives a conservative auditable bound without
    relying on floating-point binomial-tail summation.
    """

    leaves = 2 ** depth
    threshold = bucket_size + 1
    if threshold > size:
        return float("-inf")
    probability = 1.0 / leaves
    fraction = threshold / size
    if fraction <= probability:
        return 0.0
    divergence = (
        fraction * math.log(fraction / probability)
        + (1 - fraction) * math.log((1 - fraction) / (1 - probability))
    )
    return (math.log(leaves) - size * divergence) / math.log(2)


def secure_tree_shape(
    size: int,
    *,
    statistical_security_bits: int = 80,
    maximum_stack_levels: int = 64,
) -> tuple[int, int]:
    """Increase the MP-SPDZ bucket until placement conditioning is negligible.

    Each recursive level is allocated ``epsilon / maximum_stack_levels`` so a
    union bound across the complete stack remains below ``2^-security_bits``.
    The depth remains MP-SPDZ-compatible; only the public bucket capacity grows.
    """

    if statistical_security_bits < 40:
        raise ValueError("statistical_security_bits must be at least 40")
    if maximum_stack_levels < 1:
        raise ValueError("maximum_stack_levels must be positive")
    bucket_size, depth = tree_shape(size)
    target = -statistical_security_bits - math.log2(maximum_stack_levels)
    while leaf_overflow_log2_bound(size, bucket_size, depth) > target:
        bucket_size += 1
        if bucket_size >= size:
            return size + 1, depth
    return bucket_size, depth


@dataclass(frozen=True)
class OwnerOramTree:
    """One owner's plaintext tree-ORAM state, ready to be secret-shared."""

    size: int
    bucket_size: int
    depth: int
    value_length: int
    fields: list[list[int]]      # column-major, mirroring ram.l[field][slot]
    position_map: list[int]      # logical index -> leaf label

    @property
    def n_buckets(self) -> int:
        return 2 ** (self.depth + 1)

    @property
    def slots(self) -> int:
        return self.n_buckets * self.bucket_size

    @property
    def field_count(self) -> int:
        return len(self.fields)

    def bucket_slots(self, bucket: int) -> range:
        base = bucket * self.bucket_size
        return range(base, base + self.bucket_size)

    def flat_values(self) -> list[int]:
        """Column-major flattening, in the order a circuit would consume it."""

        flat: list[int] = []
        for column in self.fields:
            flat.extend(column)
        return flat

    def entry(self, slot: int) -> tuple[int, ...]:
        return tuple(column[slot] for column in self.fields)


def build_owner_oram_tree(
    values: list[list[int]],
    *,
    max_attempts: int = 64,
    rng: secrets.SystemRandom | None = None,
    statistical_security_bits: int | None = None,
) -> OwnerOramTree:
    """Build the post-``batch_init`` tree state in plaintext.

    ``values[a]`` is the value tuple stored at logical index ``a``.

    Leaf labels are drawn uniformly. A leaf bucket holding more than
    ``bucket_size`` entries would overflow, so the assignment is redrawn until it
    fits. That retry is free: it is local plaintext work by the owner, invisible
    to the servers and outside the MPC entirely. Failing after ``max_attempts``
    raises rather than silently producing a structure that would drop entries.
    """

    size = len(values)
    if size < 2:
        raise ValueError("ORAM size must be at least 2")
    width = len(values[0])
    if width < 1:
        raise ValueError("entries must carry at least one value")
    if any(len(value) != width for value in values):
        raise ValueError("every entry must have the same value length")

    bucket_size, depth = (
        secure_tree_shape(size, statistical_security_bits=statistical_security_bits)
        if statistical_security_bits is not None
        else tree_shape(size)
    )
    leaves = 2 ** depth
    generator = rng or secrets.SystemRandom()

    for _ in range(max_attempts):
        assignment = [generator.randrange(leaves) for _ in range(size)]
        occupancy: dict[int, list[int]] = {}
        for index, leaf in enumerate(assignment):
            occupancy.setdefault(leaf, []).append(index)
        if max((len(b) for b in occupancy.values()), default=0) <= bucket_size:
            break
    else:
        raise ValueError(
            f"could not place {size} entries into {leaves} leaf buckets of "
            f"{bucket_size} slots within {max_attempts} attempts"
        )

    slots = (2 ** (depth + 1)) * bucket_size
    # is_empty, logical index, leaf, then the values.
    fields = [[0] * slots for _ in range(3 + width - 1 + 1)]
    fields[0] = [1] * slots          # everything starts empty, as init_mem does

    for leaf, indices in occupancy.items():
        base = (leaf + leaves) * bucket_size
        for offset, logical in enumerate(indices):
            slot = base + offset
            fields[0][slot] = 0
            fields[1][slot] = logical
            fields[2][slot] = leaf
            for position, value in enumerate(values[logical]):
                fields[3 + position][slot] = value

    return OwnerOramTree(
        size=size,
        bucket_size=bucket_size,
        depth=depth,
        value_length=width + 1,      # MP-SPDZ prepends the leaf to the value
        fields=fields,
        position_map=assignment,
    )


def path_buckets(leaf: int, depth: int) -> list[int]:
    """Heap indices from root to ``leaf``'s bucket -- what one access reads."""

    if not 0 <= leaf < 2 ** depth:
        raise ValueError("leaf out of range")
    bucket = leaf + 2 ** depth
    path = []
    while bucket >= 1:
        path.append(bucket)
        bucket //= 2
    return list(reversed(path))


def lookup(tree: OwnerOramTree, logical_index: int) -> list[int] | None:
    """Plaintext model of one read: follow the path, find the entry.

    An access reads every bucket on the root-to-leaf path, which is what makes
    the cost ``O(depth * bucket_size)`` rather than ``O(size)``. This mirrors
    that so a test can assert the entry is genuinely reachable along the path
    the circuit would walk.
    """

    if not 0 <= logical_index < tree.size:
        raise ValueError("logical index out of range")
    leaf = tree.position_map[logical_index]
    for bucket in path_buckets(leaf, tree.depth):
        for slot in tree.bucket_slots(bucket):
            if tree.fields[0][slot] == 0 and tree.fields[1][slot] == logical_index:
                return [column[slot] for column in tree.fields[3:]]
    return None


def tree_cost_estimate(size: int, value_width: int) -> dict[str, object]:
    """Public shape of the owner-built tree, for planning share volume."""

    bucket_size, depth = tree_shape(size)
    slots = (2 ** (depth + 1)) * bucket_size
    fields = 3 + value_width - 1 + 1
    return {
        "logical_entries": size,
        "bucket_size": bucket_size,
        "depth": depth,
        "buckets": 2 ** (depth + 1),
        "slots": slots,
        "fields_per_entry": fields,
        "shared_values": slots * fields,
        "slot_overhead_versus_flat_table": round(slots / size, 2),
        "path_buckets_per_access": depth + 1,
        "entries_touched_per_access": (depth + 1) * bucket_size,
        "in_circuit_initialisation_cost": 0,
        "remaining": REMAINING,
    }


@dataclass(frozen=True)
class OwnerOramStack:
    """A data tree plus the recursive position map that makes it addressable.

    Reading the data tree needs the leaf label for the requested logical index,
    and that lookup must itself be oblivious or it leaks the index. MP-SPDZ
    solves this by storing the labels in a further ORAM, recursively, until the
    level is small enough to scan. This is the owner-side plaintext equivalent.

    ``levels[0]`` is the data tree. ``levels[i]`` for ``i > 0`` holds the leaf
    labels of ``levels[i-1]``, packed ``chi`` per entry. ``base`` holds the leaf
    labels of the last tree level and is read with a linear scan.
    """

    levels: list[OwnerOramTree]
    base: list[int]
    chi: int

    @property
    def size(self) -> int:
        return self.levels[0].size

    def level_index(self, logical_index: int, level: int) -> int:
        """Index into ``levels[level]`` for a level-0 logical index.

        A public shift of the original index, so in-circuit it is one bit
        decomposition of the secret index followed by recomposing the high bits.
        """

        return logical_index // (self.chi ** level)

    def shared_values(self) -> int:
        return sum(tree.slots * tree.field_count for tree in self.levels) + len(self.base)


def build_owner_oram_stack(
    values: list[list[int]],
    *,
    chi: int = DEFAULT_CHI,
    base_threshold: int = DEFAULT_BASE_THRESHOLD,
    rng: secrets.SystemRandom | None = None,
    statistical_security_bits: int | None = None,
) -> OwnerOramStack:
    """Build the data tree and its recursive position map, all in plaintext."""

    if chi < 2:
        raise ValueError("chi must be at least 2")
    if base_threshold < 2:
        raise ValueError("base_threshold must be at least 2")

    levels: list[OwnerOramTree] = []
    current_values = values
    while True:
        tree = build_owner_oram_tree(
            current_values,
            rng=rng,
            statistical_security_bits=statistical_security_bits,
        )
        levels.append(tree)
        labels = tree.position_map
        # If packing would create a single-record position-map ORAM, that tree
        # has no private address to hide and build_owner_oram_tree correctly
        # rejects its size. Keep the current labels as the secret scanned base
        # instead. This can make the base larger than base_threshold but avoids
        # a pointless/invalid one-record recursive level.
        if len(labels) <= base_threshold or len(labels) <= chi:
            return OwnerOramStack(levels=levels, base=labels, chi=chi)
        # The next level stores these labels, chi per entry, zero-padded.
        packed: list[list[int]] = []
        for start in range(0, len(labels), chi):
            group = labels[start:start + chi]
            packed.append(list(group) + [0] * (chi - len(group)))
        current_values = packed


def stack_lookup(stack: OwnerOramStack, logical_index: int) -> list[int] | None:
    """Plaintext model of a full recursive access.

    Walks from the flat base down to the data tree, exactly as the circuit
    would: each level's lookup yields the leaf label needed by the level below.
    """

    if not 0 <= logical_index < stack.size:
        raise ValueError("logical index out of range")

    top = len(stack.levels) - 1
    leaf = stack.base[stack.level_index(logical_index, top)]
    for level in range(top, 0, -1):
        tree = stack.levels[level]
        index = stack.level_index(logical_index, level)
        if tree.position_map[index] != leaf:
            raise AssertionError("position map disagrees with the tree it indexes")
        packed = lookup(tree, index)
        if packed is None:
            return None
        # This entry holds chi labels of the level below; pick ours.
        leaf = packed[stack.level_index(logical_index, level - 1) % stack.chi]
    if stack.levels[0].position_map[logical_index] != leaf:
        raise AssertionError("position map disagrees with the data tree")
    return lookup(stack.levels[0], logical_index)


def stack_cost_estimate(
    size: int,
    value_width: int,
    *,
    chi: int = DEFAULT_CHI,
    base_threshold: int = DEFAULT_BASE_THRESHOLD,
) -> dict[str, object]:
    """Cost of one full recursive access, in entries touched per level."""

    levels: list[dict[str, object]] = []
    current = size
    while current > base_threshold:
        bucket_size, depth = tree_shape(current)
        levels.append({
            "entries": current,
            "depth": depth,
            "bucket_size": bucket_size,
            "entries_touched": (depth + 1) * bucket_size,
            "index_bits": max(1, (current - 1).bit_length()),
        })
        current = -(-current // chi)
    touched = sum(int(level["entries_touched"]) for level in levels) + current
    return {
        "logical_entries": size,
        "chi": chi,
        "tree_levels": len(levels),
        "base_entries": current,
        "levels": levels,
        "entries_touched_per_access": touched,
        "linear_scan_entries": size,
        "entries_ratio": round(size / touched, 2) if touched else None,
        "in_circuit_initialisation_cost": 0,
        "remaining": REMAINING,
    }


@dataclass
class AccessTrace:
    """What one run of accesses returns, and what the servers got to see."""

    results: list[list[int] | None]
    # Per access, one revealed leaf per level, indexed level-0-first.
    revealed_leaves: list[list[int]]
    # Per access, per level: whether that level was served from its stash and so
    # revealed a dummy path. A single per-access flag is not enough -- an access
    # can be real at the data level while its level-2 index was already fetched
    # by a different logical index, since level i is addressed by a // chi**i.
    dummy_levels: list[list[bool]]
    stash_high_water: int

    @property
    def fully_stashed(self) -> list[bool]:
        """Accesses that touched no real path at any level."""

        return [all(levels) for levels in self.dummy_levels]


def simulate_access_sequence(
    stack: OwnerOramStack,
    indices: list[int],
    *,
    max_accesses: int,
    rng: secrets.SystemRandom | None = None,
) -> AccessTrace:
    """Model a run of accesses with a read-only stash instead of eviction.

    Path ORAM normally remaps the accessed block to a fresh leaf and writes the
    path back, or reading the same index twice reveals the same path and leaks
    the repeat. That write-back roughly doubles the cost of every access.

    This workload never writes: the graph is fixed for the duration of a run and
    the owner reshuffles between runs anyway. That admits the classic
    square-root-ORAM treatment instead. Each index is fetched from the tree at
    most once; a repeat is served from a **stash** of everything already read,
    while the circuit reads a path at a *freshly drawn* leaf so the servers still
    observe one uniformly random path per access.

    The stash is **per level**, which matters and is easy to get wrong. Level
    ``i`` is addressed by ``a // chi**i``, so two *different* level-0 indices can
    share a level-2 index and a single level-0 stash would let the upper level
    reveal the same real path twice. Each level therefore tracks what it has
    already fetched, independently.

    The security argument is Path ORAM's, minus the write-back: every leaf the
    servers observe is uniform and independent of the access pattern, because a
    real leaf was drawn uniformly at build time and is revealed at most once per
    level, and every subsequent observation at that level is a fresh draw.

    ``max_accesses`` is the public bound on accesses per run. It sizes the stash,
    and once reached the owner must reshuffle -- which is exactly what re-sharing
    between runs already does, so it is a bound to declare rather than machinery
    to build.
    """

    if max_accesses < 1:
        raise ValueError("max_accesses must be positive")
    if len(indices) > max_accesses:
        raise ValueError(
            f"{len(indices)} accesses exceeds the declared max_accesses "
            f"{max_accesses}; the owner must reshuffle and re-share before "
            "serving more, or the revealed paths stop being independent"
        )

    generator = rng or secrets.SystemRandom()
    top = len(stack.levels) - 1
    # One stash per level, keyed by that level's own index.
    stashes: list[dict[int, list[int]]] = [{} for _ in stack.levels]
    results: list[list[int] | None] = []
    revealed: list[list[int]] = []
    dummies: list[list[bool]] = []

    for index in indices:
        if not 0 <= index < stack.size:
            raise ValueError("logical index out of range")

        per_level: list[int] = []
        per_level_dummy: list[bool] = []
        # Descend from the flat base to the data tree; each level yields the
        # leaf the level below needs.
        leaf = stack.base[stack.level_index(index, top)]
        value: list[int] | None = None
        for level in range(top, -1, -1):
            tree = stack.levels[level]
            level_index = stack.level_index(index, level)
            if level_index in stashes[level]:
                # Already fetched at this level: read a dummy path so the
                # observable access is unchanged, and serve from the stash.
                per_level.append(generator.randrange(2 ** tree.depth))
                per_level_dummy.append(True)
                value = stashes[level][level_index]
            else:
                per_level_dummy.append(False)
                per_level.append(leaf)
                value = lookup(tree, level_index)
                if value is not None:
                    stashes[level][level_index] = value
            if level > 0 and value is not None:
                # This entry packs chi labels of the level below; pick ours.
                leaf = value[stack.level_index(index, level - 1) % stack.chi]

        # Stored level-0-first so an index into these lists is a stack level;
        # the walk itself descends from the top, hence the reversal.
        revealed.append(per_level[::-1])
        dummies.append(per_level_dummy[::-1])
        results.append(value)

    return AccessTrace(
        results=results,
        revealed_leaves=revealed,
        dummy_levels=dummies,
        stash_high_water=max(len(stash) for stash in stashes),
    )


def access_cost_estimate(
    size: int,
    value_width: int,
    *,
    max_accesses: int,
    chi: int = DEFAULT_CHI,
    base_threshold: int = DEFAULT_BASE_THRESHOLD,
) -> dict[str, object]:
    """Cost of a whole run: path reads plus the stash scans they require."""

    per_access = stack_cost_estimate(
        size, value_width, chi=chi, base_threshold=base_threshold
    )
    touched = int(per_access["entries_touched_per_access"])
    path_total = touched * max_accesses
    # The stash is scanned obliviously on every access and grows by at most one
    # entry per access, so the total is triangular in the access count.
    stash_total = max_accesses * (max_accesses - 1) // 2
    return {
        "per_access": per_access,
        "max_accesses": max_accesses,
        "path_entries_total": path_total,
        "stash_entries_total": stash_total,
        "total_entries": path_total + stash_total,
        "stash_overhead_percent": (
            round(100 * stash_total / path_total, 2) if path_total else None
        ),
        "versus_full_eviction": (
            "a write-back eviction would roughly double the path cost; the "
            "stash replaces it because this workload never writes"
        ),
        "reshuffle_required_after": max_accesses,
        "remaining": REMAINING,
    }
