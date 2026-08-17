"""EXPERIMENTAL owner-blind page pooling: hiding per-owner data volume.

The leak this removes
---------------------
``LEAKAGE_ABUSE.md`` ranks ``B_i``, the per-owner page budget, as the
highest-severity item in the leakage function. It is an upper bound on how many
distinct ``(source, relation)`` keys owner ``i`` holds -- essentially its data
volume -- and it is **structural**: owner ``i``'s pages occupy their own region
of the shared array, so two colluding servers read ``B_i`` off the input file
length without breaking anything.

The only mitigation implemented before this was uniform padding to
``B = max_i B_i``, which taxes a participant holding 1% of the largest owner's
data at 100x its own weight. That is a direct disincentive to join a federation.

What pooling changes
--------------------
All owners' pages go into one array which is then permuted by a secret
permutation the servers do not learn. No region is attributable, so the leakage
function drops ``B_1..B_n`` and keeps only the federation total ``sum(B_i)``:

    before   L = ( ..., B_1, ..., B_n, ... )
    after    L = ( ..., sum(B_i),      ... )

Federation size stays public. **Who contributes how much becomes hidden.**

The pointer problem, and why it is the expensive part
-----------------------------------------------------
Permuting the pool moves every page, so each directory descriptor pointing at a
page must be updated to the page's new position -- and the permutation has to
stay hidden from the servers, or the pooling achieves nothing. Simply revealing
it and rewriting pointers is therefore not available.

This module models the construction whose cost is tractable: apply the *same*
secret permutation to a parallel position array, so the new position of every
original slot is available in shared form, then remap the descriptors against
it. See ``pooling_cost_estimate`` for what each step costs; the remap dominates,
and it is a **one-time preparation cost** rather than a per-query one.

Threat model is unchanged: three servers, static passive adversary corrupting
any two, 3-of-3 additive sharing, no dealer, no trusted setup.

Status
------
The cleartext model, the cost model, and the MPC circuit are all here. The
circuit has been **executed and verified**: every descriptor remaps correctly
through the parallel position array while the permutation stays secret. See
``benchmarks/pooling_circuit_verification.json``.

What is not done: the circuit has only been run at small scale, and it is not
integrated with the relation-paged backend, so no pooled deployment exists yet.
The remap step here is a direct oblivious scan; at federation scale that step is
replaced by the sort-join whose growth law is measured in
``benchmarks/sort_join_growth.json``. The mechanism is identical, only the
lookup implementation differs.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass


# Measured coefficients, from the recorded benchmarks in this directory.
SHUFFLE_MB_PER_N_LOG_N = 0.10157      # volume_hiding_shuffle_cost.json
SCAN_MB_PER_PRODUCT = 0.030487        # relation_paged_multiaxis.json

# Sort-join, measured at 1024/2048/4096 rows with 20-bit keys -- the width the
# remap actually needs, being log2(directory_rows) at MetaQA scale.
# See benchmarks/sort_join_growth.json.
#
# An earlier estimate here assumed cost was LINEAR in row count and used a
# 16-bit measurement, giving 29,244 GB. Both were wrong: cost per row grows with
# size (59.5 -> 64.0 -> 68.5 MB/row across the measured range) because radix_sort
# runs one shuffle-based pass per key bit, and each pass is itself super-linear.
# The n*log2(n) law fits with 4.2% coefficient spread against the linear law's
# 14.0%, and the empirical exponent is 1.101.
SORT_JOIN_MB_PER_N_LOG_N_20BIT = 5.824613

# The linear law is retained only to bracket the projection: it is the
# optimistic end, and the gap between the two is the honest uncertainty given
# that MetaQA scale is still 144x beyond the largest measured point.
SORT_JOIN_MB_PER_ROW_OPTIMISTIC = 63.98916


@dataclass(frozen=True)
class PooledLayout:
    """All owners' pages in one permuted array, with remapped descriptors."""

    pages: list[list[int]]
    # descriptors[key] = (position in `pages`, page count). Positions refer to
    # post-permutation slots, so they carry no owner information.
    descriptors: dict[int, tuple[int, int]]
    owner_count: int
    total_pages: int

    def read(self, key: int) -> list[list[int]] | None:
        """Read a key's pages, exactly as the circuit would after pooling."""

        if key not in self.descriptors:
            return None
        base, count = self.descriptors[key]
        return [self.pages[base + offset] for offset in range(count)]


def concatenate_owner_pools(
    owner_pages: list[dict[int, list[list[int]]]],
) -> tuple[list[list[int]], dict[int, tuple[int, int]], list[int]]:
    """Lay every owner's pages end to end, before any permutation.

    ``owner_pages[i][key]`` is owner ``i``'s list of pages for that key.

    Returns the concatenated pool, descriptors into it, and the owner that
    contributed each slot. That last list is what pooling must destroy: in the
    concatenated order it is a public function of position, which is exactly how
    ``B_i`` leaks today.
    """

    pool: list[list[int]] = []
    descriptors: dict[int, tuple[int, int]] = {}
    provenance: list[int] = []
    for owner_index, pages_by_key in enumerate(owner_pages):
        for key in sorted(pages_by_key):
            pages = pages_by_key[key]
            if not pages:
                continue
            if key in descriptors:
                raise ValueError(
                    f"key {key} is held by more than one owner; pooling requires "
                    "keys to be partitioned, or descriptors would collide"
                )
            descriptors[key] = (len(pool), len(pages))
            pool.extend(pages)
            provenance.extend([owner_index] * len(pages))
    return pool, descriptors, provenance


def apply_permutation(
    pool: list[list[int]],
    descriptors: dict[int, tuple[int, int]],
    permutation: list[int],
) -> PooledLayout:
    """Permute the pool and remap descriptors through a parallel position array.

    ``permutation[p]`` is the slot that original position ``p`` moves to. In the
    circuit this is the *same* secret shuffle applied to a position array, so the
    new position of every slot is available in shared form without the servers
    ever learning the permutation.

    A key's pages must stay contiguous, or the descriptor's ``(base, count)``
    form cannot address them. This is enforced rather than assumed: permuting
    keys as blocks preserves it, permuting individual pages does not.
    """

    size = len(pool)
    if sorted(permutation) != list(range(size)):
        raise ValueError("permutation must be a bijection on the pool positions")

    permuted: list[list[int]] = [[] for _ in range(size)]
    for original, target in enumerate(permutation):
        permuted[target] = pool[original]

    remapped: dict[int, tuple[int, int]] = {}
    for key, (base, count) in descriptors.items():
        targets = [permutation[base + offset] for offset in range(count)]
        if targets != list(range(targets[0], targets[0] + count)):
            raise ValueError(
                f"key {key} was split by the permutation; a key's pages must "
                "move as one contiguous block or (base, count) cannot address them"
            )
        remapped[key] = (targets[0], count)

    owners = 0
    return PooledLayout(
        pages=permuted,
        descriptors=remapped,
        owner_count=owners,
        total_pages=size,
    )


def block_permutation(
    descriptors: dict[int, tuple[int, int]],
    size: int,
    *,
    rng: secrets.SystemRandom | None = None,
) -> list[int]:
    """A uniformly random permutation that moves each key's pages as one block.

    Permuting individual pages would break the contiguity ``(base, count)``
    descriptors rely on. Permuting *blocks* keeps each key's pages together while
    still destroying the correspondence between position and owner, which is the
    only thing pooling has to achieve.
    """

    generator = rng or secrets.SystemRandom()
    blocks = sorted(descriptors.items(), key=lambda item: item[1][0])
    order = list(range(len(blocks)))
    for i in range(len(order) - 1, 0, -1):
        j = generator.randrange(i + 1)
        order[i], order[j] = order[j], order[i]

    permutation = [0] * size
    cursor = 0
    for block_position in order:
        _, (base, count) = blocks[block_position]
        for offset in range(count):
            permutation[base + offset] = cursor + offset
        cursor += count
    if cursor != size:
        raise ValueError("descriptors do not cover the pool exactly")
    return permutation


def provenance_after(permutation: list[int], provenance: list[int]) -> list[int]:
    """Owner of each slot after permuting, for tests to inspect."""

    result = [0] * len(provenance)
    for original, target in enumerate(permutation):
        result[target] = provenance[original]
    return result


def pooling_cost_estimate(
    directory_rows: int,
    total_pages: int,
    *,
    queries_per_epoch: int,
    query_cost_gb: float,
) -> dict[str, object]:
    """One-time cost of pooling, and what it amortises to per query.

    The shuffle is cheap. The descriptor remap dominates, because applying a
    hidden permutation to secret pointers needs either an oblivious sort-join or
    a scatter, and both are expensive under a dishonest-majority protocol.
    """

    import math

    shuffle_gb = (
        SHUFFLE_MB_PER_N_LOG_N * total_pages * math.log2(max(total_pages, 2)) / 1024
    )
    # Sort-join of directory entries against position records. Cheapest of the
    # three remap routes; the alternatives are quadratic in the table sizes.
    records = directory_rows + total_pages
    remap_gb = (
        SORT_JOIN_MB_PER_N_LOG_N_20BIT
        * records
        * math.log2(max(records, 2))
        / 1024
    )
    remap_gb_optimistic = SORT_JOIN_MB_PER_ROW_OPTIMISTIC * records / 1024
    total_gb = shuffle_gb + remap_gb
    per_query_gb = total_gb / queries_per_epoch if queries_per_epoch else None
    return {
        "total_pages": total_pages,
        "directory_rows": directory_rows,
        "one_time_shuffle_gb": round(shuffle_gb, 1),
        "one_time_remap_gb": round(remap_gb, 1),
        "one_time_remap_gb_optimistic": round(remap_gb_optimistic, 1),
        "one_time_total_gb": round(total_gb, 1),
        "queries_per_epoch": queries_per_epoch,
        "amortised_gb_per_query": round(per_query_gb, 1) if per_query_gb else None,
        "amortised_overhead_percent": (
            round(100 * per_query_gb / query_cost_gb, 1)
            if per_query_gb and query_cost_gb
            else None
        ),
        "dominant_term": "descriptor remap",
        "projection_bracket_gb": [
            round(shuffle_gb + remap_gb_optimistic, 1),
            round(total_gb, 1),
        ],
        "leakage_removed": "B_1..B_n, replaced by sum(B_i)",
        "status": "cleartext model and cost model only; the MPC circuit is not written",
    }


def render_pooling_program(
    key_blocks: int,
    block_width: int,
    *,
    reveal_permutation: bool = False,
) -> str:
    """Render the MPC circuit that pools, shuffles, and remaps descriptors.

    Each row is one key's whole page block, so shuffling **rows** moves a key's
    pages atomically and the ``(base, count)`` descriptor stays addressable.
    Shuffling individual pages would split multi-page keys, which
    ``apply_permutation`` rejects for the same reason.

    ``reveal_permutation`` is for **verification only**. It opens where each
    block landed so a test can confirm the shuffle is not the identity. A
    deployment must never set it: revealing the permutation re-links positions
    to owners and undoes exactly the property pooling exists to provide.
    """

    if key_blocks < 2:
        raise ValueError("need at least two key blocks to pool")
    if block_width < 1:
        raise ValueError("block width must be positive")

    permutation_output = ""
    if reveal_permutation:
        permutation_output = """
# VERIFICATION ONLY: opens where each block landed. Never enable in deployment;
# revealing the permutation re-links positions to owners.
for p in range(KEYS):
    print_ln_to(0, 'POOL_PERM %s %s', p, new_slot_of[p].reveal_to(0))"""

    return f'''# Generated owner-blind pooling circuit (EXPERIMENTAL).
# Pools every owner's key blocks into one array, permutes it under a secret
# permutation the servers never learn, and remaps the descriptors through a
# parallel position array so lookups still resolve.
from Compiler.library import print_ln_to, start_timer, stop_timer
from Compiler.types import Array, Matrix, sint

KEYS = {key_blocks}
WIDTH = {block_width}


def shared(rows, cols):
    m = Matrix(rows, cols, sint)
    m.input_from(0)
    for player in (1, 2):
        incoming = Matrix(rows, cols, sint)
        incoming.input_from(player)
        m.assign_vector(m[:] + incoming[:])
        incoming.delete()
    return m


pool = shared(KEYS, WIDTH)
descriptor = shared(KEYS, 1)

start_timer(1)
# One secret permutation, applied to the pool and to an identity array. It
# exists only as a shuffle handle and is never opened.
perm = sint.get_secure_shuffle(KEYS)
pool.secure_permute(perm)

idx = Array(KEYS, sint)
for j in range(KEYS):
    idx[j] = sint(j)
# The reverse direction yields new_slot_of[p]: where original row p landed.
new_slot_of = Array.create_from(idx.get_vector().secure_permute(perm, reverse=True))
stop_timer(1)

start_timer(2)
# Remap each descriptor by looking its old row up in new_slot_of. At federation
# scale this lookup becomes the sort-join measured in sort_join_growth.json;
# the mechanism is the same, only the lookup implementation differs.
remapped = Array(KEYS, sint)
for r in range(KEYS):
    acc = sint(0)
    for p in range(KEYS):
        acc = acc + (descriptor[r][0] == p) * new_slot_of[p]
    remapped[r] = acc
stop_timer(2)

for r in range(KEYS):
    first = sint(0)
    second = sint(0)
    for j in range(KEYS):
        hit = remapped[r] == j
        first = first + hit * pool[j][0]
        second = second + hit * pool[j][WIDTH - 1]
    print_ln_to(0, 'POOL_REMAP %s %s %s', r, first.reveal_to(0), second.reveal_to(0)){permutation_output}
'''
