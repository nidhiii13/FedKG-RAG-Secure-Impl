"""EXPERIMENTAL compact directory: size the index to the data, not the keyspace.

The problem this attacks
------------------------
``relation_pages`` stores the ``(source, relation)`` directory **densely**: a row
for every entity-relation pair, whether or not an edge exists. Because the
lookup is oblivious, every dependent read scans the whole table, so cost grows
with ``entity_count * relation_count`` -- the size of the *keyspace* -- rather
than with the number of keys that actually exist.

Measured, that is most of the circuit. On the WebQSP evaluation fixture the
dense directory is 1,706,776 rows of which **2.20% are occupied**; at full
WebQSP scale it is 771,502,600 rows at **0.154%**. The padding is what buys
obliviousness, but paying for a 650x-oversized table is not the only way to buy
it: a table sized to the real key count is equally oblivious, because its size
is a public constant either way.

The construction
----------------
A public hash sends each key to one of ``buckets`` buckets. Owner ``i`` places
its own keys into its own ``slots`` columns of that bucket, so **no owner needs
to know anything about another owner's keys** -- the property the dense layout
got for free and that any replacement has to preserve. Additive sharing does
the rest: every owner shares a full-width vector that is zero outside its own
columns, and the servers' sum is the assembled table.

A bucket therefore holds several *different* keys, so each slot stores the key
tag next to the descriptor and the circuit checks the tag before believing the
descriptor. That check is what a dense table does not need, and it is the price
of compaction.

Why the hash must be evaluated inside the circuit
-------------------------------------------------
For hop one the client knows ``(source, relation_1)`` and could hash it locally.
Hop two cannot: its entities are hop-one's *results*, discovered inside the MPC
and unknown to the client. So the bucket index is computed on secret shares.
That rules out anything needing XOR or modular reduction on a secret, and it is
why the hash here is ``high bits of key * MULTIPLIER``: the multiplication is by
a public constant and therefore free, and the bit extraction is a single
decomposition the circuit needs anyway.

What is public, and what that costs
-----------------------------------
``buckets`` and ``slots`` are public, exactly like ``page_budget``. They are
chosen from the per-owner key counts ``B_i``, which the leakage function already
publishes, so this adds no *information* -- but it does add two more numbers
that must be honest, and ``plan_capacity`` refuses a plan whose measured maximum
load exceeds ``slots`` rather than silently dropping keys.

Uniform ``slots`` across owners wastes space when ``B_i`` is skewed, because it
is sized for the largest owner. That is a deliberate simplicity choice, recorded
because it is a real cost: a federation with 10x volume skew pays 10x the slack
of a balanced one.

Status
------
Layout, capacity planning and cost model. A circuit exists in ``page_program``
and its assembly is cleartext-verified against the dense layout, but **it has
never executed**: MP-SPDZ compilation exceeded 1800s on every fixture tried, over
three attempts. Bounding the tag comparison to the tag width did not fix it, so
the binding constraint is the *output width* of the bucket-fetch ``map_sum``
rather than the comparison. See ``benchmarks/compact_directory_planning.json``
for the revised diagnosis and the proposed restructuring.

Prefer the type-blocked directory (``KG_VS_PLAIN_GRAPH.md``) where an ontology is
available: it models ~2.5x cheaper on the same graph and has no tag comparison,
so it avoids this failure mode entirely. The *supported* backend remains the
packed scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence


# Public hash constants. MULTIPLIER is odd so the map is injective modulo any
# power of two; the value is Knuth's golden-ratio constant, chosen for being a
# published number rather than one tuned against this data.
MULTIPLIER = 0x9E3779B97F4A7C15
HASH_INPUT_BITS = 40
# Fibonacci hashing is defined over fixed-width words: truncate the product to
# HASH_WORD_BITS *first*, then take its top bits. Getting that order wrong sends
# every key to bucket zero, because the untruncated product's high bits are the
# high bits of the small input.
HASH_WORD_BITS = 64


def key_tag(entity: int, relation: int, relation_count: int) -> int:
    """The dense address, reused as the key tag. Zero is reserved for 'empty'."""

    if not 1 <= relation <= relation_count:
        raise ValueError(f"relation {relation} outside [1, {relation_count}]")
    if entity < 0:
        raise ValueError("entity must be non-negative")
    return entity * relation_count + (relation - 1) + 1


def bucket_of(tag: int, buckets: int) -> int:
    """Multiplicative hash, taking the HIGH bits of ``tag * MULTIPLIER``.

    The high bits are what make this a hash rather than a relabelling: the low
    bits of a product depend only on the low bits of the input, so ``tag % M``
    would put every key of a hub entity in a handful of buckets whenever the
    relation count shares factors with ``M``. Taking the top bits mixes every
    input bit into every output bit.

    ``buckets`` must be a power of two so that the circuit can read the index
    straight out of a bit decomposition -- a secret modular reduction by an
    arbitrary constant would cost more than the lookup it serves. In circuit the
    product is a public-constant multiple of a secret, hence free; only the
    decomposition to HASH_WORD_BITS is paid for, and the index is then a slice
    of the resulting bits.
    """

    if buckets < 1 or buckets & (buckets - 1):
        raise ValueError(f"buckets must be a power of two, got {buckets}")
    if buckets == 1:
        return 0
    if tag.bit_length() > HASH_INPUT_BITS:
        raise ValueError(
            f"key tag {tag} exceeds {HASH_INPUT_BITS} bits; the circuit "
            "decomposes a fixed width and a wider tag would silently truncate"
        )
    width = buckets.bit_length() - 1
    word = (tag * MULTIPLIER) & ((1 << HASH_WORD_BITS) - 1)
    return word >> (HASH_WORD_BITS - width)


@dataclass(frozen=True)
class CompactDirectoryPlan:
    """A sized compact directory, with the measurement that justifies its size."""

    buckets: int
    slots: int
    owner_count: int
    max_load: int
    total_keys: int

    @property
    def total_slots(self) -> int:
        return self.buckets * self.owner_count * self.slots

    @property
    def slack(self) -> float:
        """Slots per real key. 1.0 would be a perfect hash; nothing achieves it."""

        return self.total_slots / self.total_keys if self.total_keys else 0.0

    @property
    def headroom(self) -> int:
        return self.slots - self.max_load

    def as_dict(self) -> dict[str, object]:
        return {
            "directory_buckets": self.buckets,
            "bucket_slots": self.slots,
            "owner_count": self.owner_count,
            "measured_max_load": self.max_load,
            "headroom": self.headroom,
            "total_keys": self.total_keys,
            "total_slots": self.total_slots,
            "slack": round(self.slack, 3),
        }


def measure_load(
    owner_tags: Mapping[str, Iterable[int]], buckets: int
) -> tuple[int, list[int]]:
    """Largest number of one owner's keys landing in one bucket.

    Returned rather than bounded analytically because the theory gives a tail
    bound and what the layout needs is the actual figure on the actual keys. A
    plan sized from a bound that the data then exceeds would drop edges.
    """

    worst = 0
    per_owner: list[int] = []
    for tags in owner_tags.values():
        counts: dict[int, int] = {}
        total = 0
        for tag in tags:
            bucket = bucket_of(tag, buckets)
            counts[bucket] = counts.get(bucket, 0) + 1
            total += 1
        owner_worst = max(counts.values(), default=0)
        per_owner.append(owner_worst)
        worst = max(worst, owner_worst)
    return worst, per_owner


def plan_capacity(
    owner_tags: Mapping[str, Iterable[int]],
    *,
    candidates: Sequence[int] | None = None,
    relation_count: int = 0,
    entity_count: int = 0,
    frontier_addresses: int = 1,
) -> CompactDirectoryPlan:
    """Pick the bucket count that minimises modelled lookup cost.

    There is a real optimum rather than 'more buckets is better'. Few buckets
    means little slack but wide buckets, and every slot in the selected bucket
    needs a tag comparison; many buckets means cheap comparison but the
    per-owner capacity is sized for the worst bucket and most slots sit empty.
    ``lookup_products`` prices both sides and this walks the candidates.
    """

    materialised = {owner: list(tags) for owner, tags in owner_tags.items()}
    total_keys = sum(len(tags) for tags in materialised.values())
    owner_count = len(materialised) or 1
    if candidates is None:
        candidates = [1 << power for power in range(0, 15)]

    best: CompactDirectoryPlan | None = None
    best_cost = None
    for buckets in candidates:
        max_load, _ = measure_load(materialised, buckets)
        if max_load == 0:
            continue
        plan = CompactDirectoryPlan(
            buckets=buckets,
            slots=max_load,
            owner_count=owner_count,
            max_load=max_load,
            total_keys=total_keys,
        )
        cost = lookup_products(plan, frontier_addresses=frontier_addresses)
        if best_cost is None or cost < best_cost:
            best, best_cost = plan, cost
    if best is None:
        raise ValueError("no candidate bucket count fits these keys")
    return best


# Cost model
# ----------
# Products, not bytes. Bytes need a measured per-product rate, and the two
# recorded rates in this repository differ by 3.4x between layouts, so
# converting here would bake in a constant that does not travel.
EQUALITY_PRODUCTS = 50


def lookup_products(plan: CompactDirectoryPlan, *, frontier_addresses: int = 1) -> int:
    """Modelled products for one query's directory work under the compact layout.

    Per address: fetch the selected bucket -- tag and descriptor columns, so two
    elements per slot, over every bucket because the selection is secret -- then
    compare the tag in each of the fetched slots.
    """

    addresses = 1 + frontier_addresses
    fetch = 2 * plan.buckets * plan.owner_count * plan.slots
    verify = plan.owner_count * plan.slots * EQUALITY_PRODUCTS
    return addresses * (fetch + verify)


def dense_products(
    entity_count: int,
    relation_count: int,
    *,
    frontier_addresses: int = 1,
    folded: bool = True,
) -> int:
    """The same figure for the dense layout, for an apples-to-apples ratio.

    ``folded=True`` is the current default circuit, which contracts the shared
    hop-two relation out of the directory first (relation_folded_directory.json);
    comparing against the unfolded cost would overstate this layout's advantage.
    """

    rows = entity_count * relation_count
    if folded:
        # hop one reads the dense table; hop two folds once then reads per entity.
        return rows + rows + frontier_addresses * entity_count
    return (1 + frontier_addresses) * rows


# Assembly
# --------
# Owner i writes only its own columns and zero everywhere else, so the servers'
# additive sum is the assembled table and no owner learns anything about
# another's keys. That independence is the property the dense layout got for
# free, and preserving it is the reason capacity is per-owner rather than
# per-bucket.
def slot_columns(owner_index: int, slots: int) -> range:
    return range(owner_index * slots, (owner_index + 1) * slots)


def pack_slot(tag: int, descriptor: int, descriptor_bits: int) -> int:
    """One field element per slot: the tag above the descriptor.

    Packing halves the fetch, which is the dominant term, at the cost of one
    unpacking per *fetched* slot rather than per stored slot -- fetched slots
    are ``n * s`` where stored slots are ``b * n * s``, so the trade is
    favourable by exactly the bucket count.
    """

    if tag < 0 or descriptor < 0:
        raise ValueError("tag and descriptor must be non-negative")
    if descriptor >= 1 << descriptor_bits:
        raise ValueError(
            f"descriptor {descriptor} does not fit {descriptor_bits} bits"
        )
    return (tag << descriptor_bits) | descriptor


def build_owner_table(
    keyed_descriptors: Mapping[int, int],
    *,
    owner_index: int,
    buckets: int,
    slots: int,
    owner_count: int,
    descriptor_bits: int,
) -> list[int]:
    """Flatten one owner's keys into the full-width table, zero outside its columns.

    ``keyed_descriptors`` maps key tag -> descriptor. Raises rather than
    truncating when a bucket overflows: dropping an edge silently would make the
    circuit disagree with the oracle for a reason no test would attribute
    correctly.
    """

    width = owner_count * slots
    table = [0] * (buckets * width)
    filled: dict[int, int] = {}
    for tag, descriptor in sorted(keyed_descriptors.items()):
        if tag == 0:
            raise ValueError("tag 0 is reserved to mark an empty slot")
        bucket = bucket_of(tag, buckets)
        used = filled.get(bucket, 0)
        if used >= slots:
            raise ValueError(
                f"bucket {bucket} overflows for owner {owner_index}: more than "
                f"{slots} keys hash to it. Re-plan capacity; do not raise "
                "buckets without re-measuring, because the worst-case load is "
                "what sizes the slots."
            )
        filled[bucket] = used + 1
        column = owner_index * slots + used
        table[bucket * width + column] = pack_slot(tag, descriptor, descriptor_bits)
    return table


def lookup_cleartext(
    tables: Sequence[Sequence[int]],
    tag: int,
    *,
    buckets: int,
    slots: int,
    owner_count: int,
    descriptor_bits: int,
) -> list[int]:
    """The reference the circuit must match: descriptor per owner, 0 if absent."""

    width = owner_count * slots
    bucket = bucket_of(tag, buckets)
    mask = (1 << descriptor_bits) - 1
    found = [0] * owner_count
    for owner in range(owner_count):
        for column in slot_columns(owner, slots):
            packed = sum(table[bucket * width + column] for table in tables)
            if packed and (packed >> descriptor_bits) == tag:
                found[owner] = packed & mask
    return found


# Data-independent capacity
# -------------------------
# plan_capacity sizes `slots` to the MEASURED worst-case bucket load, which makes
# it a public parameter whose value depends on the owners' actual keys. That is a
# small but real leak: two federations with identical B_i but differently
# clustered keys publish different `s`.
#
# public_capacity_bound removes the dependence by deriving `s` from the public
# per-owner key count and bucket count alone, sized so that overflow is
# cryptographically unlikely rather than empirically absent. Use this for
# deployment; plan_capacity's measured figure is for cost analysis, where the
# tighter number is what you want and nothing is published.
def public_capacity_bound(
    keys_per_owner: int,
    buckets: int,
    owner_count: int,
    *,
    failure_log2: int = 40,
) -> int:
    """Smallest ``slots`` whose overflow probability is below 2^-failure_log2.

    A function of public inputs only, so publishing it reveals nothing about
    which keys exist. The cost is slack: this is necessarily larger than the
    measured maximum, and the gap is the price of not leaking.
    """

    from math import lgamma, log, exp

    if keys_per_owner < 0 or buckets < 1 or owner_count < 1:
        raise ValueError("counts must be positive")
    if keys_per_owner == 0:
        return 1

    # Work in logs throughout: the binomial coefficient overflows a float long
    # before the probability underflows it, so computing the terms directly fails
    # on realistic key counts.
    log_p = -log(buckets)
    log_q = log(1.0 - 1.0 / buckets) if buckets > 1 else float("-inf")
    log_target = -failure_log2 * log(2.0) - log(buckets * owner_count)

    def log_choose(total: int, taken: int) -> float:
        return (
            lgamma(total + 1) - lgamma(taken + 1) - lgamma(total - taken + 1)
        )

    def log_term(hits: int) -> float:
        value = log_choose(keys_per_owner, hits) + hits * log_p
        if keys_per_owner - hits:
            value += (keys_per_owner - hits) * log_q
        return value

    # Only search ABOVE the mean. Below it the tail is essentially 1, and an
    # earlier version that applied the geometric bound from slots=1 returned 1
    # for every large input -- the first term is tiny far below the mean, but the
    # tail it is supposed to bound is not.
    mean = keys_per_owner / buckets
    start = max(1, int(mean))
    for slots in range(start, keys_per_owner + 1):
        first = slots + 1
        if first > keys_per_owner:
            return slots
        # Successive binomial terms shrink by this ratio past the mean, so the
        # tail is bounded by first_term / (1 - ratio) -- rigorous, and it avoids
        # summing thousands of terms that underflow a float individually.
        ratio = ((keys_per_owner - first) / (first + 1)) / (buckets - 1) if buckets > 1 else 1.0
        if ratio >= 1.0:
            continue
        log_tail = log_term(first) - log(1.0 - ratio)
        if log_tail <= log_target:
            return slots
    return keys_per_owner
