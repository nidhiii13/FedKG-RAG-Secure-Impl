"""EXPERIMENTAL hybrid directory: type-blocked partition plus hashed residual.

Why a hybrid, and not either half
---------------------------------
Measuring the two candidate layouts on real WebQSP produced a split verdict
(``KG_VS_PLAIN_GRAPH.md`` §2b):

* **Type-blocked partition** is nearly free to address -- the row index is affine
  in the secret entity -- and reaches 186x. But affine addressing needs a
  *partition*, one type per entity, and a Freebase entity carries 1 to 189
  domains. Forcing a partition drops **45.9% of edges**.
* **Hashed compact** needs no contiguity, so it keeps every edge and reaches 50x.
  But it pays a key-tag comparison on every fetched slot, which is both its cost
  driver and the thing that made it hard to compile.

The split suggests the obvious composition. Give each entity one primary type,
which covers 54.1% of edges affinely and almost for free, and put the remaining
45.9% in a hashed table. The hashed half then carries roughly half the keys, so
its per-slot comparison is paid on half as many.

A key lives in exactly one half, decided by the public type map, so a lookup
reads both and sums -- at most one contributes. That keeps the read oblivious
without a secret branch.

Leakage
-------
Nothing new beyond the two halves' own parameters, and the split itself is a
function of the public type map. A key's *half* is publicly derivable from
``(entity, relation)`` and the ontology, so it is not a secret being revealed --
but note that this means the split is only leakage-free under the same
precondition as type-blocking: the type map must be **external public input**,
not derived from the federation's edges. See ``type_blocked_directory``.

The hashed half must size its capacity with ``public_capacity_bound``, not the
measured maximum, for the reason recorded in ``LEAKAGE_ABUSE.md`` §8.

Status
------
The hybrid is now an opt-in executable path in ``page_program`` and
``paged_shares``. Owners route primary-type keys to the affine table and every
residual key to the hashed table without coordinating. The circuit reads both
halves and adds their descriptors, so the trace never reveals which half held
the key. A one-query MP-SPDZ Semi execution is recorded in
``benchmarks/hybrid_directory_execution.json``. Batched residual-tag
decomposition subsequently allowed all ten distinct fixture queries to compile,
run, and match the oracle on every field. This is still not a scale result: the
compiler processed roughly 4.2 million lines, so whole-batch compiler expansion
remains material.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class HybridSplit:
    """How the federation's keys divide between the two halves."""

    primary_type: Mapping[str, str]
    blocked_keys: int
    hashed_keys: int
    blocked_edges: int
    hashed_edges: int

    @property
    def total_keys(self) -> int:
        return self.blocked_keys + self.hashed_keys

    @property
    def total_edges(self) -> int:
        return self.blocked_edges + self.hashed_edges

    @property
    def blocked_edge_share(self) -> float:
        return self.blocked_edges / self.total_edges if self.total_edges else 0.0


def choose_primary_types(
    edges_by_domain: Mapping[str, Mapping[str, int]],
) -> dict[str, str]:
    """Give each entity the domain carrying most of its edges.

    Most-edges rather than most-relations: the goal is to route as much *traffic*
    as possible into the cheap affine half, and a domain with one very common
    relation beats three rare ones.

    NOTE: choosing from edge counts makes this map data-dependent, which is fine
    for the sizing analysis this module performs and is NOT a deployment path.
    A deployment must take the primary type from the published ontology, or the
    block widths leak the owners' edge distribution.
    """

    primary: dict[str, str] = {}
    for entity, counts in edges_by_domain.items():
        if counts:
            primary[entity] = max(sorted(counts), key=lambda d: (counts[d], d))
    return primary


def split_keys(
    keys: Mapping[tuple[str, str], int],
    primary_type: Mapping[str, str],
    relation_domain: Mapping[str, str],
) -> HybridSplit:
    """Route each key to the blocked half or the hashed half.

    ``keys`` maps (entity, relation) -> edge count for that key.
    """

    blocked_keys = hashed_keys = 0
    blocked_edges = hashed_edges = 0
    for (entity, relation), count in keys.items():
        domain = relation_domain.get(relation)
        if domain is not None and primary_type.get(entity) == domain:
            blocked_keys += 1
            blocked_edges += count
        else:
            hashed_keys += 1
            hashed_edges += count
    return HybridSplit(
        primary_type=dict(primary_type),
        blocked_keys=blocked_keys,
        hashed_keys=hashed_keys,
        blocked_edges=blocked_edges,
        hashed_edges=hashed_edges,
    )


def cost_model(
    *,
    blocked_rows: int,
    blocked_max_block: int,
    hashed_buckets: int,
    hashed_slots: int,
    owner_count: int,
    relation_count: int,
    frontier_addresses: int,
    folded: bool = True,
) -> dict[str, int]:
    """Modelled products for one query, split by component.

    Comparable with ``compact_directory.dense_products`` and
    ``compact_directory.lookup_products``: same units, same conventions, so the
    ratios travel.
    """

    from .compact_directory import EQUALITY_PRODUCTS

    addresses = 1 + frontier_addresses
    if folded:
        # Hop one reads the table; hop two extracts the queried relation's block
        # once and then reads it per address, padded to the widest block so the
        # read width cannot reveal the relation's domain.
        blocked = blocked_rows + blocked_rows + frontier_addresses * blocked_max_block
    else:
        blocked = addresses * blocked_rows
    # Coefficient lookup: a public per-relation table read at a secret relation.
    coefficients = addresses * relation_count
    width = owner_count * hashed_slots
    hashed = addresses * (
        hashed_buckets * width + width * EQUALITY_PRODUCTS
    )
    return {
        "blocked": blocked,
        "coefficient_lookups": coefficients,
        "hashed": hashed,
        "total": blocked + coefficients + hashed,
    }
