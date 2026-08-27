"""EXPERIMENTAL relation-paged adjacency layout with explicit overflow pages.

Status: EXPERIMENTAL but executable. This module defines the owner-side data
structure, an independent cleartext oracle for its semantics, and a public cost
model. Its MP-SPDZ circuit lives in ``page_program.py`` and its sharing path in
``paged_shares.py``. The *supported* backend remains the packed MPC-oblivious
linear scan in ``scan_program.py``: the paged backend has been executed only on
a small local fixture, where it is measurably slower than the scan because that
fixture has nothing to narrow.

Motivation
----------
The supported layout indexes adjacency by ``source`` alone, so every bucket must
reserve ``fanout_per_owner`` slots for the *widest* source in the dataset. On
MetaQA that maximum is roughly three orders of magnitude above the mean, which
is why the current fixtures are capped and lossy.

This layout indexes by ``(source, relation)`` through two levels:

1. a dense **directory** with one descriptor per ``(source, relation)`` and
   owner, at ``entity_count * relation_count`` rows and ``owner_count`` columns;
2. a compact **page pool** per owner of ``page_budget`` fixed-size pages, each
   holding ``page_size`` packed edges.

A key occupies ``ceil(degree / page_size)`` consecutive pages, up to the public
``pages_per_key`` bound, so high-degree keys are represented by overflow pages
instead of forcing a global cap. Preparation fails closed on overflow; it never
truncates.

Two consequences matter for the circuit that will consume this layout:

* the directory address ``source * relation_count + (relation - 1)`` is a public
  affine function of two secret values, so it is computable inside MPC with one
  multiplication and never has to be opened;
* the relation is resolved by the index itself, so the per-slot secret
  ``relation == relation_1`` equality test of the scan backend disappears at the
  first hop.

Threat model
------------
Unchanged from the supported backend: three servers, static passive adversary
corrupting any two, 3-of-3 additive sharing, no new primitive and no trusted
dealer. Every table here is read with the same secret-index linear lookup.

Additional public leakage introduced by this layout, beyond the supported
backend's public bounds, is exactly: ``page_size``, ``pages_per_key``, and the
padded ``page_budget``. ``page_budget`` is a declared bound, not the realized
page count, but it does upper-bound an owner's distinct ``(source, relation)``
population and must be declared public before shares are produced.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import PublicConfig, canonical_json
from .packed import pack_edge, packing_widths
from .type_blocked_directory import TypeBlockedLayout


LAYOUT_VERSION = 1

# A directory descriptor packs (page_base, page_count). Slot zero of the page
# pool is the reserved all-dummy page, so page_base == 0 marks an absent key.
EMPTY_DESCRIPTOR = 0


@dataclass(frozen=True)
class RelationPageParameters:
    """Public layout bounds for the experimental relation-paged backend.

    Two distinct bounds matter and must not be confused:

    ``page_size * pages_per_key``
        the **storage** bound, i.e. how many edges one ``(source, relation)``
        key may hold;
    ``frontier_per_owner``
        the **dependent-read** bound, i.e. how many of an owner's first-hop
        matches the circuit dereferences at the second hop.

    Compaction below the storage bound is only lossless if the owner-side
    builder enforces the read bound too, so ``frontier_per_owner`` is a
    declared public capacity that preparation fails closed on. Defaulting it to
    the storage bound disables compaction and can never drop an edge.

    ``global_frontier``
        an optional **federation-wide** dependent-read bound. Without it the
        second hop dereferences ``owners * frontier_per_owner`` slots, so its
        cost grows with the size of the federation and total cost is near
        quadratic in owner count -- the worst measured scaling axis, see
        ``benchmarks/relation_paged_multiaxis.json``. With it, the frontier is
        compacted across owners to one fixed global width and the second hop
        stops growing with the federation entirely.

        This is a strictly stronger declaration than the per-owner bound: it
        asserts that no ``(source, relation)`` key has more than
        ``global_frontier`` matching edges *summed over every owner*. No single
        owner can verify that alone, so preparation cannot enforce it
        owner-locally the way it enforces ``frontier_per_owner``. See
        ``check_global_frontier`` for the coordinated check, and
        ``IDEAL_FUNCTIONALITY.md`` for what declaring it adds to the public
        leakage.
    """

    page_size: int
    pages_per_key: int
    page_budget: int
    frontier_per_owner: int | None = None
    global_frontier: int | None = None
    # Compact directory (optional). Both None keeps the dense
    # entity x relation directory. See compact_directory.py for why this is a
    # narrow win: it trades padding for a per-slot key comparison and only pays
    # above roughly 40x sparsity, so it must stay selectable rather than
    # becoming the default.
    directory_buckets: int | None = None
    bucket_slots: int | None = None
    # Hybrid-only optimization. Residual keys are stored in uniformly sized,
    # relation-major compact tables and tagged by entity rather than by the
    # combined (entity, relation) address. The relation remains a secret part
    # of the MPC lookup address; this changes layout, not leakage.
    partition_residual_by_relation: bool = False

    def validate(self) -> None:
        for name, value in (
            ("page_size", self.page_size),
            ("pages_per_key", self.pages_per_key),
            ("page_budget", self.page_budget),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if value < 1:
                raise ValueError(f"{name} must be positive")
        # Page index 0 is the reserved dummy page, so a budget of one page can
        # store nothing.
        if self.page_budget < 2:
            raise ValueError("page_budget must reserve the dummy page plus data")
        if self.frontier_per_owner is not None:
            if (
                isinstance(self.frontier_per_owner, bool)
                or not isinstance(self.frontier_per_owner, int)
            ):
                raise ValueError("frontier_per_owner must be an integer")
            if not 1 <= self.frontier_per_owner <= self.slots_per_key:
                raise ValueError(
                    "frontier_per_owner must be in "
                    f"[1, {self.slots_per_key}]"
                )
        for name, value in (
            ("directory_buckets", self.directory_buckets),
            ("bucket_slots", self.bucket_slots),
        ):
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if value < 1:
                raise ValueError(f"{name} must be positive")
        if (self.directory_buckets is None) != (self.bucket_slots is None):
            raise ValueError(
                "directory_buckets and bucket_slots must be set together; one "
                "without the other describes no layout"
            )
        if self.directory_buckets is not None and (
            self.directory_buckets & (self.directory_buckets - 1)
        ):
            # The circuit reads the bucket index out of a bit slice of the hash,
            # so a non-power-of-two would need a secret modular reduction that
            # costs more than the lookup it serves.
            raise ValueError("directory_buckets must be a power of two")
        if self.global_frontier is not None:
            if (
                isinstance(self.global_frontier, bool)
                or not isinstance(self.global_frontier, int)
            ):
                raise ValueError("global_frontier must be an integer")
            if self.global_frontier < 1:
                raise ValueError("global_frontier must be positive")
        if not isinstance(self.partition_residual_by_relation, bool):
            raise ValueError("partition_residual_by_relation must be boolean")
        if self.partition_residual_by_relation and not self.uses_compact_directory:
            raise ValueError(
                "partition_residual_by_relation requires directory_buckets "
                "and bucket_slots"
            )

    @classmethod
    def from_dict(cls, raw: Any) -> "RelationPageParameters":
        if not isinstance(raw, dict):
            raise ValueError("relation_page_layout must be a JSON object")
        required = {"page_size", "pages_per_key", "page_budget"}
        optional = {
            "frontier_per_owner", "global_frontier", "directory_buckets",
            "bucket_slots", "partition_residual_by_relation",
        }
        missing = required - set(raw)
        unknown = set(raw) - required - optional
        if missing or unknown:
            raise ValueError(
                "relation_page_layout requires "
                + ", ".join(sorted(required))
                + f" (missing={sorted(missing)}, unknown={sorted(unknown)})"
            )
        result = cls(
            page_size=raw["page_size"],
            pages_per_key=raw["pages_per_key"],
            page_budget=raw["page_budget"],
            frontier_per_owner=raw.get("frontier_per_owner"),
            global_frontier=raw.get("global_frontier"),
            directory_buckets=raw.get("directory_buckets"),
            bucket_slots=raw.get("bucket_slots"),
            partition_residual_by_relation=raw.get(
                "partition_residual_by_relation", False
            ),
        )
        result.validate()
        return result

    def public_dict(self) -> dict[str, int]:
        result = {
            "page_size": self.page_size,
            "pages_per_key": self.pages_per_key,
            "page_budget": self.page_budget,
        }
        # Keep digests stable for layouts that never enable compaction.
        if self.frontier_per_owner is not None:
            result["frontier_per_owner"] = self.frontier_per_owner
        if self.global_frontier is not None:
            result["global_frontier"] = self.global_frontier
        if self.directory_buckets is not None:
            result["directory_buckets"] = self.directory_buckets
            result["bucket_slots"] = self.bucket_slots
        if self.partition_residual_by_relation:
            result["partition_residual_by_relation"] = True
        return result

    @property
    def slots_per_key(self) -> int:
        """Fixed public number of edge slots stored for one key."""

        return self.pages_per_key * self.page_size

    @property
    def effective_frontier_per_owner(self) -> int:
        """Fixed public number of dependent reads issued per owner."""

        return self.frontier_per_owner or self.slots_per_key

    @property
    def uses_frontier_compaction(self) -> bool:
        return self.effective_frontier_per_owner < self.slots_per_key

    def frontier_slots(self, owner_count: int) -> int:
        """Total dependent reads the second hop issues, per query.

        Without ``global_frontier`` this is proportional to the owner
        count, which is what makes total cost near quadratic in the size
        of the federation. With it, the second hop is a fixed width and
        stops growing with the federation.
        """

        if self.global_frontier is not None:
            return self.global_frontier
        return owner_count * self.effective_frontier_per_owner

    @property
    def uses_compact_directory(self) -> bool:
        return self.directory_buckets is not None

    @property
    def uses_global_frontier(self) -> bool:
        return self.global_frontier is not None

    @property
    def pool_rows(self) -> int:
        """Shared page-pool height, including the shifted-scan tail.

        The circuit fetches a ``pages_per_key``-wide window starting at a secret
        base with a single demux, reading row ``base + j`` for each public
        offset ``j``. Trailing dummy rows keep every shifted access in range
        without ever branching on the secret base.
        """

        return self.page_budget + self.pages_per_key - 1

    @property
    def page_base_bits(self) -> int:
        return max(1, (self.page_budget - 1).bit_length())

    @property
    def page_count_bits(self) -> int:
        return max(1, self.pages_per_key.bit_length())

    @property
    def descriptor_bits(self) -> int:
        return self.page_base_bits + self.page_count_bits


@dataclass(frozen=True)
class RelationPageConfig:
    """A public config plus the experimental relation-page bounds."""

    base: PublicConfig
    pages: RelationPageParameters
    type_blocks: TypeBlockedLayout | None = None
    entity_types: dict[str, str] | None = None
    relation_domains: dict[str, str] | None = None

    @classmethod
    def load(cls, path: str | Path) -> "RelationPageConfig":
        import json

        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("relation-page configuration must be a JSON object")
        if "relation_page_layout" not in raw:
            raise ValueError(
                "relation-page configuration requires a relation_page_layout object"
            )
        type_raw = raw.get("type_block_layout")
        remainder = {
            key: value
            for key, value in raw.items()
            if key not in {"relation_page_layout", "type_block_layout"}
        }
        base = PublicConfig.from_dict(remainder)
        pages = RelationPageParameters.from_dict(raw["relation_page_layout"])
        if pages.partition_residual_by_relation and type_raw is None:
            raise ValueError(
                "partition_residual_by_relation is only valid with "
                "type_block_layout"
            )
        if type_raw is None:
            return cls(base=base, pages=pages)
        if not isinstance(type_raw, dict) or set(type_raw) != {
            "entity_types", "relation_domains"
        }:
            raise ValueError(
                "type_block_layout requires exactly entity_types and relation_domains"
            )
        entity_types = type_raw["entity_types"]
        relation_domains = type_raw["relation_domains"]
        if not isinstance(entity_types, dict) or not isinstance(relation_domains, dict):
            raise ValueError("type-block ontology maps must be JSON objects")
        if not pages.uses_compact_directory:
            raise ValueError(
                "type_block_layout requires directory_buckets and bucket_slots: "
                "the hashed residual is what preserves valid multi-domain keys"
            )
        from .type_blocked_directory import build_layout_from_public_ids

        layout = build_layout_from_public_ids(
            base.entities, base.relations, entity_types, relation_domains
        )
        return cls(
            base=base,
            pages=pages,
            type_blocks=layout,
            entity_types={str(k): str(v) for k, v in entity_types.items()},
            relation_domains={str(k): str(v) for k, v in relation_domains.items()},
        )

    @property
    def relation_count(self) -> int:
        return len(self.base.relations)

    @property
    def directory_rows(self) -> int:
        """Secret-shared affine-directory height, including dummy row zero."""

        if self.type_blocks is not None:
            return self.type_blocks.total_rows
        return self.dense_directory_rows

    @property
    def dense_directory_rows(self) -> int:
        return self.base.entity_count * self.relation_count

    @property
    def uses_hybrid_directory(self) -> bool:
        return self.type_blocks is not None

    @property
    def residual_directory_rows(self) -> int:
        """Rows in the compact residual table consumed by the circuit."""

        buckets = self.pages.directory_buckets or 0
        if self.pages.partition_residual_by_relation:
            logical_rows = self.relation_count * buckets
            # demux_matrix materializes a power-of-two selector. Padding here
            # keeps its matrix height identical to the shared table height.
            return 1 << max(0, (logical_rows - 1).bit_length())
        return buckets

    @property
    def residual_tag_bits(self) -> int:
        """Exact public bit width of the residual slot tag."""

        if self.pages.partition_residual_by_relation:
            # Entity zero is never stored; +1 reserves tag zero for an empty
            # slot, so the largest possible tag is entity_count.
            return max(1, self.base.entity_count.bit_length())
        # Combined dense address + 1 reserves tag zero.
        return max(1, self.dense_directory_rows.bit_length())

    @property
    def owners_per_directory_element(self) -> int:
        """How many owners' descriptors fit in one field element.

        A descriptor is only ``descriptor_bits`` wide while the field carries
        ``field_usable_bits``, so several owners' descriptors fit side by side
        in disjoint bit ranges of a single element. Reading the directory then
        costs one product per row instead of one per row *per owner*, which is
        the dominant term in the whole circuit.

        This is a pure representation change. The same descriptors are present
        either way, so it adds no public parameter and no leakage; it only stops
        paying an owner-count factor to fetch values that already fit together.
        Crucially it needs no coordination between owners: additive sharing is
        linear, so owner ``i`` shares its own descriptor shifted into its own
        bit range and the servers' sum *is* the packed element.
        """

        return max(1, self.base.field_usable_bits // self.pages.descriptor_bits)

    @property
    def directory_columns(self) -> int:
        """Field elements per directory row after packing owners together."""

        owners = len(self.base.owners)
        per_element = self.owners_per_directory_element
        return (owners + per_element - 1) // per_element

    def directory_slot(self, owner_index: int) -> tuple[int, int]:
        """Which column, and which bit offset within it, owner ``i`` occupies."""

        per_element = self.owners_per_directory_element
        column = owner_index // per_element
        offset = (owner_index % per_element) * self.pages.descriptor_bits
        return column, offset

    def directory_index(self, source_slot: int, relation_id: int) -> int:
        """Public affine address used for both hops.

        Inside MPC this is ``source * relation_count + (relation - 1)``: one
        multiplication by a public constant plus an addition, so the address
        stays secret and no table position is ever opened.
        """

        if not 0 <= source_slot < self.base.entity_count:
            raise ValueError("source slot out of range")
        if not 1 <= relation_id <= self.relation_count:
            raise ValueError("relation id out of range")
        if self.type_blocks is None:
            return source_slot * self.relation_count + (relation_id - 1)
        if source_slot == 0:
            return 0
        entity = next(
            name for name, slot in self.base.entities.items() if slot == source_slot
        )
        relation = next(
            name for name, value in self.base.relations.items() if value == relation_id
        )
        address = self.type_blocks.address(entity, relation)
        if address is None:
            raise ValueError("key belongs in the hybrid hashed residual")
        return address

    def dense_directory_index(self, source_slot: int, relation_id: int) -> int:
        if not 0 <= source_slot < self.base.entity_count:
            raise ValueError("source slot out of range")
        if not 1 <= relation_id <= self.relation_count:
            raise ValueError("relation id out of range")
        return source_slot * self.relation_count + (relation_id - 1)

    def blocked_directory_index(self, source_slot: int, relation_id: int) -> int | None:
        if self.type_blocks is None:
            return self.dense_directory_index(source_slot, relation_id)
        if source_slot == 0:
            return 0
        entity = next(name for name, slot in self.base.entities.items() if slot == source_slot)
        relation = next(name for name, value in self.base.relations.items() if value == relation_id)
        return self.type_blocks.address(entity, relation)

    def pack_descriptor(self, page_base: int, page_count: int) -> int:
        if not 0 <= page_base < self.pages.page_budget:
            raise ValueError("page_base out of range")
        if not 0 <= page_count <= self.pages.pages_per_key:
            raise ValueError("page_count out of range")
        return page_base | (page_count << self.pages.page_base_bits)

    def unpack_descriptor(self, value: int) -> tuple[int, int]:
        mask = (1 << self.pages.page_base_bits) - 1
        return value & mask, value >> self.pages.page_base_bits

    @property
    def digest(self) -> str:
        import hashlib

        payload = {
            "layout_version": LAYOUT_VERSION,
            "base": self.base.public_dict(),
            "relation_page_layout": self.pages.public_dict(),
        }
        if self.type_blocks is not None:
            payload["type_block_layout"] = {
                "entity_types": self.entity_types,
                "relation_domains": self.relation_domains,
            }
        return hashlib.sha256(canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class OwnerPageLayout:
    """One owner's built directory and page pool, in cleartext."""

    owner: str
    directory: list[int]
    pages: list[list[int]]
    realized_page_count: int
    residual_descriptors: dict[int, int] | None = None

    def descriptor(self, index: int) -> int:
        return self.directory[index]


def _grouped_edges(
    config: RelationPageConfig, owner: str, edges: list[dict[str, Any]]
) -> dict[tuple[int, int], list[tuple[int, int, int, int]]]:
    """Validate raw edges and group them by (source, relation)."""

    base = config.base
    if owner not in base.owners:
        raise ValueError(f"unknown owner {owner!r}")
    grouped: dict[tuple[int, int], list[tuple[int, int, int, int]]] = defaultdict(list)
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
            source = base.entities[edge["source"]]
            target = base.entities[edge["target"]]
            relation = base.relations[edge["relation"]]
        except (KeyError, TypeError) as exc:
            raise ValueError(
                f"edge {row_number} uses an unknown ontology item"
            ) from exc
        evidence = edge["evidence"]
        score = edge["score"]
        if (
            isinstance(evidence, bool)
            or not isinstance(evidence, int)
            or evidence <= 0
        ):
            raise ValueError(f"edge {row_number} has an invalid evidence handle")
        if isinstance(score, bool) or not isinstance(score, int) or score < 0:
            raise ValueError(f"edge {row_number} has an invalid score")
        # Width enforcement mirrors the packed backend so a layout that builds
        # is also shareable.
        pack_edge(base, target, relation, evidence, score, 1)
        grouped[(source, relation)].append((target, relation, evidence, score))
    return grouped


def build_owner_page_layout(
    config: RelationPageConfig, owner: str, edges: list[dict[str, Any]]
) -> OwnerPageLayout:
    """Build one owner's lossless relation-paged layout.

    Fails closed if any key needs more than ``pages_per_key`` pages or if the
    owner's realized page count exceeds the public ``page_budget``. No edge is
    ever silently dropped.
    """

    base = config.base
    params = config.pages
    grouped = _grouped_edges(config, owner, edges)

    directory = [EMPTY_DESCRIPTOR] * config.directory_rows
    residual_descriptors: dict[int, int] = {}
    # Page 0 is the reserved dummy page every absent key resolves to.
    pool: list[list[int]] = [[0] * params.page_size]

    for (source, relation) in sorted(grouped):
        records = grouped[(source, relation)]
        required_pages = -(-len(records) // params.page_size)
        if required_pages > params.pages_per_key:
            raise ValueError(
                f"owner {owner!r} needs {required_pages} pages for entity slot "
                f"{source}, relation ID {relation}; public bound "
                f"pages_per_key is {params.pages_per_key}"
            )
        # The dependent-read bound is what makes compaction lossless. Enforce
        # it here so the circuit can compact to a fixed width without ever
        # dropping a match.
        if len(records) > params.effective_frontier_per_owner:
            raise ValueError(
                f"owner {owner!r} has {len(records)} edges at entity slot "
                f"{source}, relation ID {relation}; public bound "
                f"frontier_per_owner is {params.effective_frontier_per_owner}"
            )
        # Deterministic ordering keeps the layout, its digest, and the oracle's
        # tie-breaking reproducible across owners and runs.
        records.sort()
        page_base = len(pool)
        if page_base + required_pages > params.page_budget:
            raise ValueError(
                f"owner {owner!r} exceeds public page_budget "
                f"{params.page_budget}; realized pages would be "
                f"{page_base + required_pages}"
            )
        for page_number in range(required_pages):
            window = records[
                page_number * params.page_size : (page_number + 1) * params.page_size
            ]
            page = [
                pack_edge(base, target, edge_relation, evidence, score, 1)
                for target, edge_relation, evidence, score in window
            ]
            page.extend([0] * (params.page_size - len(page)))
            pool.append(page)
        descriptor = config.pack_descriptor(page_base, required_pages)
        blocked = config.blocked_directory_index(source, relation)
        if config.uses_hybrid_directory and blocked is None:
            residual_descriptors[
                config.dense_directory_index(source, relation) + 1
            ] = descriptor
        else:
            directory[blocked] = descriptor

    realized = len(pool)
    # Pad to the public budget so the shared table shape reveals only the
    # declared bound, never the owner's realized page population, then add the
    # shifted-scan tail so a window read at any in-range base stays in range.
    while len(pool) < params.pool_rows:
        pool.append([0] * params.page_size)
    return OwnerPageLayout(
        owner=owner,
        directory=directory,
        pages=pool,
        realized_page_count=realized,
        residual_descriptors=residual_descriptors,
    )


def owner_occupancy_vector(
    config: RelationPageConfig, owner: str, edges: list[dict[str, Any]]
) -> list[int]:
    """This owner's realized edge count for every directory row.

    Used only by the federation-wide bound check. Every owner writes its count
    at the *same* bit position, so the servers' additive sum of the shares is
    already the federation-wide count for that key -- no unpacking, no oblivious
    read, and no owner learning another's counts.

    The vector is the same height as the directory, so it reveals nothing new
    about shape; the values themselves are secret shares.
    """

    grouped = _grouped_edges(config, owner, edges)
    occupancy = [0] * (
        config.dense_directory_rows
        if config.uses_hybrid_directory
        else config.directory_rows
    )
    for (source_slot, relation_id), records in grouped.items():
        # The global bound is over every key, including hybrid residual keys, so
        # it always uses the full dense public keyspace.
        index = config.dense_directory_index(source_slot, relation_id)
        occupancy[index] = len(records)
    return occupancy


def check_global_frontier(
    config: RelationPageConfig,
    owner_edges: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Check the federation-wide per-key bound that ``global_frontier`` asserts.

    ``frontier_per_owner`` is enforced by each owner on its own data, alone and
    fail-closed. ``global_frontier`` cannot be: it bounds a sum across owners,
    and no owner can see that sum. This helper performs the check when the
    plaintext union happens to be available -- which is true for tests, for
    fixture construction, and for a single operator running a simulation, and
    **false in a real deployment**.

    In a real deployment the same check has to be run without anyone seeing the
    union. It is a one-time preparation-phase computation over the directory,
    not a per-query cost, so an MPC pass that sums the per-owner descriptors for
    each key and compares against the bound is affordable. That pass is **not
    implemented here**; until it is, ``global_frontier`` is a *declared and
    trusted* bound in deployment, and this function only verifies it offline.

    Returns a report; raises ``ValueError`` if the bound is violated, so callers
    fail closed exactly as the owner-local path does.
    """

    bound = config.pages.global_frontier
    if bound is None:
        raise ValueError("layout does not declare global_frontier")

    totals: Counter[tuple[str, str]] = Counter()
    for owner, edges in owner_edges.items():
        if owner not in config.base.owners:
            raise ValueError(f"unknown owner: {owner}")
        for edge in edges:
            totals[(edge["source"], edge["relation"])] += 1

    worst = max(totals.values(), default=0)
    violations = sorted(key for key, count in totals.items() if count > bound)
    if violations:
        raise ValueError(
            f"global_frontier is {bound} but {len(violations)} "
            f"(source, relation) keys exceed it federation-wide; the widest "
            f"holds {worst} edges. Raise global_frontier to at least {worst} "
            "or the second hop would silently drop matches."
        )
    return {
        "global_frontier": bound,
        "distinct_keys_federation_wide": len(totals),
        "max_key_degree_federation_wide": worst,
        "headroom": bound - worst,
        "checked_owners": sorted(owner_edges),
        "enforcement": (
            "offline plaintext check over the union; a deployment needs the "
            "equivalent one-time MPC pass, which is not implemented"
        ),
    }


def owner_layout_report(layout: OwnerPageLayout, config: RelationPageConfig) -> dict[str, Any]:
    """Private occupancy report for one built owner layout."""

    blocked_occupied = sum(
        1 for value in layout.directory if value != EMPTY_DESCRIPTOR
    )
    residual_occupied = len(layout.residual_descriptors or {})
    occupied = blocked_occupied + residual_occupied
    directory_capacity = config.directory_rows
    if config.uses_hybrid_directory:
        directory_capacity += (
            config.pages.directory_buckets * config.pages.bucket_slots
        )
    stored_edges = sum(
        1
        for page in layout.pages
        for value in page
        if value != 0
    )
    return {
        "audit_scope": "supplied_file_only",
        "owner": layout.owner,
        "directory_rows": config.directory_rows,
        "directory_capacity_slots_per_owner": directory_capacity,
        "occupied_directory_rows": occupied,
        "occupied_type_block_rows": blocked_occupied,
        "occupied_hashed_residual_keys": residual_occupied,
        "directory_occupancy": (
            occupied / directory_capacity if directory_capacity else 0.0
        ),
        "realized_page_count": layout.realized_page_count,
        "page_budget": config.pages.page_budget,
        "page_budget_headroom": config.pages.page_budget - layout.realized_page_count,
        "stored_edge_count": stored_edges,
        "padded_edge_slots": config.pages.page_budget * config.pages.page_size,
        "slot_amplification": (
            (config.pages.page_budget * config.pages.page_size) / stored_edges
            if stored_edges
            else 0.0
        ),
    }


def evaluate_paged_cleartext(
    config: RelationPageConfig,
    owner_edges: dict[str, list[dict[str, Any]]],
    query: dict[str, str],
    *,
    prepared_layouts: dict[str, OwnerPageLayout] | None = None,
) -> list[dict[str, int]]:
    """Independent cleartext oracle for the relation-paged semantics.

    It walks the *built layout* the way the future circuit will: resolve the
    directory at the affine address, read a fixed ``pages_per_key`` window, and
    treat every stored slot as a hop-1 match because the index already selected
    the relation. Ranking and the output contract match the supported backend:
    descending score, ties broken by the fixed public slot order, padded to
    ``top_k``.
    """

    base = config.base
    if set(owner_edges) != set(base.owners):
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
        source = base.entities[query["source"]]
        relation_1 = base.relations[query["relation_1"]]
        relation_2 = base.relations[query["relation_2"]]
    except (KeyError, TypeError) as exc:
        raise ValueError("query uses an unknown ontology item") from exc

    layouts = prepared_layouts
    if layouts is None:
        layouts = {
            owner: build_owner_page_layout(config, owner, owner_edges[owner])
            for owner in base.owners
        }
    elif set(layouts) != set(base.owners):
        raise ValueError(
            "prepared layouts must contain every configured owner exactly once"
        )
    from .packed import unpack_edge

    def read_key(
        entity: int, relation: int, *, compact: bool
    ) -> list[tuple[int, int, int, int]]:
        """Fixed-shape read: owner-major, page-major, slot-major.

        ``compact`` models the circuit's stable owner-local compaction of the
        first-hop frontier to ``frontier_per_owner`` dependent reads. It is
        lossless because preparation already rejected any key exceeding that
        declared bound.
        """

        params = config.pages
        width = (
            params.effective_frontier_per_owner if compact else params.slots_per_key
        )
        result: list[tuple[int, int, int, int]] = []
        for owner in base.owners:
            layout = layouts[owner]
            if entity == 0:
                descriptor = EMPTY_DESCRIPTOR
            else:
                blocked = config.blocked_directory_index(entity, relation)
                if config.uses_hybrid_directory and blocked is None:
                    descriptor = (layout.residual_descriptors or {}).get(
                        config.dense_directory_index(entity, relation) + 1,
                        EMPTY_DESCRIPTOR,
                    )
                else:
                    descriptor = layout.descriptor(blocked)
            page_base, page_count = config.unpack_descriptor(descriptor)
            slots: list[tuple[int, int, int, int]] = []
            for page_number in range(params.pages_per_key):
                active = page_number < page_count
                page_index = page_base + page_number if active else 0
                page = layout.pages[page_index]
                for value in page:
                    if not active or value == 0:
                        slots.append((0, 0, 0, 0))
                        continue
                    target, edge_relation, evidence, score, valid = unpack_edge(
                        base, value
                    )
                    if not valid or not target:
                        slots.append((0, 0, 0, 0))
                        continue
                    slots.append((target, edge_relation, evidence, score))
            if compact:
                matches = [slot for slot in slots if slot[0]]
                if len(matches) > width:
                    raise AssertionError(
                        "validated owner frontier exceeds its declared bound"
                    )
                slots = matches + [(0, 0, 0, 0)] * (width - len(matches))
            result.extend(slots)
        return result

    frontier = read_key(source, relation_1, compact=True)
    if config.pages.uses_global_frontier:
        # Second stable compaction, this time across owners, so the dependent
        # second hop is a fixed width instead of one proportional to the size
        # of the federation. Order is preserved, so the circuit's tie-break
        # indices stay identical to the per-owner path.
        width = config.pages.global_frontier
        matches = [slot for slot in frontier if slot[0]]
        if len(matches) > width:
            raise AssertionError(
                "federation-wide frontier exceeds the declared global_frontier; "
                "check_global_frontier should have rejected this layout"
            )
        frontier = matches + [(0, 0, 0, 0)] * (width - len(matches))
    candidates: list[tuple[int, int, int, int, int]] = []
    second_width = len(base.owners) * config.pages.slots_per_key
    for first_index, (target, _, left_handle, first_score) in enumerate(frontier):
        if not target:
            continue
        for second_index, (
            terminal,
            _,
            right_handle,
            second_score,
        ) in enumerate(read_key(target, relation_2, compact=False)):
            if not terminal:
                continue
            candidates.append(
                (
                    -(first_score + second_score),
                    first_index * second_width + second_index,
                    left_handle,
                    right_handle,
                    terminal,
                )
            )
    candidates.sort()

    selected: list[tuple[int, int, int, int, int]] = []
    seen_terminals: set[int] = set()
    for candidate in candidates:
        terminal = candidate[4]
        if base.deduplicate_terminal_answers and terminal in seen_terminals:
            continue
        selected.append(candidate)
        seen_terminals.add(terminal)
        if len(selected) == base.top_k:
            break

    results: list[dict[str, int]] = []
    for rank in range(base.top_k):
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


def paged_cost_estimate(
    config: RelationPageConfig,
    query_count: int,
    *,
    compacted_frontier_slots: int | None = None,
) -> dict[str, Any]:
    """Public circuit-shape cost of the paged layout vs the supported scan.

    Counts are secret multiplications in the selected-product sense used by
    ``scan_program.scan_cost_estimate``: one per (table row, output slot) pair
    touched by a secret-index linear lookup. Both backends read every row of
    every table they touch, so these are directly comparable.

    ``compacted_frontier_slots`` models composing this layout with the frontier
    compaction already implemented for the scan backend: the hop-1 window of
    ``owner_count * pages_per_key * page_size`` slots is obliviously compacted
    to a smaller fixed number of dependent reads. The second hop dominates
    total cost, so this parameter is the primary tuning knob.
    """

    if query_count < 1:
        raise ValueError("query_count must be positive")
    base = config.base
    params = config.pages
    owner_count = len(base.owners)

    # One directory read yields all owners' descriptors for a key.
    if config.uses_hybrid_directory:
        blocked_products = config.directory_rows * config.directory_columns
        compact_width = owner_count * params.bucket_slots
        compact_products = (
            config.residual_directory_rows * compact_width
            + compact_width * config.residual_tag_bits
        )
        directory_products = blocked_products + compact_products
    else:
        blocked_products = None
        compact_products = None
        # Descriptors for several owners are bit-packed into a field element.
        # The circuit scans packed columns, not one independent value per owner.
        directory_products = config.directory_rows * config.directory_columns
    # One demux per owner serves the whole consecutive page window, so the
    # window costs one shifted pass over the budget per public offset.
    page_products = (
        owner_count * params.pages_per_key * params.page_budget * params.page_size
    )
    per_address = directory_products + page_products

    # The executable circuit uses the global bound when one is declared.  Keep
    # the second-hop output width separate: every dependent key still yields
    # every owner's fixed page window even when only one federation-wide
    # frontier entity is dereferenced.
    second_width = owner_count * params.slots_per_key
    frontier_slots = params.frontier_slots(owner_count)
    declared_reads = frontier_slots
    if compacted_frontier_slots is not None:
        if not 1 <= compacted_frontier_slots <= second_width:
            raise ValueError(
                "compacted_frontier_slots must be in "
                f"[1, {second_width}]"
            )
        dependent_reads = compacted_frontier_slots
    else:
        dependent_reads = declared_reads
    first_hop = query_count * per_address
    second_hop = query_count * dependent_reads * per_address

    # Supported backend, same query batch, for reference.
    scan_first = base.entity_count * query_count * base.block_edges
    scan_second = (
        base.entity_count * query_count * base.frontier_edges * base.block_edges
    )
    return {
        "layout": "relation-paged (experimental)",
        "query_count": query_count,
        "directory_rows": config.directory_rows,
        "page_budget": params.page_budget,
        "page_size": params.page_size,
        "pages_per_key": params.pages_per_key,
        "pool_rows": params.pool_rows,
        "frontier_per_owner": params.effective_frontier_per_owner,
        "frontier_slots": frontier_slots,
        "declared_dependent_reads_per_query": declared_reads,
        "dependent_reads_per_query": dependent_reads,
        "candidate_count_per_query": dependent_reads * second_width,
        "per_address_directory_products": directory_products,
        "per_address_type_block_products": blocked_products,
        "per_address_hashed_residual_products": compact_products,
        "per_address_page_products": page_products,
        "first_hop_products": first_hop,
        "second_hop_products": second_hop,
        "total_lookup_products": first_hop + second_hop,
        "packed_scan_first_hop_products": scan_first,
        "packed_scan_second_hop_products": scan_second,
        "packed_scan_total_lookup_products": scan_first + scan_second,
        "second_hop_ratio_vs_packed_scan": (
            second_hop / scan_second if scan_second else None
        ),
        "comparison_note": (
            "The packed-scan figures use the *configured* fanout_per_owner. "
            "They are only a like-for-like comparison when that configuration "
            "is lossless for the same dataset; a capped configuration is "
            "cheaper because it stores fewer edges."
        ),
    }


def relation_split_cost_advantage(
    config: RelationPageConfig,
    lossless_fanout_per_owner: int,
    query_count: int,
    *,
    compacted_frontier_slots: int | None = None,
) -> dict[str, Any]:
    """Compare against the fanout the packed scan would need to be lossless.

    ``lossless_fanout_per_owner`` comes from
    ``capacity_planning.degree_profile()['max_source_degree']`` over the raw
    dataset. This is the honest comparison for a losslessness claim: the packed
    scan must widen every bucket to the global maximum source degree, while the
    paged layout only widens the pages of the keys that need them.
    """

    if lossless_fanout_per_owner < 1:
        raise ValueError("lossless_fanout_per_owner must be positive")
    base = config.base
    owner_count = len(base.owners)
    paged = paged_cost_estimate(
        config, query_count, compacted_frontier_slots=compacted_frontier_slots
    )

    lossless_block_edges = owner_count * lossless_fanout_per_owner
    lossless_second = (
        base.entity_count * query_count * lossless_block_edges * lossless_block_edges
    )
    return {
        "lossless_fanout_per_owner": lossless_fanout_per_owner,
        "lossless_packed_scan_block_edges": lossless_block_edges,
        "lossless_packed_scan_second_hop_products": lossless_second,
        "paged_second_hop_products": paged["second_hop_products"],
        "paged_speedup_vs_lossless_packed_scan": (
            lossless_second / paged["second_hop_products"]
            if paged["second_hop_products"]
            else None
        ),
    }
