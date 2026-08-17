"""EXPERIMENTAL type-blocked directory: the knowledge-graph-specific layout.

The one-sentence version
------------------------
A relation has a *domain*, so most ``(entity, relation)`` pairs are not merely
absent from the data -- they are **impossible under the ontology**. An ontology is
public, so deleting those rows shrinks the oblivious index without deleting any
secret.

Why this is a knowledge-graph design and not a graph design
-----------------------------------------------------------
GORAM (PVLDB'25, ABY3) operates on graphs whose edges are untyped, and an untyped
edge has no domain: there is no publicly-known sparsity to exploit. A knowledge
graph's adjacency is a 3-tensor ``entity x relation x entity``, and that third
dimension is simultaneously why this project's directory is expensive
(``E * R`` rows, 0.154% occupied on WebQSP) and why it need not be. See
``KG_VS_PLAIN_GRAPH.md``.

Measured on real WebQSP: 771,502,600 dense rows collapse to 5,785,620 -- 133x --
with the widest relation block 4x narrower than the entity universe.

The two security preconditions
------------------------------
Both are load-bearing. Violate either and this leaks.

1. **The type map must be EXTERNAL public input** -- a published ontology, not
   something derived from the federation's edges. If block widths are a function
   of which entities the owners actually hold, publishing them leaks owner data.
   ``scripts/measure_type_blocking.py`` derives types from observed relations,
   which is fine for sizing analysis and **not** a deployment path; its 133x is
   an upper bound for that reason.

2. **Per-address reads must be padded to the GLOBAL maximum block width**, never
   to the queried relation's own block. Reading ``n_dom(r2)`` rows instead of
   ``max_r n_dom(r)`` would make communication a function of the queried
   relation's domain, leaking query content. ``max_block`` exists for this and
   ``block_of`` never returns a narrower width to a caller sizing a read.

Given both, this layout adds **no data-dependent public parameter at all** -- one
fewer than the hashed compact directory, whose ``bucket_slots`` needs
``public_capacity_bound`` to be safe (``LEAKAGE_ABUSE.md`` §8).

Addressing, and why it stays cheap
----------------------------------
Entities are renumbered so each type class is contiguous, so a relation's block
is a contiguous window and the address is *affine* in the secret entity::

    address = c_r + entity          c_r = block_start_r - type_start_dom(r)

``c_r`` is a public table read at a **secret** relation, which costs one demux
over ``relation_count`` -- negligible beside the directory, and ``relation_count``
is the small dimension. After that there is no multiplication, exactly as the
dense address had none. The same demux yields the bounds for the range check that
sends an entity outside the block to the dummy row.

Status
------
Layout, addressing and cleartext reference. The circuit consumes this through the
same read machinery as the dense layout -- only ``DIRECTORY_ROWS`` and the
address computation change -- so nothing here needs a new read primitive. The
*supported* backend remains the packed scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence


DUMMY_TYPE = "\x00dummy"


def domain_from_name(relation: str) -> str:
    """Freebase names are ``domain.type.property``, so the domain is the prefix.

    A convenience for Freebase-derived graphs only. It is a *syntactic* reading of
    a public relation name and therefore still public input, but a KG whose
    relation names do not encode their domain must supply ``relation_domains``
    explicitly rather than rely on this.
    """

    return relation.rsplit(".", 1)[0] if "." in relation else relation


@dataclass(frozen=True)
class TypeBlockedLayout:
    """A directory laid out as one contiguous block per relation.

    Every field here is a function of the public type map and relation vocabulary
    alone. Nothing is derived from any owner's edges, which is what makes
    publishing the whole structure leakage-free.
    """

    entity_order: tuple[str, ...]
    entity_index: Mapping[str, int]
    type_start: Mapping[str, int]
    type_size: Mapping[str, int]
    relation_order: tuple[str, ...]
    block_start: Mapping[str, int]
    relation_domain: Mapping[str, str]

    @property
    def total_rows(self) -> int:
        """Directory height. Replaces entity_count * relation_count."""

        return sum(
            self.type_size[self.relation_domain[relation]]
            for relation in self.relation_order
        )

    @property
    def max_block(self) -> int:
        """Widest relation block.

        Every per-address read must be sized to THIS, not to the queried
        relation's own block, or the read width reveals the relation's domain.
        """

        return max(
            (
                self.type_size[self.relation_domain[relation]]
                for relation in self.relation_order
            ),
            default=1,
        )

    def block_of(self, relation: str) -> tuple[int, int, int]:
        """``(block_start, type_start, width)`` for one relation.

        ``width`` is this relation's own block width and is for *layout* use --
        placing rows, sizing the owner vector. A caller sizing an oblivious read
        must use ``max_block``.
        """

        domain = self.relation_domain[relation]
        return (
            self.block_start[relation],
            self.type_start[domain],
            self.type_size[domain],
        )

    def coefficient(self, relation: str) -> int:
        """``c_r`` such that ``address = c_r + entity_index[entity]``."""

        block_start, type_start, _ = self.block_of(relation)
        return block_start - type_start

    def address(self, entity: str, relation: str) -> int | None:
        """Row for this key, or None when the ontology forbids it.

        None is the type-invalid case, which the circuit maps to the dummy row.
        It is not an error: most pairs are type-invalid, and that is the point.
        """

        index = self.entity_index.get(entity)
        if index is None or relation not in self.relation_domain:
            return None
        _, type_start, width = self.block_of(relation)
        if not type_start <= index < type_start + width:
            return None
        return self.coefficient(relation) + index

    def coefficient_table(self) -> list[tuple[int, int, int]]:
        """Per-relation ``(c_r, type_start, width)``, in relation-id order.

        This is the public table the circuit reads at a secret relation with one
        demux over ``relation_count``. Emitting it here keeps the circuit's view
        and the layout's view of the arithmetic identical by construction.
        """

        table = []
        for relation in self.relation_order:
            block_start, type_start, width = self.block_of(relation)
            table.append((block_start - type_start, type_start, width))
        return table


def build_layout(
    entity_types: Mapping[str, str],
    relation_domains: Mapping[str, str],
) -> TypeBlockedLayout:
    """Lay out the directory from the public type map and relation signatures.

    Entities are ordered by type so each class is contiguous; that is what makes a
    relation's block a window and the address affine. Within a type the order is
    by name, so the layout is deterministic and every party derives the same one
    from the same public input without coordinating.

    Relations whose domain holds no entity still receive a zero-width block, so
    the relation vocabulary is unchanged and no relation becomes unaskable.
    """

    by_type: dict[str, list[str]] = {}
    for entity, entity_type in entity_types.items():
        by_type.setdefault(entity_type, []).append(entity)

    # Entity id 0 stays the reserved dummy, exactly as in the dense layout, so a
    # gated-off address still lands on a row that is empty for every relation.
    entity_order: list[str] = []
    type_start: dict[str, int] = {}
    type_size: dict[str, int] = {}
    cursor = 1
    for entity_type in sorted(by_type):
        members = sorted(by_type[entity_type])
        type_start[entity_type] = cursor
        type_size[entity_type] = len(members)
        entity_order.extend(members)
        cursor += len(members)
    type_start.setdefault(DUMMY_TYPE, 0)
    type_size.setdefault(DUMMY_TYPE, 1)

    relation_order = tuple(sorted(relation_domains))
    block_start: dict[str, int] = {}
    offset = 0
    for relation in relation_order:
        domain = relation_domains[relation]
        block_start[relation] = offset
        offset += type_size.get(domain, 0)

    return TypeBlockedLayout(
        entity_order=tuple(entity_order),
        entity_index={
            entity: position + 1 for position, entity in enumerate(entity_order)
        },
        type_start=type_start,
        type_size={**type_size, **{
            relation_domains[r]: type_size.get(relation_domains[r], 0)
            for r in relation_order
        }},
        relation_order=relation_order,
        block_start=block_start,
        relation_domain=dict(relation_domains),
    )


def build_owner_vector(
    layout: TypeBlockedLayout,
    keyed_descriptors: Mapping[tuple[str, str], int],
) -> list[int]:
    """One owner's directory vector: its descriptor at each row it occupies.

    Zero everywhere else, so the servers' modular sum is the assembled table and
    no owner needs to know another's keys -- the independence property the dense
    layout had and that any replacement must keep.

    Refuses a key the ontology forbids rather than dropping it: a type-invalid
    edge means the type map and the data disagree, and silently discarding it
    would make the circuit disagree with the oracle for a reason no test would
    attribute correctly.
    """

    vector = [0] * layout.total_rows
    for (entity, relation), descriptor in keyed_descriptors.items():
        address = layout.address(entity, relation)
        if address is None:
            raise ValueError(
                f"({entity!r}, {relation!r}) is type-invalid under the supplied "
                "ontology: the type map and the data disagree. Fix the type map "
                "or exclude the edge deliberately; do not let it be dropped here."
            )
        vector[address] = descriptor
    return vector


def lookup_cleartext(
    vectors: Sequence[Sequence[int]],
    layout: TypeBlockedLayout,
    entity: str,
    relation: str,
) -> list[int]:
    """The reference the circuit must match: each owner's descriptor, 0 if absent."""

    address = layout.address(entity, relation)
    if address is None:
        return [0] * len(vectors)
    return [vector[address] for vector in vectors]


def cost_model(
    layout: TypeBlockedLayout,
    *,
    frontier_addresses: int,
    folded: bool = False,
) -> int:
    """Modelled products, comparable with ``compact_directory.dense_products``.

    ``folded=False`` is what the circuit does today: every address reads the whole
    table. ``folded=True`` is the planned refinement -- extract the queried
    relation's block once, then read it per address at ``max_block`` width -- and
    is reported separately because it is not implemented.
    """

    if folded:
        return layout.total_rows + (
            layout.total_rows + frontier_addresses * layout.max_block
        )
    return (1 + frontier_addresses) * layout.total_rows
