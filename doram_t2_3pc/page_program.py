"""EXPERIMENTAL MP-SPDZ circuit for the relation-paged adjacency layout.

Same threat model as the supported packed scan: exactly three MP-SPDZ ``Semi``
servers, static passive adversary corrupting any two, 3-of-3 additive input and
output sharing, external owners and client. No new primitive, no dealer, no
trusted setup.

What this circuit does differently from ``scan_program``
-------------------------------------------------------
1. **Two-level index.** A dense ``(source, relation)`` directory is read at the
   secret address ``source * relation_count + (relation - 1)``. That address is
   an *affine* function of two secret values, so it costs no multiplication and
   is never opened. The descriptor it returns locates a window in a compact
   page pool, which is then read at a second secret address.
2. **No first-hop relation comparison.** The index resolves the relation, so the
   per-slot secret ``relation == relation_1`` equality test of the scan backend
   disappears. Pages for a key contain only that key's edges by construction.
3. **One demux per page window.** A key's pages are consecutive, so a single
   one-hot selector over the page pool serves every offset ``j`` of the
   ``pages_per_key``-wide window: offset ``j`` is a pass over the same pool
   shifted by ``j``. Trailing dummy rows keep the shifted access in range
   without branching on the secret base.

Every table is still read by a full linear scan. This is a *narrower* oblivious
lookup, not a sublinear one, and it does not implement persistent ORAM state.

Defence in depth
----------------
The passive model assumes honest input formation, but the circuit still
range-checks everything it uses as an address: query source and relations,
descriptor page base and page count, and second-hop targets. A value failing
its check is replaced by the reserved dummy address, so a malformed share can
corrupt a result but cannot steer a read out of its table.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .config import SCALABLE_FIELD_PRIME
from .packed import packed_edge_bits, packing_widths
from .relation_pages import RelationPageConfig


PAGE_PROGRAM_VERSION = 1
MAX_BATCH_QUERIES = 10


def _validate(config: RelationPageConfig, query_count: int) -> None:
    base = config.base
    if base.field_prime != SCALABLE_FIELD_PRIME:
        raise ValueError("the relation-paged circuit requires field_prime=2^127-1")
    if not 1 <= query_count <= MAX_BATCH_QUERIES:
        raise ValueError(f"query_count must be in [1, {MAX_BATCH_QUERIES}]")
    if packed_edge_bits(base) > base.field_usable_bits:
        raise ValueError("packed edge does not fit the scalable field")
    if config.pages.descriptor_bits > base.field_usable_bits:
        raise ValueError("page descriptor does not fit the scalable field")
    params = config.pages
    candidate_count = (
        params.frontier_slots(len(base.owners))
        * len(base.owners)
        * params.slots_per_key
    )
    if base.top_k > candidate_count:
        raise ValueError(
            f"top_k exceeds the paged candidate count {candidate_count}"
        )
    # ``reject_scan_only_options`` guards options this backend does not model;
    # terminal deduplication is implemented below, so only the scan-specific
    # relation fanout is rejected here.
    if base.relation_fanout_per_owner is not None:
        raise ValueError(
            "the relation-paged backend replaces relation_fanout_per_owner "
            "with relation_page_layout.frontier_per_owner"
        )


def _check_compaction_ablation(config: RelationPageConfig) -> None:
    """Refuse to skip compaction unless the frontier is already full width.

    Removing the compaction loop makes the frontier arrays alias the first-hop
    arrays, which is only lossless when every occupied slot has a frontier slot
    to land in. Silently narrowing here would drop real matches.
    """

    params = config.pages
    if params.uses_global_frontier:
        # The ablated circuit aliases the frontier arrays onto the first-hop
        # arrays, which is only sound when the two have the same width. A
        # federation-wide frontier is deliberately narrower than
        # owner_count * slots_per_key, so aliasing would read past the end.
        raise ValueError(
            "ablate_compaction is incompatible with global_frontier: the "
            f"frontier is {params.global_frontier} slots wide but the "
            "first-hop arrays are owner_count * page_size * pages_per_key "
            "wide, so aliasing them would not measure compaction, it would "
            "produce a different circuit"
        )
    if params.effective_frontier_per_owner != params.slots_per_key:
        raise ValueError(
            "ablate_compaction requires frontier_per_owner == page_size * "
            f"pages_per_key ({params.slots_per_key}); this layout declares "
            f"{params.effective_frontier_per_owner}, so skipping compaction "
            "would discard matches instead of measuring its cost"
        )


def program_name(
    config: RelationPageConfig,
    query_count: int,
    *,
    ablate_relation_check: bool = False,
    ablate_window_demux: bool = False,
    ablate_folded_directory: bool = False,
    ablate_compaction: bool = False,
) -> str:
    _validate(config, query_count)
    if ablate_compaction:
        _check_compaction_ablation(config)
    # Ablation variants must not share a compiled program with the real one.
    ablation = (
        f"{int(ablate_relation_check)}{int(ablate_window_demux)}"
        f"{int(ablate_compaction)}{int(ablate_folded_directory)}"
    )
    material = (
        f"{PAGE_PROGRAM_VERSION}:{query_count}:{ablation}:{config.digest}".encode()
    )
    suffix = hashlib.sha256(material).hexdigest()[:16]
    return f"paged_kg_3pc_{suffix}"


def _dedup_fragments(enabled: bool) -> tuple[str, str, str, str, str]:
    if not enabled:
        return (
            "",
            "",
            "",
            "",
            "            suppress = best_index == candidate",
        )
    return (
        "    candidate_terminal = Array(CANDIDATE_COUNT, sint)",
        "            candidate_terminal[candidate] = valid * terminal",
        "        best_terminal = sint(0)",
        """            best_terminal = better.if_else(
                candidate_terminal[candidate], best_terminal
            )""",
        """            same_terminal = candidate_terminal[candidate] == best_terminal
            suppress = same_terminal""",
    )


def render_program(
    config: RelationPageConfig,
    query_count: int,
    *,
    ablate_relation_check: bool = False,
    ablate_window_demux: bool = False,
    ablate_folded_directory: bool = False,
    ablate_compaction: bool = False,
) -> str:
    """Render the paged circuit.

    The three ``ablate_*`` switches exist solely to attribute measured speedups
    to individual optimizations. They are deliberately renderer arguments rather
    than configuration fields so they can never be set by a deployed layout, and
    none changes the circuit's output.

    ``ablate_relation_check``
        Restore the per-slot first-hop ``relation == relation_1`` equality test
        that relation-resolved indexing makes redundant. Semantically a no-op:
        pages for a key contain only that key's edges by construction.
    ``ablate_window_demux``
        Build one selector per page offset instead of sharing a single selector
        across the consecutive window. Only observable when
        ``pages_per_key > 1``.
    ``ablate_folded_directory``
        Read the hop-two directory at the combined ``entity * R + relation``
        address instead of folding the shared relation out first. The folded
        path costs ``E*R + n*E`` where this costs ``n*E*R``; both must return
        identical descriptors, and the regression asserts they do.
    ``ablate_compaction``
        Drop the owner-local frontier compaction and carry every first-hop slot
        into the second hop. Only permitted when the declared frontier already
        equals the full slot width, so the two circuits return the same rows.
    """

    _validate(config, query_count)
    if ablate_compaction:
        _check_compaction_ablation(config)
    base = config.base
    params = config.pages
    slot_bits, relation_bits, evidence_bits, score_bits, _ = packing_widths(base)
    owner_count = len(base.owners)
    relation_count = config.relation_count
    directory_rows = config.directory_rows
    dir_index_bits = max(1, (directory_rows - 1).bit_length())
    ent_index_bits = max(1, (base.entity_count - 1).bit_length())
    rel_index_bits = max(1, (relation_count - 1).bit_length())
    from .compact_directory import HASH_WORD_BITS, MULTIPLIER as HASH_MULT
    hash_multiplier = HASH_MULT
    compact = params.uses_compact_directory
    directory_buckets = params.directory_buckets or 1
    bucket_slots = params.bucket_slots or 1
    bucket_width = owner_count * bucket_slots
    bucket_index_bits = max(1, (directory_buckets - 1).bit_length())
    # The tag is the dense address plus one, so it needs the dense index width;
    # packing it above the descriptor must still fit the usable field.
    tag_bits = max(1, directory_rows.bit_length())
    packed_slot_bits = tag_bits + params.descriptor_bits
    hash_word_bits = HASH_WORD_BITS
    hash_product_bits = tag_bits + HASH_MULT.bit_length()
    if compact:
        if packed_slot_bits > base.field_usable_bits:
            raise ValueError(
                f"compact slot needs {packed_slot_bits} bits (tag {tag_bits} + "
                f"descriptor {params.descriptor_bits}) but the field carries "
                f"{base.field_usable_bits}"
            )
        if bucket_index_bits > hash_word_bits:
            raise ValueError("directory_buckets exceeds the hash word width")
    directory_columns = config.directory_columns
    directory_slots = [config.directory_slot(i) for i in range(owner_count)]
    packed_directory_bits = min(
        base.field_usable_bits,
        config.owners_per_directory_element * params.descriptor_bits,
    )
    pool_index_bits = max(1, (params.page_budget - 1).bit_length())
    frontier_slots = params.frontier_slots(owner_count)
    second_width = owner_count * params.slots_per_key
    candidate_count = frontier_slots * second_width
    (
        terminal_array,
        terminal_store,
        best_terminal_init,
        best_terminal_update,
        suppress_update,
    ) = _dedup_fragments(base.deduplicate_terminal_answers)

    # ABLATION ONLY. The relation is already resolved by the index, so this
    # restores a redundant per-slot equality test to price what removing it
    # saved. `wanted_relation` is threaded in only when the switch is on.
    if ablate_relation_check:
        relation_gate = (
            "\n                    ablation_relation = sint.bit_compose("
            "\n                        window[source_index].bit_decompose("
            "PACKED_EDGE_BITS)[SLOT_BITS:SLOT_BITS + RELATION_BITS]"
            "\n                    )"
            "\n                    ok = ok * (ablation_relation == wanted[address])"
        )
        gate_signature = ", wanted"
        first_wanted_setup = (
            "first_wanted = Array(QUERY_COUNT, sint)\n"
            "for query_index in range(QUERY_COUNT):\n"
            "    first_wanted[query_index] = queries[query_index][1]\n"
        )
        first_wanted_arg = ", first_wanted"
        second_wanted_setup = (
            "second_wanted = Array(FRONTIER_COUNT, sint)\n"
            "for query_index in range(QUERY_COUNT):\n"
            "    for frontier_index in range(FRONTIER_SLOTS):\n"
            "        second_wanted[query_index * FRONTIER_SLOTS + frontier_index] "
            "= queries[query_index][2]\n"
        )
        second_wanted_arg = ", second_wanted"
    else:
        relation_gate = ""
        gate_signature = ""
        first_wanted_setup = ""
        first_wanted_arg = ""
        second_wanted_setup = ""
        second_wanted_arg = ""

    # Hop two folds the relation out of the directory before reading it, so the
    # frontier addresses cost ENTITY_COUNT each instead of DIRECTORY_ROWS. The
    # ablation restores the unfolded read, which must return identical rows.
    # Layout dispatch. The compact directory replaces the dense one for BOTH
    # hops: folding contracts a relation out of a table indexed by relation, and
    # the compact table is indexed by hash, so the two are alternatives rather
    # than composable.
    if compact:
        directory_storage = "compact = shared_matrix(DIRECTORY_BUCKETS, BUCKET_WIDTH)"
        first_descriptors = (
            "first_descriptors = read_compact_directory(\n"
            "    first_entities, first_relations, first_valids, QUERY_COUNT\n"
            ")"
        )
        second_descriptors = (
            "second_descriptors = read_compact_directory(\n"
            "    second_entities, second_relations, second_valids, FRONTIER_COUNT\n"
            ")"
        )
    elif ablate_folded_directory:
        directory_storage = (
            "directory = shared_matrix(DIRECTORY_ROWS, DIRECTORY_COLUMNS)"
        )
        first_descriptors = (
            "first_descriptors = read_directory(first_addresses, QUERY_COUNT)"
        )
        second_descriptors = (
            "second_descriptors = read_directory("
            "second_addresses, FRONTIER_COUNT)"
        )
    else:
        directory_storage = (
            "directory = shared_matrix(DIRECTORY_ROWS, DIRECTORY_COLUMNS)"
        )
        first_descriptors = (
            "first_descriptors = read_directory(first_addresses, QUERY_COUNT)"
        )
        # One fold per query -- each query carries its own relation_2 -- and
        # that query's FRONTIER_SLOTS addresses all read the table it produced.
        second_descriptors = '''second_descriptors = Array(
    FRONTIER_COUNT * DIRECTORY_COLUMNS, sint
)
for query_index in range(QUERY_COUNT):
    relation_2 = queries[query_index][2]
    folded = fold_directory(
        relation_2, (relation_2 != 0) * (relation_2 <= RELATION_COUNT)
    )
    slice_entities = Array(FRONTIER_SLOTS, sint)
    for frontier_index in range(FRONTIER_SLOTS):
        slice_entities[frontier_index] = second_entities[
            query_index * FRONTIER_SLOTS + frontier_index
        ]
    part = read_folded_directory(slice_entities, folded, FRONTIER_SLOTS)
    for frontier_index in range(FRONTIER_SLOTS):
        flat = query_index * FRONTIER_SLOTS + frontier_index
        for column in range(DIRECTORY_COLUMNS):
            second_descriptors[flat * DIRECTORY_COLUMNS + column] = part[
                frontier_index * DIRECTORY_COLUMNS + column
            ]'''

    # ABLATION ONLY. One selector per offset instead of one shared across the
    # consecutive window; observable only when pages_per_key > 1.
    if ablate_window_demux:
        window_read = '''def read_page_window(owner, bases, address_count):
    row_offset = owner * POOL_ROWS
    parts = []
    for offset in range(PAGES_PER_KEY):
        shifted = Array(address_count, sint)
        for address in range(address_count):
            shifted[address] = bases[address]
        shifted_bits = shifted.get_vector(0, address_count).bit_decompose(
            POOL_INDEX_BITS
        )
        selectors = demux_matrix(shifted_bits, n_threads=SCAN_THREADS)

        @map_sum(
            SCAN_THREADS,
            1024,
            PAGE_BUDGET,
            address_count * PAGE_SIZE,
            [sint] * (address_count * PAGE_SIZE),
        )
        def scan_page(page, offset=offset, selectors=selectors):
            selected = selectors[page]
            return tuple(
                selected[address] * pages[row_offset + page + offset][slot]
                for address in range(address_count)
                for slot in range(PAGE_SIZE)
            )

        parts.append(Array.create_from(scan_page()))
        selectors.delete()
    result = Array(address_count * PAGES_PER_KEY * PAGE_SIZE, sint)
    for address in range(address_count):
        for offset in range(PAGES_PER_KEY):
            for slot in range(PAGE_SIZE):
                result[
                    address * PAGES_PER_KEY * PAGE_SIZE + offset * PAGE_SIZE + slot
                ] = parts[offset][address * PAGE_SIZE + slot]
    return result'''
    else:
        window_read = '''def read_page_window(owner, bases, address_count):
    base_bits = bases.get_vector(0, address_count).bit_decompose(POOL_INDEX_BITS)
    selectors = demux_matrix(base_bits, n_threads=SCAN_THREADS)
    row_offset = owner * POOL_ROWS

    @map_sum(
        SCAN_THREADS,
        1024,
        PAGE_BUDGET,
        address_count * PAGES_PER_KEY * PAGE_SIZE,
        [sint] * (address_count * PAGES_PER_KEY * PAGE_SIZE),
    )
    def scan_page(page):
        selected = selectors[page]
        return tuple(
            selected[address] * pages[row_offset + page + offset][slot]
            for address in range(address_count)
            for offset in range(PAGES_PER_KEY)
            for slot in range(PAGE_SIZE)
        )

    result = Array.create_from(scan_page())
    selectors.delete()
    return result'''

    # ABLATION ONLY. Carry every first-hop slot into the second hop instead of
    # compacting it. Guarded above so the frontier is already full width, which
    # makes the array layouts identical and the aliasing exact.
    if ablate_compaction:
        compaction = """# ABLATION: no compaction.  FRONTIER_PER_OWNER equals SLOTS_PER_KEY here, so
# the first-hop arrays already have the frontier layout and carry through
# unchanged -- every slot, occupied or not, is paid for again in hop two.
frontier_targets = hop1_targets
frontier_handles = hop1_handles
frontier_scores = hop1_scores
frontier_valid = hop1_valid"""
    elif config.pages.uses_global_frontier:
        # Stable compaction ACROSS owners to one fixed federation-wide width.
        # The per-owner variant below emits owner_count * FRONTIER_PER_OWNER
        # slots, so the dependent second hop grows with the federation; this one
        # emits GLOBAL_FRONTIER slots regardless of how many owners there are.
        # Occupancy still rides in secret validity bits, so which owner filled
        # which slot -- and how many each filled -- stays hidden exactly as
        # before.
        compaction = """# Stable federation-wide compaction of the first-hop frontier.  The declared
# global_frontier bounds the per-key degree summed over ALL owners, so this
# discards no match; check_global_frontier verifies that bound offline.
frontier_targets = Array(FRONTIER_COUNT, sint)
frontier_handles = Array(FRONTIER_COUNT, sint)
frontier_scores = Array(FRONTIER_COUNT, sint)
frontier_valid = Array(FRONTIER_COUNT, sint)

for query_index in range(QUERY_COUNT):
    consumed = Array(SECOND_WIDTH, sint)
    for slot in range(SECOND_WIDTH):
        consumed[slot] = sint(0)
    for compact_slot in range(FRONTIER_SLOTS):
        found = sint(0)
        chosen_target = sint(0)
        chosen_handle = sint(0)
        chosen_score = sint(0)
        for slot in range(SECOND_WIDTH):
            flat = query_index * SECOND_WIDTH + slot
            available = hop1_valid[flat] * (sint(1) - consumed[slot])
            take = available * (sint(1) - found)
            found = found + take
            consumed[slot] = consumed[slot] + take
            chosen_target = chosen_target + take * hop1_targets[flat]
            chosen_handle = chosen_handle + take * hop1_handles[flat]
            chosen_score = chosen_score + take * hop1_scores[flat]
        compact_flat = query_index * FRONTIER_SLOTS + compact_slot
        frontier_valid[compact_flat] = found
        frontier_targets[compact_flat] = chosen_target
        frontier_handles[compact_flat] = chosen_handle
        frontier_scores[compact_flat] = chosen_score"""
    else:
        compaction = """# Stable owner-local compaction of the first-hop frontier.  Preparation already
# rejected any key exceeding FRONTIER_PER_OWNER, so this discards no match; the
# realized match count, its owner, and its slot all stay secret.
frontier_targets = Array(FRONTIER_COUNT, sint)
frontier_handles = Array(FRONTIER_COUNT, sint)
frontier_scores = Array(FRONTIER_COUNT, sint)
frontier_valid = Array(FRONTIER_COUNT, sint)

for query_index in range(QUERY_COUNT):
    for owner in range(OWNER_COUNT):
        consumed = Array(SLOTS_PER_KEY, sint)
        for slot in range(SLOTS_PER_KEY):
            consumed[slot] = sint(0)
        for compact_slot in range(FRONTIER_PER_OWNER):
            found = sint(0)
            chosen_target = sint(0)
            chosen_handle = sint(0)
            chosen_score = sint(0)
            for slot in range(SLOTS_PER_KEY):
                flat = (
                    query_index * SECOND_WIDTH + owner * SLOTS_PER_KEY + slot
                )
                available = hop1_valid[flat] * (sint(1) - consumed[slot])
                take = available * (sint(1) - found)
                found = found + take
                consumed[slot] = consumed[slot] + take
                chosen_target = chosen_target + take * hop1_targets[flat]
                chosen_handle = chosen_handle + take * hop1_handles[flat]
                chosen_score = chosen_score + take * hop1_scores[flat]
            compact_flat = (
                query_index * FRONTIER_SLOTS
                + owner * FRONTIER_PER_OWNER
                + compact_slot
            )
            frontier_valid[compact_flat] = found
            frontier_targets[compact_flat] = chosen_target
            frontier_handles[compact_flat] = chosen_handle
            frontier_scores[compact_flat] = chosen_score"""

    return f'''# Generated relation-paged two-level oblivious KG lookup (EXPERIMENTAL).
from Compiler.library import map_sum, print_ln_to, start_timer, stop_timer
from Compiler.oram import demux_matrix
from Compiler.types import Array, Matrix, sint

program.use_edabit(True)
program.timeout = None

SERVER_COUNT = 3
QUERY_COUNT = {query_count}
OWNER_COUNT = {owner_count}
ENTITY_COUNT = {base.entity_count}
RELATION_COUNT = {relation_count}
DIRECTORY_ROWS = {directory_rows}
DIR_INDEX_BITS = {dir_index_bits}
ENT_INDEX_BITS = {ent_index_bits}
REL_INDEX_BITS = {rel_index_bits}
HASH_MULTIPLIER = {hash_multiplier}
HASH_WORD_BITS = {hash_word_bits}
HASH_PRODUCT_BITS = {hash_product_bits}
DIRECTORY_BUCKETS = {directory_buckets}
BUCKET_SLOTS = {bucket_slots}
BUCKET_WIDTH = {bucket_width}
BUCKET_INDEX_BITS = {bucket_index_bits}
PACKED_SLOT_BITS = {packed_slot_bits}
TAG_BITS = {tag_bits}
PAGE_SIZE = {params.page_size}
PAGES_PER_KEY = {params.pages_per_key}
PAGE_BUDGET = {params.page_budget}
POOL_ROWS = {params.pool_rows}
POOL_INDEX_BITS = {pool_index_bits}
PAGE_BASE_BITS = {params.page_base_bits}
PAGE_COUNT_BITS = {params.page_count_bits}
DESCRIPTOR_BITS = {params.descriptor_bits}
DIRECTORY_COLUMNS = {directory_columns}
PACKED_DIRECTORY_BITS = {packed_directory_bits}
DIRECTORY_SLOTS = {directory_slots}
SLOTS_PER_KEY = {params.slots_per_key}
FRONTIER_PER_OWNER = {params.effective_frontier_per_owner}
FRONTIER_SLOTS = {frontier_slots}
SECOND_WIDTH = {second_width}
CANDIDATE_COUNT = {candidate_count}
TOP_K = {base.top_k}
DEDUPLICATE_TERMINAL_ANSWERS = {int(base.deduplicate_terminal_answers)}
SLOT_BITS = {slot_bits}
RELATION_BITS = {relation_bits}
EVIDENCE_BITS = {evidence_bits}
SCORE_BITS = {score_bits}
PACKED_EDGE_BITS = {packed_edge_bits(base)}
SCAN_THREADS = 16


def shared_matrix(rows, columns):
    result = Matrix(rows, columns, sint)
    result.input_from(0)
    for player in (1, 2):
        incoming = Matrix(rows, columns, sint)
        incoming.input_from(player)
        result.assign_vector(result[:] + incoming[:])
        incoming.delete()
    return result


def unpack_edge(packed):
    bits = packed.bit_decompose(PACKED_EDGE_BITS)
    offset = 0
    target = sint.bit_compose(bits[offset:offset + SLOT_BITS])
    offset += SLOT_BITS
    relation = sint.bit_compose(bits[offset:offset + RELATION_BITS])
    offset += RELATION_BITS
    evidence = sint.bit_compose(bits[offset:offset + EVIDENCE_BITS])
    offset += EVIDENCE_BITS
    score = sint.bit_compose(bits[offset:offset + SCORE_BITS])
    offset += SCORE_BITS
    valid = bits[offset]
    return target, relation, evidence, score, valid


def unpack_descriptor(packed, offset=0):
    # Several owners' descriptors share one field element in disjoint bit
    # ranges; `offset` selects this owner's range.
    bits = packed.bit_decompose(PACKED_DIRECTORY_BITS)[offset:offset + DESCRIPTOR_BITS]
    page_base = sint.bit_compose(bits[0:PAGE_BASE_BITS])
    page_count = sint.bit_compose(bits[PAGE_BASE_BITS:DESCRIPTOR_BITS])
    # Defence in depth: an out-of-range descriptor is forced to the reserved
    # dummy page instead of steering a read outside the pool.
    usable = (page_base < PAGE_BUDGET) * (page_count <= PAGES_PER_KEY)
    return usable.if_else(page_base, sint(0)), usable * page_count


# The directory address is affine in two secret values, so it needs no
# multiplication and is never opened.  Address zero is the dummy row.
def directory_address(entity, relation):
    entity_ok = (entity != 0) * (entity < ENTITY_COUNT)
    relation_ok = (relation != 0) * (relation <= RELATION_COUNT)
    ok = entity_ok * relation_ok
    address = entity * RELATION_COUNT + relation - 1
    return ok, ok.if_else(address, sint(0))


def read_directory(addresses, address_count):
    address_bits = addresses.get_vector(0, address_count).bit_decompose(
        DIR_INDEX_BITS
    )
    selectors = demux_matrix(address_bits, n_threads=SCAN_THREADS)

    @map_sum(
        SCAN_THREADS,
        1024,
        DIRECTORY_ROWS,
        address_count * DIRECTORY_COLUMNS,
        [sint] * (address_count * DIRECTORY_COLUMNS),
    )
    def scan_row(row):
        selected = selectors[row]
        descriptors = directory[row]
        return tuple(
            selected[address] * descriptors[column]
            for address in range(address_count)
            for column in range(DIRECTORY_COLUMNS)
        )

    result = Array.create_from(scan_row())
    selectors.delete()
    return result


# The compact directory
# ---------------------
# Sizes the index to the number of keys instead of to ENTITY_COUNT *
# RELATION_COUNT. A public hash sends each key to one of DIRECTORY_BUCKETS
# buckets; owner i occupies its own BUCKET_SLOTS columns of that bucket, so no
# owner needs to know another's keys. A bucket therefore holds several different
# keys and each slot carries its key tag above its descriptor, which the circuit
# must check before believing the descriptor -- the cost a dense table avoids.
#
# The hash runs HERE, on secret shares, because hop two's entities are hop one's
# *results*: the client cannot precompute their buckets. That rules out XOR- or
# modulus-based hashing and is why this is Fibonacci hashing -- the multiply is
# by a public constant, hence free, and the bucket index is a slice of one bit
# decomposition.
#
# This is a narrow win. It trades padding for a per-slot comparison and only
# pays above roughly 40x sparsity; below that the dense directory is cheaper.
# See compact_directory.py and benchmarks/compact_directory_planning.json.
def compact_bucket(tag):
    """Fibonacci hash of a secret tag -> secret bucket index."""

    # tag * MULTIPLIER is exact in the field (TAG_BITS + 64 < field width), so
    # decomposing HASH_PRODUCT_BITS gives the true product bits. The word
    # truncation is implicit: bits [0, HASH_WORD_BITS) *are* the product mod
    # 2^HASH_WORD_BITS, and the index is the top BUCKET_INDEX_BITS of those.
    product = Array(1, sint)
    product[0] = tag * HASH_MULTIPLIER
    bits = product.get_vector(0, 1).bit_decompose(HASH_PRODUCT_BITS)
    low = HASH_WORD_BITS - BUCKET_INDEX_BITS
    return sint.bit_compose(bits[low:HASH_WORD_BITS])


def read_compact_directory(entities, relations, valids, address_count):
    """Resolve address_count secret keys through the compact directory.

    Returns descriptors in exactly the packed layout read_directory produces --
    owner i's descriptor at its DIRECTORY_SLOTS offset -- so read_keys consumes
    either source without knowing which layout produced it.
    """

    tags = Array(address_count, sint)
    buckets = Array(address_count, sint)
    for address in range(address_count):
        # Tag 0 marks an empty slot, so a gated-off address gets tag 0 and can
        # never match a stored key. That replaces the dense path's dummy row.
        tag = valids[address].if_else(
            entities[address] * RELATION_COUNT + relations[address], sint(0)
        )
        tags[address] = tag
        buckets[address] = compact_bucket(tag)

    bucket_bits = buckets.get_vector(0, address_count).bit_decompose(
        BUCKET_INDEX_BITS
    )
    selectors = demux_matrix(bucket_bits, n_threads=SCAN_THREADS)

    # Fetch the selected bucket. Every bucket is touched because the selection is
    # secret; this is the term that shrinks from ENTITY_COUNT * RELATION_COUNT.
    @map_sum(
        SCAN_THREADS,
        1024,
        DIRECTORY_BUCKETS,
        address_count * BUCKET_WIDTH,
        [sint] * (address_count * BUCKET_WIDTH),
    )
    def scan_bucket(bucket):
        selected = selectors[bucket]
        row = compact[bucket]
        return tuple(
            selected[address] * row[column]
            for address in range(address_count)
            for column in range(BUCKET_WIDTH)
        )

    fetched = Array.create_from(scan_bucket())

    # Check the tag in each fetched slot, then rebuild the packed descriptor
    # element the dense path would have returned.
    #
    # Vectorised deliberately. Written as a scalar loop over
    # address_count * BUCKET_WIDTH slots this unrolls one bit decomposition per
    # slot, which compiled to over 4.4 million lines on a 75-slot bucket before
    # finishing -- the decomposition is the expensive part and there are
    # addresses * owners * slots of them. One vector operation over the whole
    # fetched block does the same work in a fraction of the program text.
    total_slots = address_count * BUCKET_WIDTH
    wanted = Array(total_slots, sint)
    for address in range(address_count):
        for column in range(BUCKET_WIDTH):
            wanted[address * BUCKET_WIDTH + column] = tags[address]

    slot_bits = fetched.get_vector(0, total_slots).bit_decompose(PACKED_SLOT_BITS)
    descriptors = sint.bit_compose(slot_bits[:DESCRIPTOR_BITS])

    # Compare at TAG_BITS width, not at the field width.
    #
    # `stored_tags == wanted` looks like the obvious way to write this, and it is
    # why an earlier version never compiled: a field equality is emitted at the
    # default 124-bit length, so every one of the address_count * BUCKET_WIDTH
    # slots paid a full-field zero test and compile.py exceeded 1800s on every
    # fixture tried. The tag is only TAG_BITS wide and its bits are already in
    # hand from the decomposition above, so the comparison costs TAG_BITS
    # operations instead of 124.
    stored_tag_bits = slot_bits[DESCRIPTOR_BITS:]
    wanted_bits = wanted.get_vector(0, total_slots).bit_decompose(TAG_BITS)
    # XNOR per bit: 1 - (a XOR b) = 1 - a - b + 2ab, one multiplication each.
    equal_bits = [
        1 - stored - asked + 2 * (stored * asked)
        for stored, asked in zip(stored_tag_bits, wanted_bits)
    ]
    # Balanced AND tree, so the depth is log2(TAG_BITS) rounds rather than
    # TAG_BITS -- rounds are what the wall clock feels on a real network.
    while len(equal_bits) > 1:
        paired = [
            equal_bits[index] * equal_bits[index + 1]
            for index in range(0, len(equal_bits) - 1, 2)
        ]
        if len(equal_bits) % 2:
            paired.append(equal_bits[-1])
        equal_bits = paired
    selected = Array.create_from(equal_bits[0] * descriptors)

    # Only additions remain, which cost no products; shifting each owner's
    # descriptor into its own bit range reproduces the dense packed element, so
    # read_keys cannot tell which layout produced this.
    result = Array(address_count * DIRECTORY_COLUMNS, sint)
    for address in range(address_count):
        accumulators = [sint(0)] * DIRECTORY_COLUMNS
        for owner in range(OWNER_COUNT):
            column_index, offset = DIRECTORY_SLOTS[owner]
            owner_total = sint(0)
            for slot in range(BUCKET_SLOTS):
                owner_total += selected[
                    address * BUCKET_WIDTH + owner * BUCKET_SLOTS + slot
                ]
            accumulators[column_index] += owner_total * (1 << offset)
        for column in range(DIRECTORY_COLUMNS):
            result[address * DIRECTORY_COLUMNS + column] = accumulators[column]
    selectors.delete()
    return result


# Folding the directory by relation
# ---------------------------------
# read_directory pays DIRECTORY_ROWS = ENTITY_COUNT * RELATION_COUNT products
# per address, because it demuxes the combined address entity*R + relation-1
# over the whole dense keyspace.
#
# Hop two does not need that. Every one of its FRONTIER_SLOTS addresses carries
# the SAME relation_2 -- only the entity differs. So the relation can be
# contracted out of the directory once, leaving a table indexed by entity
# alone, and each address then costs ENTITY_COUNT rather than ENTITY_COUNT *
# RELATION_COUNT:
#
#     n * E * R      ->      E * R  +  n * E
#
# which is a factor of n*R/(R+n): on a graph with many relations it approaches
# the address count. It is a pure re-association of the same sum -- the same
# products over the same shares, grouped differently -- so it adds no public
# parameter, changes no leakage, and must return identical descriptors. The
# ablation switch below restores the unfolded path so that equality can be
# checked rather than asserted.
#
# Hop one is deliberately NOT folded: it has one address per relation, so there
# is nothing to amortise and folding would add E products per query for nothing.
def fold_directory(relation, relation_ok):
    """Contract the directory down to one row per entity, at a secret relation."""

    index = Array(1, sint)
    index[0] = relation_ok.if_else(relation - 1, sint(0))
    relation_bits = index.get_vector(0, 1).bit_decompose(REL_INDEX_BITS)
    selector = demux_matrix(relation_bits, n_threads=1)

    @map_sum(
        SCAN_THREADS,
        1024,
        RELATION_COUNT,
        ENTITY_COUNT * DIRECTORY_COLUMNS,
        [sint] * (ENTITY_COUNT * DIRECTORY_COLUMNS),
    )
    def fold(relation_index):
        weight = selector[relation_index][0]
        return tuple(
            weight * directory[entity * RELATION_COUNT + relation_index][column]
            for entity in range(ENTITY_COUNT)
            for column in range(DIRECTORY_COLUMNS)
        )

    table = Array.create_from(fold())
    selector.delete()
    return table


def read_folded_directory(entities, table, address_count):
    """Read the folded table at address_count secret entities."""

    entity_bits = entities.get_vector(0, address_count).bit_decompose(
        ENT_INDEX_BITS
    )
    selectors = demux_matrix(entity_bits, n_threads=SCAN_THREADS)

    @map_sum(
        SCAN_THREADS,
        1024,
        ENTITY_COUNT,
        address_count * DIRECTORY_COLUMNS,
        [sint] * (address_count * DIRECTORY_COLUMNS),
    )
    def scan_entity(entity):
        selected = selectors[entity]
        return tuple(
            selected[address] * table[entity * DIRECTORY_COLUMNS + column]
            for address in range(address_count)
            for column in range(DIRECTORY_COLUMNS)
        )

    result = Array.create_from(scan_entity())
    selectors.delete()
    return result


# One demux serves the whole consecutive window: offset j is the same pool
# scanned shifted by j.  POOL_ROWS includes the trailing dummy rows that keep
# every shifted access in range.
{window_read}


def read_keys(descriptors, valids, address_count{gate_signature}):
    """Resolve address_count secret keys into address_count * SECOND_WIDTH slots.

    ``descriptors`` comes from either read_directory (unfolded, indexed by the
    combined address) or read_folded_directory (relation already contracted
    out). Both produce the same address_count * DIRECTORY_COLUMNS layout, so
    everything below this line is shared by the two paths.
    """

    targets = Array(address_count * SECOND_WIDTH, sint)
    handles = Array(address_count * SECOND_WIDTH, sint)
    scores = Array(address_count * SECOND_WIDTH, sint)
    slot_valid = Array(address_count * SECOND_WIDTH, sint)

    for owner in range(OWNER_COUNT):
        bases = Array(address_count, sint)
        counts = []
        for address in range(address_count):
            column, offset = DIRECTORY_SLOTS[owner]
            page_base, page_count = unpack_descriptor(
                descriptors[address * DIRECTORY_COLUMNS + column], offset
            )
            bases[address] = valids[address].if_else(page_base, sint(0))
            counts.append(valids[address] * page_count)
        window = read_page_window(owner, bases, address_count)
        for address in range(address_count):
            for offset in range(PAGES_PER_KEY):
                # Pages past the secret page count contribute nothing.
                active = counts[address] > offset
                for slot in range(PAGE_SIZE):
                    source_index = (
                        address * PAGES_PER_KEY * PAGE_SIZE
                        + offset * PAGE_SIZE
                        + slot
                    )
                    target_index = (
                        address * SECOND_WIDTH
                        + owner * SLOTS_PER_KEY
                        + offset * PAGE_SIZE
                        + slot
                    )
                    target, _, handle, score, stored = unpack_edge(
                        window[source_index]
                    )
                    ok = (
                        active
                        * stored
                        * (target != 0)
                        * (target < ENTITY_COUNT)
                    ){relation_gate}
                    slot_valid[target_index] = ok
                    targets[target_index] = ok * target
                    handles[target_index] = ok * handle
                    scores[target_index] = ok * score
    return targets, handles, scores, slot_valid


def emit_output_shares(query_index, rank, field, value):
    share_0 = sint.get_random()
    share_1 = sint.get_random()
    share_2 = value - share_0 - share_1
    print_ln_to(
        0, 'DORAM_BATCH_SHARE %s %s %s 0 %s',
        query_index, rank, field, share_0.reveal_to(0)
    )
    print_ln_to(
        1, 'DORAM_BATCH_SHARE %s %s %s 1 %s',
        query_index, rank, field, share_1.reveal_to(1)
    )
    print_ln_to(
        2, 'DORAM_BATCH_SHARE %s %s %s 2 %s',
        query_index, rank, field, share_2.reveal_to(2)
    )


queries = shared_matrix(QUERY_COUNT, 3)

start_timer(10)
{directory_storage}
pages = shared_matrix(OWNER_COUNT * POOL_ROWS, PAGE_SIZE)
stop_timer(10)

first_addresses = Array(QUERY_COUNT, sint)
first_valids = Array(QUERY_COUNT, sint)
first_entities = Array(QUERY_COUNT, sint)
first_relations = Array(QUERY_COUNT, sint)
for query_index in range(QUERY_COUNT):
    ok, address = directory_address(
        queries[query_index][0], queries[query_index][1]
    )
    first_valids[query_index] = ok
    first_addresses[query_index] = address
    first_entities[query_index] = queries[query_index][0]
    first_relations[query_index] = queries[query_index][1]

{first_wanted_setup}
start_timer(11)
{first_descriptors}
hop1_targets, hop1_handles, hop1_scores, hop1_valid = read_keys(
    first_descriptors, first_valids, QUERY_COUNT{first_wanted_arg}
)
stop_timer(11)

FRONTIER_COUNT = QUERY_COUNT * FRONTIER_SLOTS

start_timer(12)
{compaction}

second_addresses = Array(FRONTIER_COUNT, sint)
second_valids = Array(FRONTIER_COUNT, sint)
second_entities = Array(FRONTIER_COUNT, sint)
second_relations = Array(FRONTIER_COUNT, sint)
for query_index in range(QUERY_COUNT):
    relation_2 = queries[query_index][2]
    for frontier_index in range(FRONTIER_SLOTS):
        flat = query_index * FRONTIER_SLOTS + frontier_index
        ok, address = directory_address(frontier_targets[flat], relation_2)
        combined = ok * frontier_valid[flat]
        second_valids[flat] = combined
        second_addresses[flat] = combined.if_else(address, sint(0))
        # Entity 0 is the dummy source, whose descriptors are empty at every
        # relation, so gating the entity to 0 is exactly what gating the
        # combined address to 0 does on the unfolded path.
        second_entities[flat] = combined.if_else(frontier_targets[flat], sint(0))
        second_relations[flat] = relation_2
stop_timer(12)

{second_wanted_setup}
start_timer(13)
{second_descriptors}
hop2_targets, hop2_handles, hop2_scores, hop2_valid = read_keys(
    second_descriptors, second_valids, FRONTIER_COUNT{second_wanted_arg}
)
stop_timer(13)

for query_index in range(QUERY_COUNT):
    left_evidence = Array(CANDIDATE_COUNT, sint)
    right_evidence = Array(CANDIDATE_COUNT, sint)
{terminal_array}
    candidate_score = Array(CANDIDATE_COUNT, sint)
    candidate_valid = Array(CANDIDATE_COUNT, sint)
    selected = Array(CANDIDATE_COUNT, sint)

    start_timer(20 + query_index * 2)
    for first_index in range(FRONTIER_SLOTS):
        first_flat = query_index * FRONTIER_SLOTS + first_index
        for second_index in range(SECOND_WIDTH):
            candidate = first_index * SECOND_WIDTH + second_index
            second_flat = first_flat * SECOND_WIDTH + second_index
            terminal = hop2_targets[second_flat]
            valid = frontier_valid[first_flat] * hop2_valid[second_flat]
            left_evidence[candidate] = valid * frontier_handles[first_flat]
            right_evidence[candidate] = valid * hop2_handles[second_flat]
{terminal_store}
            candidate_score[candidate] = valid * (
                frontier_scores[first_flat] + hop2_scores[second_flat]
            )
            candidate_valid[candidate] = valid
            selected[candidate] = sint(0)

    result_valid = Array(TOP_K, sint)
    result_left = Array(TOP_K, sint)
    result_right = Array(TOP_K, sint)
    result_score = Array(TOP_K, sint)

    for rank in range(TOP_K):
        best_valid = sint(0)
        best_score = sint(0)
        best_index = sint(0)
        best_left = sint(0)
        best_right = sint(0)
{best_terminal_init}
        for candidate in range(CANDIDATE_COUNT):
            available = candidate_valid[candidate] * (
                sint(1) - selected[candidate]
            )
            better = available * (
                (sint(1) - best_valid)
                + best_valid * (candidate_score[candidate] > best_score)
            )
            best_valid = better.if_else(available, best_valid)
            best_score = better.if_else(candidate_score[candidate], best_score)
            best_index = better.if_else(sint(candidate), best_index)
            best_left = better.if_else(left_evidence[candidate], best_left)
            best_right = better.if_else(right_evidence[candidate], best_right)
{best_terminal_update}
        result_valid[rank] = best_valid
        result_score[rank] = best_valid * best_score
        result_left[rank] = best_valid * best_left
        result_right[rank] = best_valid * best_right
        for candidate in range(CANDIDATE_COUNT):
{suppress_update}
            selected[candidate] = selected[candidate] + best_valid * (
                suppress
            )
    stop_timer(20 + query_index * 2)

    start_timer(21 + query_index * 2)
    for rank in range(TOP_K):
        emit_output_shares(query_index, rank, 0, result_valid[rank])
        emit_output_shares(query_index, rank, 1, result_left[rank])
        emit_output_shares(query_index, rank, 2, result_right[rank])
        emit_output_shares(query_index, rank, 3, result_score[rank])
    stop_timer(21 + query_index * 2)
'''


def page_cost_estimate(
    config: RelationPageConfig, query_count: int
) -> dict[str, int | float]:
    """Circuit-shape counts for the generated program."""

    _validate(config, query_count)
    base = config.base
    params = config.pages
    owner_count = len(base.owners)
    frontier_slots = params.frontier_slots(owner_count)
    second_width = owner_count * params.slots_per_key

    # Owners' descriptors are packed into shared field elements, so the
    # directory scan costs one product per column, not one per owner.
    directory_products = config.directory_rows * config.directory_columns
    window_products = (
        owner_count * params.pages_per_key * params.page_budget * params.page_size
    )
    per_address = directory_products + window_products
    return {
        "query_count": query_count,
        "directory_rows": config.directory_rows,
        "pool_rows": params.pool_rows,
        "frontier_slots": frontier_slots,
        "second_width": second_width,
        "candidate_count_per_query": frontier_slots * second_width,
        "first_hop_products": query_count * per_address,
        "second_hop_products": query_count * frontier_slots * per_address,
        "compaction_selection_cells": (
            query_count * frontier_slots * params.slots_per_key
        ),
        "topk_candidate_visits": (
            query_count * base.top_k * frontier_slots * second_width
        ),
        "private_input_values_per_server": (
            query_count * 3
            + config.directory_rows * config.directory_columns
            + owner_count * params.pool_rows * params.page_size
        ),
    }


def write_program(
    config: RelationPageConfig,
    query_count: int,
    output_dir: str | Path,
    *,
    ablate_relation_check: bool = False,
    ablate_window_demux: bool = False,
    ablate_folded_directory: bool = False,
    ablate_compaction: bool = False,
) -> Path:
    name = program_name(
        config,
        query_count,
        ablate_relation_check=ablate_relation_check,
        ablate_window_demux=ablate_window_demux,
        ablate_folded_directory=ablate_folded_directory,
        ablate_compaction=ablate_compaction,
    )
    destination = Path(output_dir) / f"{name}.mpc"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        render_program(
            config,
            query_count,
            ablate_relation_check=ablate_relation_check,
            ablate_window_demux=ablate_window_demux,
            ablate_folded_directory=ablate_folded_directory,
            ablate_compaction=ablate_compaction,
        ),
        encoding="utf-8",
    )
    return destination
