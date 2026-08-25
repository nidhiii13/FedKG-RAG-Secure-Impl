"""EXPERIMENTAL MP-SPDZ circuit for the relation-paged adjacency layout.

Same threat model as the supported packed scan: exactly three MP-SPDZ servers,
static passive adversary corrupting any two, 3-of-3 additive input and output
sharing, external owners and client. The default backend is OT-based ``Semi``;
the runners also permit field-compatible ``Hemi`` and ``Temi`` under the same
passive corruption threshold. No new primitive, no dealer, no trusted setup.

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

from .config import SCALABLE_FIELD_PRIMES
from .packed import packed_edge_bits, packing_widths
from .relation_pages import RelationPageConfig


PAGE_PROGRAM_VERSION = 12
MAX_BATCH_QUERIES = 10


def _validate(config: RelationPageConfig, query_count: int) -> None:
    base = config.base
    if base.field_prime not in SCALABLE_FIELD_PRIMES:
        raise ValueError(
            "the relation-paged circuit requires an audited scalable field_prime"
        )
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
    if config.uses_hybrid_directory and not config.pages.uses_compact_directory:
        raise ValueError("hybrid type-blocked layout requires a compact residual")


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
    ablate_folded_residual: bool = False,
    ablate_compaction: bool = False,
    ablate_owner_batching: bool = False,
) -> str:
    _validate(config, query_count)
    if ablate_compaction:
        _check_compaction_ablation(config)
    # Ablation variants must not share a compiled program with the real one.
    ablation = (
        f"{int(ablate_relation_check)}{int(ablate_window_demux)}"
        f"{int(ablate_compaction)}{int(ablate_folded_directory)}"
        f"{int(ablate_folded_residual)}{int(ablate_owner_batching)}"
    )
    material = (
        f"{PAGE_PROGRAM_VERSION}:{query_count}:{ablation}:{config.digest}".encode()
    )
    suffix = hashlib.sha256(material).hexdigest()[:16]
    return f"paged_kg_3pc_{suffix}"


def _dedup_fragments(
    enabled: bool,
) -> tuple[str, str, str, str, str, str, str]:
    """Render top-k fragments, avoiding a secret index equality by default.

    During the forward maximum scan, ``better`` marks every point at which the
    incumbent changes. The final winner is therefore the last set bit. A
    reverse pass recovers that bit with one multiplication per candidate,
    instead of decomposing and comparing a secret integer index once per
    candidate and rank. Terminal-deduplication still needs terminal equality,
    because it deliberately suppresses more than the winning path.
    """

    if not enabled:
        return (
            "",
            "",
            "",
            "",
            "    became_best = Array(CANDIDATE_COUNT, sint)",
            "            became_best[candidate] = better",
            """        later_winner = sint(0)
        for reverse_offset in range(CANDIDATE_COUNT):
            candidate = CANDIDATE_COUNT - 1 - reverse_offset
            winner = became_best[candidate] * (sint(1) - later_winner)
            selected[candidate] = selected[candidate] + winner
            later_winner = later_winner + winner""",
        )
    return (
        "    candidate_terminal = Array(CANDIDATE_COUNT, sint)",
        "            candidate_terminal[candidate] = valid * terminal",
        "        best_terminal = sint(0)",
        """            best_terminal = better.if_else(
                candidate_terminal[candidate], best_terminal
            )""",
        "",
        "",
        """        for candidate in range(CANDIDATE_COUNT):
            same_terminal = candidate_terminal[candidate] == best_terminal
            selected[candidate] = selected[candidate] + best_valid * (
                same_terminal
            )""",
    )


def _ranking_block(query_count: int, deduplicate: bool) -> str:
    """Render candidate formation and top-k, SIMD-batched across queries.

    MP-SPDZ vector lanes execute the same instruction for every query.  For a
    batch this avoids emitting ``query_count`` copies of the candidate/ranking
    circuit while preserving independent state, tie-breaking, and terminal
    suppression in every lane.  A one-query program deliberately keeps the
    scalar implementation as a simple executable reference.
    """

    (
        terminal_array,
        terminal_store,
        best_terminal_init,
        best_terminal_update,
        winner_array,
        winner_record,
        suppression_block,
    ) = _dedup_fragments(deduplicate)
    if query_count == 1:
        return f'''for query_index in range(QUERY_COUNT):
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
{winner_array}

    for rank in range(TOP_K):
        best_valid = sint(0)
        best_score = sint(0)
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
            best_left = better.if_else(left_evidence[candidate], best_left)
            best_right = better.if_else(right_evidence[candidate], best_right)
{winner_record}
{best_terminal_update}
        result_valid[rank] = best_valid
        result_score[rank] = best_valid * best_score
        result_left[rank] = best_valid * best_left
        result_right[rank] = best_valid * best_right
{suppression_block}
    stop_timer(20 + query_index * 2)

    start_timer(21 + query_index * 2)
    for rank in range(TOP_K):
        emit_output_shares(query_index, rank, 0, result_valid[rank])
        emit_output_shares(query_index, rank, 1, result_left[rank])
        emit_output_shares(query_index, rank, 2, result_right[rank])
        emit_output_shares(query_index, rank, 3, result_score[rank])
    stop_timer(21 + query_index * 2)'''

    terminal_matrix = (
        "candidate_terminal = Matrix(CANDIDATE_COUNT, QUERY_COUNT, sint)"
        if deduplicate
        else ""
    )
    terminal_gather = (
        "            terminal_lanes[query_index] = terminal"
        if deduplicate
        else ""
    )
    terminal_store_vector = (
        "        candidate_terminal[candidate].assign_vector(valid * terminal_lanes[:])"
        if deduplicate
        else ""
    )
    best_terminal_vector = (
        "    best_terminal = sint(0, size=QUERY_COUNT)" if deduplicate else ""
    )
    best_terminal_update_vector = (
        "        best_terminal = better.if_else(\n"
        "            candidate_terminal[candidate][:], best_terminal\n"
        "        )"
        if deduplicate
        else ""
    )
    if deduplicate:
        winner_matrix = ""
        winner_record_vector = ""
        suppression_vector = '''    for candidate in range(CANDIDATE_COUNT):
        same_terminal = candidate_terminal[candidate][:] == best_terminal
        selected[candidate].assign_vector(
            selected[candidate][:] + best_valid * same_terminal
        )'''
    else:
        winner_matrix = "became_best = Matrix(CANDIDATE_COUNT, QUERY_COUNT, sint)"
        winner_record_vector = (
            "        became_best[candidate].assign_vector(better)"
        )
        suppression_vector = '''    later_winner = sint(0, size=QUERY_COUNT)
    for reverse_offset in range(CANDIDATE_COUNT):
        candidate = CANDIDATE_COUNT - 1 - reverse_offset
        winner = became_best[candidate][:] * (one - later_winner)
        selected[candidate].assign_vector(selected[candidate][:] + winner)
        later_winner = later_winner + winner'''

    return f'''# Candidate and ranking state is candidate-major: each row is one
# candidate and its QUERY_COUNT SIMD lanes are independent queries.
left_evidence = Matrix(CANDIDATE_COUNT, QUERY_COUNT, sint)
right_evidence = Matrix(CANDIDATE_COUNT, QUERY_COUNT, sint)
{terminal_matrix}
candidate_score = Matrix(CANDIDATE_COUNT, QUERY_COUNT, sint)
candidate_valid = Matrix(CANDIDATE_COUNT, QUERY_COUNT, sint)
selected = Matrix(CANDIDATE_COUNT, QUERY_COUNT, sint)
one = sint(1, size=QUERY_COUNT)

start_timer(20)
for first_index in range(FRONTIER_SLOTS):
    for second_index in range(SECOND_WIDTH):
        candidate = first_index * SECOND_WIDTH + second_index
        frontier_valid_lanes = Array(QUERY_COUNT, sint)
        hop2_valid_lanes = Array(QUERY_COUNT, sint)
        frontier_handle_lanes = Array(QUERY_COUNT, sint)
        hop2_handle_lanes = Array(QUERY_COUNT, sint)
        frontier_score_lanes = Array(QUERY_COUNT, sint)
        hop2_score_lanes = Array(QUERY_COUNT, sint)
        terminal_lanes = Array(QUERY_COUNT, sint)
        for query_index in range(QUERY_COUNT):
            first_flat = query_index * FRONTIER_SLOTS + first_index
            second_flat = first_flat * SECOND_WIDTH + second_index
            terminal = hop2_targets[second_flat]
            frontier_valid_lanes[query_index] = frontier_valid[first_flat]
            hop2_valid_lanes[query_index] = hop2_valid[second_flat]
            frontier_handle_lanes[query_index] = frontier_handles[first_flat]
            hop2_handle_lanes[query_index] = hop2_handles[second_flat]
            frontier_score_lanes[query_index] = frontier_scores[first_flat]
            hop2_score_lanes[query_index] = hop2_scores[second_flat]
{terminal_gather}
        valid = frontier_valid_lanes[:] * hop2_valid_lanes[:]
        left_evidence[candidate].assign_vector(valid * frontier_handle_lanes[:])
        right_evidence[candidate].assign_vector(valid * hop2_handle_lanes[:])
{terminal_store_vector}
        candidate_score[candidate].assign_vector(
            valid * (frontier_score_lanes[:] + hop2_score_lanes[:])
        )
        candidate_valid[candidate].assign_vector(valid)
        selected[candidate].assign_all(0)

result_valid = Matrix(TOP_K, QUERY_COUNT, sint)
result_left = Matrix(TOP_K, QUERY_COUNT, sint)
result_right = Matrix(TOP_K, QUERY_COUNT, sint)
result_score = Matrix(TOP_K, QUERY_COUNT, sint)
{winner_matrix}

for rank in range(TOP_K):
    best_valid = sint(0, size=QUERY_COUNT)
    best_score = sint(0, size=QUERY_COUNT)
    best_left = sint(0, size=QUERY_COUNT)
    best_right = sint(0, size=QUERY_COUNT)
{best_terminal_vector}
    for candidate in range(CANDIDATE_COUNT):
        available = candidate_valid[candidate][:] * (
            one - selected[candidate][:]
        )
        better = available * (
            (one - best_valid)
            + best_valid * (candidate_score[candidate][:] > best_score)
        )
        best_valid = better.if_else(available, best_valid)
        best_score = better.if_else(candidate_score[candidate][:], best_score)
        best_left = better.if_else(left_evidence[candidate][:], best_left)
        best_right = better.if_else(right_evidence[candidate][:], best_right)
{winner_record_vector}
{best_terminal_update_vector}
    result_valid[rank].assign_vector(best_valid)
    result_score[rank].assign_vector(best_valid * best_score)
    result_left[rank].assign_vector(best_valid * best_left)
    result_right[rank].assign_vector(best_valid * best_right)
{suppression_vector}
stop_timer(20)

start_timer(21)
for query_index in range(QUERY_COUNT):
    for rank in range(TOP_K):
        emit_output_shares(query_index, rank, 0, result_valid[rank][query_index])
        emit_output_shares(query_index, rank, 1, result_left[rank][query_index])
        emit_output_shares(query_index, rank, 2, result_right[rank][query_index])
        emit_output_shares(query_index, rank, 3, result_score[rank][query_index])
stop_timer(21)'''


def render_program(
    config: RelationPageConfig,
    query_count: int,
    *,
    ablate_relation_check: bool = False,
    ablate_window_demux: bool = False,
    ablate_folded_directory: bool = False,
    ablate_folded_residual: bool = False,
    ablate_compaction: bool = False,
    ablate_owner_batching: bool = False,
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
        dense path costs ``E*R + n*E`` where this costs ``n*E*R``. For the
        hybrid primary, folding costs the public type-block rows plus
        ``n*max_type_block`` instead of ``n*type_block_rows``; its hashed
        residual is unchanged. Both variants must return identical descriptors.
    ``ablate_folded_residual``
        For a relation-partitioned hybrid residual, restore the generic
        relation-and-bucket lookup independently for every hop-two frontier
        address. The default selects the secret relation once per query, then
        resolves all of that query's entity buckets in the folded table.
    ``ablate_compaction``
        Drop the owner-local frontier compaction and carry every first-hop slot
        into the second hop. Only permitted when the declared frontier already
        equals the full slot width, so the two circuits return the same rows.
    ``ablate_owner_batching``
        Restore version 7's separate descriptor decomposition, page selection,
        and edge decomposition for each owner. The default batches owners up to
        a public compiler-width limit; both paths touch the same public tables
        and return the same owner-interleaved slots.
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
    dense_directory_rows = config.dense_directory_rows
    dir_index_bits = max(1, (directory_rows - 1).bit_length())
    ent_index_bits = max(1, (base.entity_count - 1).bit_length())
    rel_index_bits = max(1, (relation_count - 1).bit_length())
    relation_selector_rows = 1 << rel_index_bits
    from .compact_directory import HASH_WORD_BITS, MULTIPLIER as HASH_MULT
    hash_multiplier = HASH_MULT
    compact = params.uses_compact_directory
    hybrid = config.uses_hybrid_directory
    directory_buckets = params.directory_buckets or 1
    bucket_slots = params.bucket_slots or 1
    bucket_width = owner_count * bucket_slots
    residual_fetch_batch = max(1, 256 // max(1, bucket_width))
    bucket_index_bits = max(1, (directory_buckets - 1).bit_length())
    # The tag is the dense address plus one, so it needs the dense index width;
    # packing it above the descriptor must still fit the usable field.
    tag_bits = config.residual_tag_bits
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
    residual_rows = max(1, config.residual_directory_rows)
    compact_index_bits = max(1, (residual_rows - 1).bit_length())
    # Keep every fold map_sum under the width that compiles; see
    # compile_shape_report and MAP_SUM_WIDTH_WARNING.
    fold_chunk = max(1, 256 // max(1, directory_columns))
    directory_slots = [config.directory_slot(i) for i in range(owner_count)]
    packed_directory_bits = min(
        base.field_usable_bits,
        config.owners_per_directory_element * params.descriptor_bits,
    )
    pool_index_bits = max(1, (params.page_budget - 1).bit_length())
    frontier_slots = params.frontier_slots(owner_count)
    second_width = owner_count * params.slots_per_key
    candidate_count = frontier_slots * second_width
    owner_read_batch = min(
        owner_count,
        max(1, MAP_SUM_WIDTH_WARNING // max(1, query_count * frontier_slots * params.slots_per_key)),
    )
    ranking_block = _ranking_block(
        query_count, base.deduplicate_terminal_answers
    )
    if params.partition_residual_by_relation:
        compact_tag_setup = '''        # Relation is encoded by the selected
        # relation-major table row, so the in-slot tag only needs the entity.
        tag = valids[address].if_else(entities[address] + 1, sint(0))'''
        compact_row_setup = '''    rows = Array(address_count, sint)
    for address in range(address_count):
        relation_ok = (relations[address] != 0) * (
            relations[address] <= RELATION_COUNT
        )
        use = valids[address] * relation_ok
        row = (relations[address] - 1) * DIRECTORY_BUCKETS + buckets[address]
        rows[address] = use.if_else(row, sint(0))'''
        folded_residual_functions = '''# Fold the relation-partitioned residual once per query.
# The residual is stored relation-major. All hop-two addresses belonging to a
# query share relation_2, so selecting that public-width relation slice once
# changes R*B*W per address into R*B*W once plus B*W per address. Neither the
# relation nor the selected slice is opened. Relations and tag verification are
# batched across queries so this saves bandwidth without serialising Q copies of
# the same protocol stages.
def fold_partitioned_residuals(relations, relation_oks, query_count):
    indexes = Array(query_count, sint)
    for query_index in range(query_count):
        indexes[query_index] = relation_oks[query_index].if_else(
            relations[query_index] - 1, sint(0)
        )
    relation_bits = indexes[:].bit_decompose(REL_INDEX_BITS)
    selector = demux_matrix(relation_bits, n_threads=1)

    cells = DIRECTORY_BUCKETS * BUCKET_WIDTH
    relation_data = compact.get_vector(0, RELATION_COUNT * cells)
    padding = (RELATION_SELECTOR_ROWS - RELATION_COUNT) * cells
    if padding:
        relation_data = sint.concat((relation_data, sint(0, size=padding)))
    relation_table = Matrix(RELATION_SELECTOR_ROWS, cells, sint)
    relation_table.assign_vector(relation_data)
    folded = Array.create_from(selector.trans_mul(relation_table).get_vector())
    selector.delete()
    return folded


def read_folded_residuals(
    entities, valids, tables, address_count, addresses_per_query
):
    # In the partitioned table a slot tag is entity+1; the relation has already
    # been selected by fold_partitioned_residual.
    tags = Array(address_count, sint)
    for address in range(address_count):
        tags[address] = valids[address].if_else(entities[address] + 1, sint(0))
    buckets = Array(address_count, sint)
    buckets.assign_vector(compact_buckets(tags, address_count))

    if DIRECTORY_BUCKETS == 1:
        # Avoid asking demux_matrix for a two-row selector for a one-row table.
        fetched = Array(address_count * BUCKET_WIDTH, sint)
        for address in range(address_count):
            query_index = address // addresses_per_query
            for column in range(BUCKET_WIDTH):
                fetched[address * BUCKET_WIDTH + column] = tables[
                    query_index * BUCKET_WIDTH + column
                ]
    else:
        bucket_bits = buckets.get_vector(0, address_count).bit_decompose(
            BUCKET_INDEX_BITS
        )
        selectors = demux_matrix(bucket_bits, n_threads=SCAN_THREADS)
        fetched = Array(address_count * BUCKET_WIDTH, sint)
        for start in range(0, address_count, RESIDUAL_FETCH_BATCH):
            stop = min(start + RESIDUAL_FETCH_BATCH, address_count)
            span = stop - start

            @map_sum(
                SCAN_THREADS, 1024, DIRECTORY_BUCKETS,
                span * BUCKET_WIDTH, [sint] * (span * BUCKET_WIDTH)
            )
            def scan_bucket(bucket, start=start, stop=stop):
                return tuple(
                    selectors[bucket][address] * tables[
                        (address // addresses_per_query)
                        * DIRECTORY_BUCKETS * BUCKET_WIDTH
                        + bucket * BUCKET_WIDTH + column
                    ]
                    for address in range(start, stop)
                    for column in range(BUCKET_WIDTH)
                )

            piece = scan_bucket()
            for offset in range(span * BUCKET_WIDTH):
                fetched[start * BUCKET_WIDTH + offset] = piece[offset]
        selectors.delete()
    return resolve_compact_fetched(fetched, tags, address_count)
'''
    else:
        compact_tag_setup = '''        tag = valids[address].if_else(
            entities[address] * RELATION_COUNT + relations[address], sint(0)
        )'''
        compact_row_setup = '''    rows = buckets'''
        folded_residual_functions = ""

    # ABLATION ONLY. The relation is already resolved by the index, so this
    # restores a redundant per-slot equality test to price what removing it
    # saved. `wanted_relation` is threaded in only when the switch is on.
    if ablate_relation_check:
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
        first_wanted_setup = ""
        first_wanted_arg = ""
        second_wanted_setup = ""
        second_wanted_arg = ""

    if ablate_relation_check:
        # Keep the scalar unpacking path for the relation-check ablation. Its
        # purpose is attribution, and retaining it gives the vectorized default
        # an independently generated executable reference.
        read_keys_code = '''def read_keys(descriptors, valids, address_count, wanted):
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
                active = counts[address] > offset
                for slot in range(PAGE_SIZE):
                    source_index = (
                        address * PAGES_PER_KEY * PAGE_SIZE
                        + offset * PAGE_SIZE + slot
                    )
                    target_index = (
                        address * SECOND_WIDTH + owner * SLOTS_PER_KEY
                        + offset * PAGE_SIZE + slot
                    )
                    target, ablation_relation, handle, score, stored = unpack_edge(
                        window[source_index]
                    )
                    ok = active * stored * (target != 0) * (target < ENTITY_COUNT)
                    ok = ok * (ablation_relation == wanted[address])
                    slot_valid[target_index] = ok
                    targets[target_index] = ok * target
                    handles[target_index] = ok * handle
                    scores[target_index] = ok * score
    return targets, handles, scores, slot_valid'''
    elif ablate_owner_batching:
        read_keys_code = '''def read_keys(descriptors, valids, address_count):
    """Version-7 ablation: resolve and unpack one owner at a time.

    Arithmetic remains lane-independent. Batching changes only the instruction
    schedule: one bit decomposition handles every requested descriptor for an
    owner, and one handles its complete fetched page window.
    """

    targets = Array(address_count * SECOND_WIDTH, sint)
    handles = Array(address_count * SECOND_WIDTH, sint)
    scores = Array(address_count * SECOND_WIDTH, sint)
    slot_valid = Array(address_count * SECOND_WIDTH, sint)
    window_slots = address_count * SLOTS_PER_KEY

    for owner in range(OWNER_COUNT):
        column, descriptor_offset = DIRECTORY_SLOTS[owner]
        packed_descriptors = Array(address_count, sint)
        for address in range(address_count):
            packed_descriptors[address] = descriptors[
                address * DIRECTORY_COLUMNS + column
            ]

        descriptor_bits = packed_descriptors[:].bit_decompose(
            PACKED_DIRECTORY_BITS
        )[descriptor_offset:descriptor_offset + DESCRIPTOR_BITS]
        page_bases = sint.bit_compose(descriptor_bits[:PAGE_BASE_BITS])
        page_counts = sint.bit_compose(
            descriptor_bits[PAGE_BASE_BITS:DESCRIPTOR_BITS]
        )
        usable = (page_bases < PAGE_BUDGET) * (page_counts <= PAGES_PER_KEY)
        safe_bases = usable.if_else(page_bases, 0)
        counts = valids[:] * usable * page_counts
        bases = Array(address_count, sint)
        bases.assign_vector(valids[:].if_else(safe_bases, 0))

        window = read_page_window(owner, bases, address_count)
        edge_bits = window[:].bit_decompose(PACKED_EDGE_BITS)
        edge_targets = sint.bit_compose(edge_bits[:SLOT_BITS])
        edge_handles = sint.bit_compose(
            edge_bits[SLOT_BITS + RELATION_BITS:
                      SLOT_BITS + RELATION_BITS + EVIDENCE_BITS]
        )
        score_start = SLOT_BITS + RELATION_BITS + EVIDENCE_BITS
        edge_scores = sint.bit_compose(
            edge_bits[score_start:score_start + SCORE_BITS]
        )
        stored = edge_bits[PACKED_EDGE_BITS - 1]

        active = Array(window_slots, sint)
        for page_offset in range(PAGES_PER_KEY):
            page_active = Array.create_from(counts > page_offset)
            for address in range(address_count):
                for slot in range(PAGE_SIZE):
                    source_index = (
                        address * SLOTS_PER_KEY + page_offset * PAGE_SIZE + slot
                    )
                    active[source_index] = page_active[address]

        ok = (
            active[:] * stored * (edge_targets != 0)
            * (edge_targets < ENTITY_COUNT)
        )
        valid_values = Array.create_from(ok)
        target_values = Array.create_from(ok * edge_targets)
        handle_values = Array.create_from(ok * edge_handles)
        score_values = Array.create_from(ok * edge_scores)
        for address in range(address_count):
            for local_slot in range(SLOTS_PER_KEY):
                source_index = address * SLOTS_PER_KEY + local_slot
                target_index = (
                    address * SECOND_WIDTH + owner * SLOTS_PER_KEY + local_slot
                )
                slot_valid[target_index] = valid_values[source_index]
                targets[target_index] = target_values[source_index]
                handles[target_index] = handle_values[source_index]
                scores[target_index] = score_values[source_index]
    return targets, handles, scores, slot_valid'''
    else:
        read_keys_code = '''def read_keys(descriptors, valids, address_count):
    """Resolve every owner in bounded owner-major vector batches.

    The directory descriptors are decomposed once for the whole address block,
    including packed columns shared by several owners. Page selection is then
    batched across OWNER_READ_BATCH owners, and all returned edges are unpacked
    in one vector decomposition. Loop bounds depend only on public parameters.
    """

    targets = Array(address_count * SECOND_WIDTH, sint)
    handles = Array(address_count * SECOND_WIDTH, sint)
    scores = Array(address_count * SECOND_WIDTH, sint)
    slot_valid = Array(address_count * SECOND_WIDTH, sint)
    owner_addresses = OWNER_COUNT * address_count
    window_slots = owner_addresses * SLOTS_PER_KEY

    # Decompose each packed directory element once. When multiple owners share
    # a field element, version 7 decomposed that same value once per owner.
    packed_bits = descriptors[:].bit_decompose(PACKED_DIRECTORY_BITS)
    bases = Array(owner_addresses, sint)
    counts = Array(owner_addresses, sint)
    for owner in range(OWNER_COUNT):
        column, descriptor_offset = DIRECTORY_SLOTS[owner]
        owner_descriptor_bits = []
        for bit_index in range(DESCRIPTOR_BITS):
            lanes = Array(address_count, sint)
            source_bits = packed_bits[descriptor_offset + bit_index]
            for address in range(address_count):
                lanes[address] = source_bits[
                    address * DIRECTORY_COLUMNS + column
                ]
            owner_descriptor_bits.append(lanes[:])
        page_bases = sint.bit_compose(
            owner_descriptor_bits[:PAGE_BASE_BITS]
        )
        page_counts = sint.bit_compose(
            owner_descriptor_bits[PAGE_BASE_BITS:DESCRIPTOR_BITS]
        )
        usable = (page_bases < PAGE_BUDGET) * (
            page_counts <= PAGES_PER_KEY
        )
        safe_bases = usable.if_else(page_bases, 0)
        safe_counts = valids[:] * usable * page_counts
        gated_bases = valids[:].if_else(safe_bases, 0)
        for address in range(address_count):
            flat = owner * address_count + address
            bases[flat] = gated_bases[address]
            counts[flat] = safe_counts[address]

    window = read_page_windows(bases, address_count)
    edge_bits = window[:].bit_decompose(PACKED_EDGE_BITS)
    edge_targets = sint.bit_compose(edge_bits[:SLOT_BITS])
    edge_handles = sint.bit_compose(
        edge_bits[SLOT_BITS + RELATION_BITS:
                  SLOT_BITS + RELATION_BITS + EVIDENCE_BITS]
    )
    score_start = SLOT_BITS + RELATION_BITS + EVIDENCE_BITS
    edge_scores = sint.bit_compose(
        edge_bits[score_start:score_start + SCORE_BITS]
    )
    stored = edge_bits[PACKED_EDGE_BITS - 1]

    active = Array(window_slots, sint)
    for owner in range(OWNER_COUNT):
        for page_offset in range(PAGES_PER_KEY):
            page_active = Array(address_count, sint)
            for address in range(address_count):
                page_active[address] = (
                    counts[owner * address_count + address] > page_offset
                )
            for address in range(address_count):
                for slot in range(PAGE_SIZE):
                    source_index = (
                        (owner * address_count + address) * SLOTS_PER_KEY
                        + page_offset * PAGE_SIZE + slot
                    )
                    active[source_index] = page_active[address]

    ok = (
        active[:] * stored * (edge_targets != 0)
        * (edge_targets < ENTITY_COUNT)
    )
    valid_values = Array.create_from(ok)
    target_values = Array.create_from(ok * edge_targets)
    handle_values = Array.create_from(ok * edge_handles)
    score_values = Array.create_from(ok * edge_scores)
    for owner in range(OWNER_COUNT):
        for address in range(address_count):
            for local_slot in range(SLOTS_PER_KEY):
                source_index = (
                    (owner * address_count + address) * SLOTS_PER_KEY
                    + local_slot
                )
                target_index = (
                    address * SECOND_WIDTH + owner * SLOTS_PER_KEY + local_slot
                )
                slot_valid[target_index] = valid_values[source_index]
                targets[target_index] = target_values[source_index]
                handles[target_index] = handle_values[source_index]
                scores[target_index] = score_values[source_index]
    return targets, handles, scores, slot_valid'''

    if hybrid:
        coefficients = []
        block_starts = []
        starts = []
        widths = []
        for relation in config.type_blocks.relation_order:
            block_start, type_start, width = config.type_blocks.block_of(relation)
            coefficients.append(block_start - type_start)
            block_starts.append(block_start)
            starts.append(type_start)
            widths.append(width)
        type_max_block = config.type_blocks.max_block
        type_block_index_bits = max(1, (type_max_block - 1).bit_length())
        type_constants = (
            f"TYPE_COEFFICIENTS = {coefficients}\n"
            f"TYPE_BLOCK_STARTS = {block_starts}\n"
            f"TYPE_STARTS = {starts}\n"
            f"TYPE_WIDTHS = {widths}\n"
            f"TYPE_MAX_BLOCK = {type_max_block}\n"
            f"TYPE_BLOCK_INDEX_BITS = {type_block_index_bits}\n"
        )
        directory_address_code = '''def directory_address(entity, relation):
    """Return generic key validity and its affine type-block address.

    A key outside its relation's primary-type block is still generically valid:
    it is looked up in the hashed residual. Its blocked address alone is sent to
    dummy row zero.
    """
    entity_ok = (entity != 0) * (entity < ENTITY_COUNT)
    relation_ok = (relation != 0) * (relation <= RELATION_COUNT)
    index = Array(1, sint)
    index[0] = relation_ok.if_else(relation - 1, sint(0))
    relation_bits = index.get_vector(0, 1).bit_decompose(REL_INDEX_BITS)
    selector = demux_matrix(relation_bits, n_threads=1)
    coefficient = sint(0)
    type_start = sint(0)
    type_width = sint(0)
    for relation_index in range(RELATION_COUNT):
        weight = selector[relation_index][0]
        coefficient += weight * TYPE_COEFFICIENTS[relation_index]
        type_start += weight * TYPE_STARTS[relation_index]
        type_width += weight * TYPE_WIDTHS[relation_index]
    selector.delete()
    generic_ok = entity_ok * relation_ok
    blocked_ok = generic_ok * (entity >= type_start) * (
        entity < type_start + type_width
    )
    address = coefficient + entity
    return generic_ok, blocked_ok.if_else(address, sint(0))'''
    else:
        type_constants = ""
        directory_address_code = '''# The dense directory address is affine in
# two secret values and is never opened. Address zero is a public dummy key.
def directory_address(entity, relation):
    entity_ok = (entity != 0) * (entity < ENTITY_COUNT)
    relation_ok = (relation != 0) * (relation <= RELATION_COUNT)
    ok = entity_ok * relation_ok
    address = entity * RELATION_COUNT + relation - 1
    return ok, ok.if_else(address, sint(0))'''

    if hybrid:
        hybrid_fold_functions = '''# Fold the type-blocked primary directory once per query.
# Every hop-two entity uses the same secret relation. Selecting that relation's
# public ontology block once avoids both a relation demux and a full primary
# directory scan for every frontier address. The block is padded in registers to
# TYPE_MAX_BLOCK, so neither its width nor the queried relation is revealed.
def fold_type_block_directory(relation, relation_ok):
    index = Array(1, sint)
    index[0] = relation_ok.if_else(relation - 1, sint(0))
    relation_bits = index.get_vector(0, 1).bit_decompose(REL_INDEX_BITS)
    selector = demux_matrix(relation_bits, n_threads=1)

    folded = sint(0, size=TYPE_MAX_BLOCK * DIRECTORY_COLUMNS)
    type_start = sint(0)
    type_width = sint(0)
    for relation_index in range(RELATION_COUNT):
        weight = selector[relation_index][0]
        width = TYPE_WIDTHS[relation_index]
        cells = width * DIRECTORY_COLUMNS
        block = directory.get_vector(
            TYPE_BLOCK_STARTS[relation_index] * DIRECTORY_COLUMNS, cells
        )
        weighted = weight.expand_to_vector(cells) * block
        padding = (TYPE_MAX_BLOCK - width) * DIRECTORY_COLUMNS
        if padding:
            weighted = sint.concat((weighted, sint(0, size=padding)))
        folded = folded + weighted
        type_start += weight * TYPE_STARTS[relation_index]
        type_width += weight * width
    selector.delete()
    return Array.create_from(folded), type_start, type_width


def read_folded_type_block(
    entities, valids, table, type_start, type_width, address_count
):
    """Read a fixed-width folded primary block at secret entity offsets."""

    offsets = Array(address_count, sint)
    active = Array(address_count, sint)
    for address in range(address_count):
        entity = entities[address]
        in_block = (entity >= type_start) * (entity < type_start + type_width)
        use = valids[address] * in_block
        active[address] = use
        offsets[address] = use.if_else(entity - type_start, sint(0))

    offset_bits = offsets.get_vector(0, address_count).bit_decompose(
        TYPE_BLOCK_INDEX_BITS
    )
    selectors = demux_matrix(offset_bits, n_threads=SCAN_THREADS)

    @map_sum(
        SCAN_THREADS,
        1024,
        TYPE_MAX_BLOCK,
        address_count * DIRECTORY_COLUMNS,
        [sint] * (address_count * DIRECTORY_COLUMNS),
    )
    def scan_offset(offset):
        selected = selectors[offset]
        return tuple(
            selected[address] * table[offset * DIRECTORY_COLUMNS + column]
            for address in range(address_count)
            for column in range(DIRECTORY_COLUMNS)
        )

    fetched = Array.create_from(scan_offset())
    result = Array(address_count * DIRECTORY_COLUMNS, sint)
    for address in range(address_count):
        for column in range(DIRECTORY_COLUMNS):
            flat = address * DIRECTORY_COLUMNS + column
            result[flat] = active[address] * fetched[flat]
    selectors.delete()
    return result'''
    else:
        hybrid_fold_functions = ""

    # Hop two folds the relation out of the primary directory before reading it.
    # Dense storage folds to ENTITY_COUNT rows; the hybrid primary folds to its
    # public maximum ontology-block width. A relation-partitioned hybrid residual
    # is folded separately and batched across queries; other residual layouts
    # keep the generic hash-indexed read. Ablations restore the old per-address
    # reads and must return identical descriptors.
    if hybrid:
        directory_storage = (
            "directory = shared_matrix(DIRECTORY_ROWS, DIRECTORY_COLUMNS)\n"
            "compact = shared_matrix(RESIDUAL_ROWS, BUCKET_WIDTH)"
        )
        first_descriptors = '''first_blocked = read_directory(first_addresses, QUERY_COUNT)
first_residual = read_compact_directory(
    first_entities, first_relations, first_valids, QUERY_COUNT
)
first_descriptors = Array.create_from(first_blocked[:] + first_residual[:])'''
        if ablate_folded_directory:
            second_descriptors = '''second_blocked = read_directory(
    second_addresses, FRONTIER_COUNT
)
second_residual = read_compact_directory(
    second_entities, second_relations, second_valids, FRONTIER_COUNT
)
second_descriptors = Array.create_from(second_blocked[:] + second_residual[:])'''
        else:
            folded_residual_setup = ""
            if params.partition_residual_by_relation and not ablate_folded_residual:
                folded_residual_setup = '''residual_relations = Array(
    QUERY_COUNT, sint
)
residual_relation_oks = Array(QUERY_COUNT, sint)
for query_index in range(QUERY_COUNT):
    residual_relations[query_index] = queries[query_index][2]
    residual_relation_oks[query_index] = (
        (queries[query_index][2] != 0)
        * (queries[query_index][2] <= RELATION_COUNT)
    )
folded_residuals = fold_partitioned_residuals(
    residual_relations, residual_relation_oks, QUERY_COUNT
)
second_residual.assign_vector(read_folded_residuals(
    second_entities, second_valids, folded_residuals,
    FRONTIER_COUNT, FRONTIER_SLOTS
))'''
            second_descriptors = '''second_blocked = Array(
    FRONTIER_COUNT * DIRECTORY_COLUMNS, sint
)
second_residual = Array(FRONTIER_COUNT * DIRECTORY_COLUMNS, sint)
{folded_residual_setup}
for query_index in range(QUERY_COUNT):
    relation_2 = queries[query_index][2]
    relation_ok = (relation_2 != 0) * (relation_2 <= RELATION_COUNT)
    folded, type_start, type_width = fold_type_block_directory(
        relation_2, relation_ok
    )
    slice_entities = Array(FRONTIER_SLOTS, sint)
    slice_valids = Array(FRONTIER_SLOTS, sint)
    for frontier_index in range(FRONTIER_SLOTS):
        flat = query_index * FRONTIER_SLOTS + frontier_index
        slice_entities[frontier_index] = second_entities[flat]
        slice_valids[frontier_index] = second_valids[flat]
    part = read_folded_type_block(
        slice_entities, slice_valids, folded, type_start, type_width,
        FRONTIER_SLOTS
    )
    for frontier_index in range(FRONTIER_SLOTS):
        flat = query_index * FRONTIER_SLOTS + frontier_index
        for column in range(DIRECTORY_COLUMNS):
            second_blocked[flat * DIRECTORY_COLUMNS + column] = part[
                frontier_index * DIRECTORY_COLUMNS + column
            ]
{generic_residual_read}
second_descriptors = Array.create_from(second_blocked[:] + second_residual[:])'''.format(
                folded_residual_setup=folded_residual_setup,
                generic_residual_read=(
                    "second_residual.assign_vector(read_compact_directory(\n"
                    "    second_entities, second_relations, second_valids, "
                    "FRONTIER_COUNT\n))"
                    if not folded_residual_setup
                    else ""
                ),
            )
    elif compact:
        directory_storage = "compact = shared_matrix(RESIDUAL_ROWS, BUCKET_WIDTH)"
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

    if hybrid and not ablate_folded_directory:
        second_address_setup = '''second_valids = Array(FRONTIER_COUNT, sint)
second_entities = Array(FRONTIER_COUNT, sint)
second_relations = Array(FRONTIER_COUNT, sint)
for query_index in range(QUERY_COUNT):
    relation_2 = queries[query_index][2]
    relation_ok = (relation_2 != 0) * (relation_2 <= RELATION_COUNT)
    for frontier_index in range(FRONTIER_SLOTS):
        flat = query_index * FRONTIER_SLOTS + frontier_index
        entity = frontier_targets[flat]
        entity_ok = (entity != 0) * (entity < ENTITY_COUNT)
        combined = entity_ok * relation_ok * frontier_valid[flat]
        second_valids[flat] = combined
        second_entities[flat] = combined.if_else(entity, sint(0))
        second_relations[flat] = relation_2'''
    else:
        second_address_setup = '''second_addresses = Array(FRONTIER_COUNT, sint)
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
        second_relations[flat] = relation_2'''

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
        batched_window_read = '''


def read_page_windows(bases, address_count):
    """Ablation: owner-batched reads, but one demux per page offset."""

    owner_addresses = OWNER_COUNT * address_count
    result = Array(owner_addresses * SLOTS_PER_KEY, sint)
    for offset in range(PAGES_PER_KEY):
        base_bits = bases[:].bit_decompose(POOL_INDEX_BITS)
        selectors = demux_matrix(base_bits, n_threads=SCAN_THREADS)
        for batch_start in range(0, OWNER_COUNT, OWNER_READ_BATCH):
            batch_owners = min(OWNER_READ_BATCH, OWNER_COUNT - batch_start)

            @map_sum(
                SCAN_THREADS,
                1024,
                PAGE_BUDGET,
                batch_owners * address_count * PAGE_SIZE,
                [sint] * (batch_owners * address_count * PAGE_SIZE),
            )
            def scan_owner_pages(
                page, batch_start=batch_start, batch_owners=batch_owners,
                offset=offset, selectors=selectors
            ):
                selected = selectors[page]
                return tuple(
                    selected[(batch_start + local_owner) * address_count + address]
                    * pages[
                        (batch_start + local_owner) * POOL_ROWS + page + offset
                    ][slot]
                    for local_owner in range(batch_owners)
                    for address in range(address_count)
                    for slot in range(PAGE_SIZE)
                )

            part = Array.create_from(scan_owner_pages())
            for local_owner in range(batch_owners):
                owner = batch_start + local_owner
                for address in range(address_count):
                    for slot in range(PAGE_SIZE):
                        source = (
                            (local_owner * address_count + address) * PAGE_SIZE
                            + slot
                        )
                        target = (
                            (owner * address_count + address) * SLOTS_PER_KEY
                            + offset * PAGE_SIZE + slot
                        )
                        result[target] = part[source]
        selectors.delete()
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
        batched_window_read = '''


def read_page_windows(bases, address_count):
    """Read fixed page windows for all owners in bounded public batches."""

    owner_addresses = OWNER_COUNT * address_count
    base_bits = bases[:].bit_decompose(POOL_INDEX_BITS)
    selectors = demux_matrix(base_bits, n_threads=SCAN_THREADS)
    result = Array(owner_addresses * SLOTS_PER_KEY, sint)
    for batch_start in range(0, OWNER_COUNT, OWNER_READ_BATCH):
        batch_owners = min(OWNER_READ_BATCH, OWNER_COUNT - batch_start)

        @map_sum(
            SCAN_THREADS,
            1024,
            PAGE_BUDGET,
            batch_owners * address_count * SLOTS_PER_KEY,
            [sint] * (batch_owners * address_count * SLOTS_PER_KEY),
        )
        def scan_owner_windows(
            page, batch_start=batch_start, batch_owners=batch_owners,
            selectors=selectors
        ):
            selected = selectors[page]
            return tuple(
                selected[(batch_start + local_owner) * address_count + address]
                * pages[
                    (batch_start + local_owner) * POOL_ROWS + page + offset
                ][slot]
                for local_owner in range(batch_owners)
                for address in range(address_count)
                for offset in range(PAGES_PER_KEY)
                for slot in range(PAGE_SIZE)
            )

        part = Array.create_from(scan_owner_windows())
        for local_owner in range(batch_owners):
            owner = batch_start + local_owner
            for address in range(address_count):
                for local_slot in range(SLOTS_PER_KEY):
                    source = (
                        (local_owner * address_count + address) * SLOTS_PER_KEY
                        + local_slot
                    )
                    target = (
                        (owner * address_count + address) * SLOTS_PER_KEY
                        + local_slot
                    )
                    result[target] = part[source]
    selectors.delete()
    return result'''

    # Emit only the implementation the selected read_keys path calls. Besides
    # keeping the generated source small, this makes the ablation an actual
    # executable alternative rather than dead code beside the optimized path.
    if ablate_relation_check or ablate_owner_batching:
        pass
    else:
        window_read = batched_window_read

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
DENSE_DIRECTORY_ROWS = {dense_directory_rows}
DIR_INDEX_BITS = {dir_index_bits}
ENT_INDEX_BITS = {ent_index_bits}
REL_INDEX_BITS = {rel_index_bits}
RELATION_SELECTOR_ROWS = {relation_selector_rows}
FOLD_CHUNK = {fold_chunk}
HASH_MULTIPLIER = {hash_multiplier}
HASH_WORD_BITS = {hash_word_bits}
HASH_PRODUCT_BITS = {hash_product_bits}
DIRECTORY_BUCKETS = {directory_buckets}
RESIDUAL_ROWS = {residual_rows}
BUCKET_SLOTS = {bucket_slots}
BUCKET_WIDTH = {bucket_width}
BUCKET_INDEX_BITS = {bucket_index_bits}
RESIDUAL_FETCH_BATCH = {residual_fetch_batch}
COMPACT_INDEX_BITS = {compact_index_bits}
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
OWNER_READ_BATCH = {owner_read_batch}
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
{type_constants}


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


{directory_address_code}


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


{hybrid_fold_functions}


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
def compact_buckets(tags, address_count):
    """Batch Fibonacci hashing for every secret requested tag.

    The old circuit called a one-element bit decomposition once per address.
    This emits one vector decomposition instead. It has identical arithmetic
    semantics and preprocessing volume, but one instruction stream and one
    protocol batch instead of ``address_count`` separately generated streams.
    """

    # A one-bucket table has the constant public index zero. Taking one hash
    # bit here would incorrectly create a second bucket that storage does not
    # contain; keep this explicit because BUCKET_INDEX_BITS is at least one for
    # the bit-decomposition API.
    if DIRECTORY_BUCKETS == 1:
        return sint(0, size=address_count)

    # tag * MULTIPLIER is exact in the field (TAG_BITS + 64 < field width), so
    # decomposing HASH_PRODUCT_BITS gives the true product bits. The word
    # truncation is implicit: bits [0, HASH_WORD_BITS) are the product mod
    # 2^HASH_WORD_BITS, and the index is the top BUCKET_INDEX_BITS of those.
    products = Array(address_count, sint)
    products.assign_vector(tags[:] * HASH_MULTIPLIER)
    bits = products[:].bit_decompose(HASH_PRODUCT_BITS)
    low = HASH_WORD_BITS - BUCKET_INDEX_BITS
    return sint.bit_compose(bits[low:HASH_WORD_BITS])


def read_compact_directory(entities, relations, valids, address_count):
    """Resolve address_count secret keys through the compact directory.

    Returns descriptors in exactly the packed layout read_directory produces --
    owner i's descriptor at its DIRECTORY_SLOTS offset -- so read_keys consumes
    either source without knowing which layout produced it.
    """

    tags = Array(address_count, sint)
    for address in range(address_count):
        # Tag 0 marks an empty slot, so a gated-off address gets tag 0 and can
        # never match a stored key. That replaces the dense path's dummy row.
{compact_tag_setup}
        tags[address] = tag
    buckets = Array(address_count, sint)
    buckets.assign_vector(compact_buckets(tags, address_count))

{compact_row_setup}
    row_bits = rows.get_vector(0, address_count).bit_decompose(
        COMPACT_INDEX_BITS
    )
    selectors = demux_matrix(row_bits, n_threads=SCAN_THREADS)

    # Fetch the selected bucket. Every bucket is touched because the selection is
    # secret; this is the term that shrinks from ENTITY_COUNT * RELATION_COUNT.
    #
    # Emitted as a MATRIX MULTIPLY, not a map_sum. The natural way to write this
    # is a map_sum over buckets returning address_count * BUCKET_WIDTH values,
    # and that is why three earlier versions never compiled: MP-SPDZ program size
    # tracks the OUTPUT WIDTH of a map_sum, and a bucket fetch has to materialise
    # every slot of the selected bucket, so the width is inherently large (1,425
    # on the fixture that timed out). The dense read compiles fine at 200,000
    # iterations because its output is narrow.
    #
    # But the same sum is a matrix product:
    #     fetched[address][column] = sum_bucket sel[bucket][address]
    #                                          * compact[bucket][column]
    # which is selectors^T . compact -- (RESIDUAL_ROWS x address_count)
    # transposed against (RESIDUAL_ROWS x BUCKET_WIDTH). trans_mul emits one
    # matmul instruction instead of address_count * BUCKET_WIDTH unrolled scalar
    # expressions. The PRODUCT COUNT IS UNCHANGED; only the program text
    # collapses, and program text was the binding constraint.
    fetched = Array.create_from(selectors.trans_mul(compact).get_vector())
    selectors.delete()
    return resolve_compact_fetched(fetched, tags, address_count)


def resolve_compact_fetched(fetched, tags, address_count):
    """Verify fetched tags and rebuild dense-compatible descriptors."""

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
    # Decompose each requested tag ONCE, then broadcast each secret bit across
    # the public bucket width. Previously `wanted` repeated each tag
    # BUCKET_WIDTH times and decomposed the repeated vector, paying the edaBit
    # conversion BUCKET_WIDTH times for identical secret values.
    tag_bits = tags[:].bit_decompose(TAG_BITS)
    wanted_bits = []
    for bit in tag_bits:
        lanes = Array.create_from(bit)
        broadcast = Array(total_slots, sint)
        for address in range(address_count):
            for column in range(BUCKET_WIDTH):
                broadcast[address * BUCKET_WIDTH + column] = lanes[address]
        wanted_bits.append(broadcast[:])
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
    return result


{folded_residual_functions}


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

    # Chunked deliberately. A single map_sum here would emit
    # ENTITY_COUNT * DIRECTORY_COLUMNS outputs, and MP-SPDZ program size tracks
    # map_sum OUTPUT WIDTH rather than iteration count -- the constraint that
    # defeated four compact-circuit attempts. At evaluation-fixture scale that
    # width is 1,529 (WebQSP) or 6,573 (MetaQA), comparable to the 1,425-wide
    # stage that never compiled, so the fold would have been the next thing to
    # hit the wall.
    #
    # Splitting the entity range into FOLD_CHUNK-wide pieces keeps every map_sum
    # narrow while doing exactly the same work: (ENTITY_COUNT / FOLD_CHUNK)
    # passes of RELATION_COUNT iterations over FOLD_CHUNK entities is
    # ENTITY_COUNT * RELATION_COUNT products either way. Same products, same
    # rounds, same result -- only the program text is bounded.
    table = Array(ENTITY_COUNT * DIRECTORY_COLUMNS, sint)
    for start in range(0, ENTITY_COUNT, FOLD_CHUNK):
        stop = min(start + FOLD_CHUNK, ENTITY_COUNT)
        span = (stop - start) * DIRECTORY_COLUMNS

        @map_sum(SCAN_THREADS, 1024, RELATION_COUNT, span, [sint] * span)
        def fold(relation_index, start=start, stop=stop):
            weight = selector[relation_index][0]
            return tuple(
                weight * directory[entity * RELATION_COUNT + relation_index][column]
                for entity in range(start, stop)
                for column in range(DIRECTORY_COLUMNS)
            )

        piece = fold()
        for offset in range(span):
            table[start * DIRECTORY_COLUMNS + offset] = piece[offset]
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


{read_keys_code}


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

{second_address_setup}
stop_timer(12)

{second_wanted_setup}
start_timer(13)
{second_descriptors}
hop2_targets, hop2_handles, hop2_scores, hop2_valid = read_keys(
    second_descriptors, second_valids, FRONTIER_COUNT{second_wanted_arg}
)
stop_timer(13)

{ranking_block}
'''


def page_cost_estimate(
    config: RelationPageConfig, query_count: int
) -> dict[str, int | float]:
    """Circuit-shape counts for the generated program."""

    _validate(config, query_count)
    base = config.base
    params = config.pages
    owner_count = len(base.owners)
    relation_count = config.relation_count
    frontier_slots = params.frontier_slots(owner_count)
    second_width = owner_count * params.slots_per_key

    # Owners' descriptors are packed into shared field elements, so the
    # directory scan costs one product per column, not one per owner.
    directory_products = config.directory_rows * config.directory_columns
    window_products = (
        owner_count * params.pages_per_key * params.page_budget * params.page_size
    )
    per_address = directory_products + window_products
    if config.uses_hybrid_directory:
        directory_input_values = (
            config.directory_rows * config.directory_columns
            + config.residual_directory_rows
            * owner_count * params.bucket_slots
        )
    elif params.uses_compact_directory:
        directory_input_values = (
            config.residual_directory_rows * owner_count * params.bucket_slots
        )
    else:
        directory_input_values = config.directory_rows * config.directory_columns
    estimate: dict[str, int | float] = {
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
            + directory_input_values
            + owner_count * params.pool_rows * params.page_size
        ),
    }
    if config.uses_hybrid_directory:
        # Primary-directory terms only. The residual hash and page pool are
        # intentionally reported elsewhere because they are unchanged by this
        # optimization. The fold multiplies every non-dummy primary cell by one
        # secret relation selector; each dependent read then scans MAX_BLOCK and
        # gates its packed descriptor by the secret ontology-range check.
        columns = config.directory_columns
        unfolded = query_count * frontier_slots * directory_products
        folded = query_count * (
            (config.directory_rows - 1) * columns
            + frontier_slots * config.type_blocks.max_block * columns
            + frontier_slots * columns
        )
        estimate.update(
            {
                "hybrid_primary_second_hop_unfolded_products": unfolded,
                "hybrid_primary_second_hop_folded_products": folded,
                "hybrid_primary_folded_product_ratio": (
                    unfolded / folded if folded else 0.0
                ),
            }
        )
        if params.partition_residual_by_relation:
            residual_width = owner_count * (params.bucket_slots or 1)
            residual_rows = config.residual_directory_rows
            buckets = params.directory_buckets or 1
            unfolded_residual = (
                query_count * frontier_slots * residual_rows * residual_width
            )
            folded_residual = query_count * (
                relation_count * buckets * residual_width
                + frontier_slots * buckets * residual_width
            )
            estimate.update(
                {
                    "hybrid_residual_second_hop_unfolded_fetch_products": (
                        unfolded_residual
                    ),
                    "hybrid_residual_second_hop_folded_fetch_products": (
                        folded_residual
                    ),
                    "hybrid_residual_folded_fetch_product_ratio": (
                        unfolded_residual / folded_residual
                        if folded_residual
                        else 0.0
                    ),
                }
            )
    return estimate


def write_program(
    config: RelationPageConfig,
    query_count: int,
    output_dir: str | Path,
    *,
    ablate_relation_check: bool = False,
    ablate_window_demux: bool = False,
    ablate_folded_directory: bool = False,
    ablate_folded_residual: bool = False,
    ablate_compaction: bool = False,
    ablate_owner_batching: bool = False,
) -> Path:
    name = program_name(
        config,
        query_count,
        ablate_relation_check=ablate_relation_check,
        ablate_window_demux=ablate_window_demux,
        ablate_folded_directory=ablate_folded_directory,
        ablate_folded_residual=ablate_folded_residual,
        ablate_compaction=ablate_compaction,
        ablate_owner_batching=ablate_owner_batching,
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
            ablate_folded_residual=ablate_folded_residual,
            ablate_compaction=ablate_compaction,
            ablate_owner_batching=ablate_owner_batching,
        ),
        encoding="utf-8",
    )
    return destination


# --------------------------------------------------------------------------
# Compile-shape analysis
# --------------------------------------------------------------------------
# Three circuits in this project failed to compile before the cause was
# understood, and the cause was not product count. MP-SPDZ unrolls a `map_sum`
# body once per output element, so program text tracks the **output width** of
# each map_sum, not its iteration count. The dense directory read iterates
# 200,000 times with a width of ~16 and compiles in seconds; the compact bucket
# fetch iterated 16 times with a width of 1,425 and never finished.
#
# This predicts the widths from a configuration so the wall can be seen before
# 30 minutes are spent hitting it.

# Empirical, not derived: 1,425 failed repeatedly and ~200 shapes compile fine.
# Treat it as an order-of-magnitude warning line rather than a hard boundary.
MAP_SUM_WIDTH_WARNING = 512


def compile_shape_report(
    config: RelationPageConfig, query_count: int
) -> dict[str, object]:
    """Predict each map_sum's output width, and flag those likely not to compile.

    Returns the widths rather than a verdict, because the threshold is empirical
    and the useful output is "here is the widest stage and why", not a boolean.
    """

    base = config.base
    params = config.pages
    owner_count = len(base.owners)
    frontier = params.frontier_slots(owner_count)
    addresses = max(query_count, query_count * frontier)

    stages: dict[str, int] = {
        # Dense read: narrow by construction -- one packed element per address.
        "dense_directory_read": query_count * config.directory_columns,
        # The relation fold is chunked, so its per-map_sum width is bounded by
        # FOLD_CHUNK regardless of how many entities there are. Before chunking
        # this was entity_count and was the next stage due to hit the wall.
        "relation_fold": min(
            base.entity_count * config.directory_columns,
            max(1, 256 // max(1, config.directory_columns))
            * config.directory_columns,
        ),
        "folded_directory_read": addresses * config.directory_columns,
        "page_window_read": addresses * params.page_size,
    }
    if params.uses_compact_directory:
        # Emitted as a matrix multiply, so it contributes no unrolled width.
        stages["compact_bucket_fetch_matmul"] = 0
    widest = max(stages, key=lambda name: stages[name])
    return {
        "stages": stages,
        "widest_stage": widest,
        "widest_width": stages[widest],
        "over_warning_threshold": sorted(
            name for name, width in stages.items()
            if width > MAP_SUM_WIDTH_WARNING
        ),
        "threshold": MAP_SUM_WIDTH_WARNING,
    }
