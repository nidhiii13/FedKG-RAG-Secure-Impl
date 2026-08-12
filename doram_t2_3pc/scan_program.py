from __future__ import annotations

import hashlib
from pathlib import Path

from .config import PublicConfig, SCALABLE_FIELD_PRIME
from .packed import packed_edge_bits, packing_widths


SCAN_PROGRAM_VERSION = 1
MAX_BATCH_QUERIES = 10


def _validate(config: PublicConfig, query_count: int) -> None:
    if config.field_prime != SCALABLE_FIELD_PRIME:
        raise ValueError("packed-scan DORAM requires the scalable field prime")
    if not 1 <= query_count <= MAX_BATCH_QUERIES:
        raise ValueError(
            f"query_count must be in [1, {MAX_BATCH_QUERIES}]"
        )
    if packed_edge_bits(config) > config.field_usable_bits:
        raise ValueError("packed edge does not fit the scalable field")


def program_name(config: PublicConfig, query_count: int) -> str:
    _validate(config, query_count)
    material = f"{SCAN_PROGRAM_VERSION}:{query_count}:{config.digest}".encode()
    suffix = hashlib.sha256(material).hexdigest()[:16]
    return f"doram_scan_3pc_{suffix}"


def render_program(config: PublicConfig, query_count: int) -> str:
    """Render a fixed-batch, packed, linear-scan DORAM circuit.

    The secret addresses are converted to one-hot vectors and every public
    graph position is touched.  This is O(N), but it is robust at six-figure
    sizes because it avoids recursive ORAM initialization and batches all
    independent first- and second-hop reads into two parallel scans.
    """
    _validate(config, query_count)
    slot_bits, relation_bits, evidence_bits, score_bits, _ = packing_widths(
        config
    )
    index_bits = max(1, (config.entity_count - 1).bit_length())
    return f'''# Generated fixed-batch packed oblivious-scan DORAM program.
from Compiler.library import map_sum, print_ln_to, start_timer, stop_timer
from Compiler.oram import demux_matrix
from Compiler.types import Array, Matrix, sint

program.use_edabit(True)
program.timeout = None

SERVER_COUNT = 3
ENTITY_COUNT = {config.entity_count}
BLOCK_EDGES = {config.block_edges}
CANDIDATE_COUNT = {config.candidate_count}
TOP_K = {config.top_k}
QUERY_COUNT = {query_count}
INDEX_BITS = {index_bits}
SLOT_BITS = {slot_bits}
RELATION_BITS = {relation_bits}
EVIDENCE_BITS = {evidence_bits}
SCORE_BITS = {score_bits}
PACKED_EDGE_BITS = {packed_edge_bits(config)}
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


# All addresses in a batch are read in one pass. demux_matrix creates a
# secret one-hot column for each address; scan_row then touches every graph
# row and sums the selected blocks. No address or selector is opened.
def oblivious_batch_read(addresses, address_count):
    address_vector = addresses.get_vector(0, address_count)
    address_bits = address_vector.bit_decompose(INDEX_BITS)
    selectors = demux_matrix(address_bits, n_threads=SCAN_THREADS)

    @map_sum(
        SCAN_THREADS,
        1024,
        ENTITY_COUNT,
        address_count * BLOCK_EDGES,
        [sint] * (address_count * BLOCK_EDGES),
    )
    def scan_row(entity):
        block = graph_values[entity]
        selected = selectors[entity]
        return tuple(
            selected[address] * block[edge]
            for address in range(address_count)
            for edge in range(BLOCK_EDGES)
        )

    result = Array.create_from(scan_row())
    selectors.delete()
    return result


queries = shared_matrix(QUERY_COUNT, 3)

start_timer(10)
graph_values = shared_matrix(ENTITY_COUNT, BLOCK_EDGES)
stop_timer(10)

query_sources = Array(QUERY_COUNT, sint)
query_source_valid = Array(QUERY_COUNT, sint)
for query_index in range(QUERY_COUNT):
    source = queries[query_index][0]
    valid = (source != 0) * (source < ENTITY_COUNT)
    query_source_valid[query_index] = valid
    query_sources[query_index] = valid.if_else(source, sint(0))

start_timer(11)
first_blocks = oblivious_batch_read(query_sources, QUERY_COUNT)
stop_timer(11)

SECOND_ADDRESS_COUNT = QUERY_COUNT * BLOCK_EDGES
second_addresses = Array(SECOND_ADDRESS_COUNT, sint)
first_valids = Array(SECOND_ADDRESS_COUNT, sint)
first_handles = Array(SECOND_ADDRESS_COUNT, sint)
first_scores = Array(SECOND_ADDRESS_COUNT, sint)

start_timer(12)
for query_index in range(QUERY_COUNT):
    relation_1 = queries[query_index][1]
    for first_index in range(BLOCK_EDGES):
        flat = query_index * BLOCK_EDGES + first_index
        packed = first_blocks[flat]
        target, relation, handle, score, stored_valid = unpack_edge(packed)
        valid = (
            query_source_valid[query_index]
            * stored_valid
            * (target != 0)
            * (target < ENTITY_COUNT)
            * (relation == relation_1)
        )
        first_valids[flat] = valid
        first_handles[flat] = valid * handle
        first_scores[flat] = valid * score
        second_addresses[flat] = valid.if_else(target, sint(0))
stop_timer(12)

start_timer(13)
second_blocks = oblivious_batch_read(second_addresses, SECOND_ADDRESS_COUNT)
stop_timer(13)


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


for query_index in range(QUERY_COUNT):
    relation_2 = queries[query_index][2]
    left_evidence = Array(CANDIDATE_COUNT, sint)
    right_evidence = Array(CANDIDATE_COUNT, sint)
    candidate_score = Array(CANDIDATE_COUNT, sint)
    candidate_valid = Array(CANDIDATE_COUNT, sint)
    selected = Array(CANDIDATE_COUNT, sint)

    start_timer(20 + query_index * 2)
    for first_index in range(BLOCK_EDGES):
        first_flat = query_index * BLOCK_EDGES + first_index
        for second_index in range(BLOCK_EDGES):
            candidate = first_index * BLOCK_EDGES + second_index
            second_flat = first_flat * BLOCK_EDGES + second_index
            _, relation, handle, score, stored_valid = unpack_edge(
                second_blocks[second_flat]
            )
            valid = (
                first_valids[first_flat]
                * stored_valid
                * (relation == relation_2)
            )
            left_evidence[candidate] = valid * first_handles[first_flat]
            right_evidence[candidate] = valid * handle
            candidate_score[candidate] = valid * (
                first_scores[first_flat] + score
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
        result_valid[rank] = best_valid
        result_score[rank] = best_valid * best_score
        result_left[rank] = best_valid * best_left
        result_right[rank] = best_valid * best_right
        for candidate in range(CANDIDATE_COUNT):
            selected[candidate] = selected[candidate] + best_valid * (
                best_index == candidate
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


def write_program(
    config: PublicConfig, query_count: int, output_dir: str | Path
) -> Path:
    destination = Path(output_dir) / f"{program_name(config, query_count)}.mpc"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_program(config, query_count), encoding="utf-8")
    return destination
