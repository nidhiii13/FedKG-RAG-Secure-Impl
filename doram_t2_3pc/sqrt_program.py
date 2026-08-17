"""Unsupported MP-SPDZ square-root ORAM experiment.

The tested MP-SPDZ implementation produced an out-of-range private position-map
address at runtime in the three-party configuration. This module is retained
only to record the experiment; ``scan_program`` is the supported scalable
baseline.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .config import PublicConfig, SCALABLE_FIELD_PRIME, reject_scan_only_options
from .packed import packed_edge_bits, packing_widths


SQRT_PROGRAM_VERSION = 2


def _validate(config: PublicConfig, query_count: int) -> None:
    reject_scan_only_options(config, "square-root ORAM experiment")
    if config.field_prime != SCALABLE_FIELD_PRIME:
        raise ValueError("square-root DORAM requires field_prime=2^127-1")
    if not 1 <= query_count <= 100:
        raise ValueError("query_count must be in [1, 100]")
    if packed_edge_bits(config) > config.field_usable_bits:
        raise ValueError("packed edge does not fit the scalable field")


def program_name(config: PublicConfig, query_count: int) -> str:
    _validate(config, query_count)
    material = f"{SQRT_PROGRAM_VERSION}:{query_count}:{config.digest}".encode()
    suffix = hashlib.sha256(material).hexdigest()[:16]
    return f"doram_sqrt_3pc_{suffix}"


def render_program(config: PublicConfig, query_count: int) -> str:
    _validate(config, query_count)
    slot_bits, relation_bits, evidence_bits, score_bits, valid_bits = packing_widths(
        config
    )
    return f'''# Generated fixed-batch square-root DORAM program.
from Compiler.library import print_ln_to, start_timer, stop_timer
from Compiler.sqrt_oram import SqrtOram
from Compiler.types import Array, Matrix, sint

program.use_edabit(True)
program.timeout = None

SERVER_COUNT = 3
ENTITY_COUNT = {config.entity_count}
BLOCK_EDGES = {config.block_edges}
CANDIDATE_COUNT = {config.candidate_count}
TOP_K = {config.top_k}
QUERY_COUNT = {query_count}
SLOT_BITS = {slot_bits}
RELATION_BITS = {relation_bits}
EVIDENCE_BITS = {evidence_bits}
SCORE_BITS = {score_bits}
PACKED_EDGE_BITS = {packed_edge_bits(config)}


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


queries = shared_matrix(QUERY_COUNT, 3)

start_timer(10)
graph_values = shared_matrix(ENTITY_COUNT, BLOCK_EDGES)
stop_timer(10)

# The graph is initialized once for the entire fixed public query batch. The
# random shuffle and recursive private position map hide all later addresses.
start_timer(11)
graph = SqrtOram(graph_values, entry_length=BLOCK_EDGES, value_type=sint)
stop_timer(11)


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
    query_source = queries[query_index][0]
    query_relation_1 = queries[query_index][1]
    query_relation_2 = queries[query_index][2]

    left_evidence = Array(CANDIDATE_COUNT, sint)
    right_evidence = Array(CANDIDATE_COUNT, sint)
    candidate_score = Array(CANDIDATE_COUNT, sint)
    candidate_valid = Array(CANDIDATE_COUNT, sint)
    selected = Array(CANDIDATE_COUNT, sint)

    start_timer(20 + query_index * 3)
    query_source_valid = (query_source != 0) * (query_source < ENTITY_COUNT)
    safe_query_source = query_source_valid.if_else(query_source, sint(0))
    # SqrtOram's position map operates on its narrow signed index type.  An
    # explicit cast is required here: passing a full-field ``sint`` silently
    # corrupts the position-map demultiplexer in current MP-SPDZ releases.
    first_block = graph.read(graph.index_type(safe_query_source))

    for first_index in range(BLOCK_EDGES):
        first_target, first_relation, first_handle, first_score, first_stored_valid = \
            unpack_edge(first_block[first_index])
        first_valid = (
            query_source_valid
            * first_stored_valid
            * (first_target != 0)
            * (first_relation == query_relation_1)
        )
        safe_second_address = first_valid.if_else(first_target, sint(0))
        second_block = graph.read(graph.index_type(safe_second_address))

        for second_index in range(BLOCK_EDGES):
            candidate = first_index * BLOCK_EDGES + second_index
            _, second_relation, second_handle, second_score, second_stored_valid = \
                unpack_edge(second_block[second_index])
            valid = first_valid * second_stored_valid * (
                second_relation == query_relation_2
            )
            left_evidence[candidate] = valid * first_handle
            right_evidence[candidate] = valid * second_handle
            candidate_score[candidate] = valid * (first_score + second_score)
            candidate_valid[candidate] = valid
            selected[candidate] = sint(0)
    stop_timer(20 + query_index * 3)

    result_valid = Array(TOP_K, sint)
    result_left = Array(TOP_K, sint)
    result_right = Array(TOP_K, sint)
    result_score = Array(TOP_K, sint)

    start_timer(21 + query_index * 3)
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
    stop_timer(21 + query_index * 3)

    start_timer(22 + query_index * 3)
    for rank in range(TOP_K):
        emit_output_shares(query_index, rank, 0, result_valid[rank])
        emit_output_shares(query_index, rank, 1, result_left[rank])
        emit_output_shares(query_index, rank, 2, result_right[rank])
        emit_output_shares(query_index, rank, 3, result_score[rank])
    stop_timer(22 + query_index * 3)
'''


def write_program(
    config: PublicConfig, query_count: int, output_dir: str | Path
) -> Path:
    destination = Path(output_dir) / f"{program_name(config, query_count)}.mpc"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_program(config, query_count), encoding="utf-8")
    return destination
