"""Research-only persistent RecursiveORAM experiment.

It is correct on the small fixture, but its secure 160k initialization has an
impractical preprocessing count.  Use ``scan_program`` for the supported
six-figure baseline.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .config import (
    EDGE_FIELDS,
    PublicConfig,
    SCALABLE_FIELD_PRIME,
    reject_scan_only_options,
)


SCALABLE_PROGRAM_VERSION = 1


def _require_scalable_config(config: PublicConfig) -> None:
    reject_scan_only_options(config, "RecursiveORAM experiment")
    if config.field_prime != SCALABLE_FIELD_PRIME:
        raise ValueError(
            "scalable DORAM requires field_prime=2^127-1 for RecursiveORAM"
        )


def _entry_sizes(config: PublicConfig) -> tuple[int, ...]:
    slot_bits = max(1, (config.entity_count - 1).bit_length())
    relation_bits = max(1, max(config.relations.values()).bit_length())
    result: list[int] = []
    for _ in range(config.block_edges):
        result.extend(
            (slot_bits, relation_bits, config.evidence_bits, config.score_bits, 1)
        )
    return tuple(result)


def _program_suffix(config: PublicConfig) -> str:
    material = f"{SCALABLE_PROGRAM_VERSION}:{config.digest}".encode()
    return hashlib.sha256(material).hexdigest()[:16]


def setup_program_name(config: PublicConfig) -> str:
    _require_scalable_config(config)
    return f"doram_setup_3pc_{_program_suffix(config)}"


def query_program_name(config: PublicConfig) -> str:
    _require_scalable_config(config)
    return f"doram_query_3pc_{_program_suffix(config)}"


def _common_source(config: PublicConfig) -> str:
    return f'''from Compiler import oram as oram_module
from Compiler.library import for_range, print_ln_to, start_timer, stop_timer
from Compiler.types import Array, Matrix, MemValue, cint, sint

program.use_edabit(True)
# MP-SPDZ imposes a generic five-minute source-expansion guard. Secure batch
# initialization at six-figure ORAM sizes is expected to exceed it once, so the
# scalable runner supplies its own bounded subprocess timeout instead.
program.timeout = None

SERVER_COUNT = 3
ENTITY_COUNT = {config.entity_count}
OWNER_COUNT = {len(config.owners)}
FANOUT_PER_OWNER = {config.fanout_per_owner}
BLOCK_EDGES = {config.block_edges}
BLOCK_FIELDS = {config.block_edges * len(EDGE_FIELDS)}
CANDIDATE_COUNT = {config.candidate_count}
TOP_K = {config.top_k}
FIELD_COUNT = {len(EDGE_FIELDS)}
ENTRY_SIZE = {_entry_sizes(config)!r}


# Batch initialization and persistence restore overwrite every state cell. The
# default constructors would first clear the same large arrays, which is pure
# overhead and does not contribute to ORAM security.
def _skip_ram_init(self, *args):
    pass


oram_module.RefRAM.init_mem = _skip_ram_init
oram_module.RefTrivialORAM.init_mem = _skip_ram_init


def new_graph():
    return oram_module.OptimalORAM(
        ENTITY_COUNT, entry_size=ENTRY_SIZE, init_rounds=0
    )


def state_arrays(graph):
    """Return all secret arrays that define the recursive ORAM state."""
    arrays = []
    seen_arrays = set()
    seen_objects = set()

    def add(array):
        marker = id(array)
        if marker not in seen_arrays:
            seen_arrays.add(marker)
            arrays.append(array)

    def walk_oram(current):
        marker = id(current)
        if marker in seen_objects:
            return
        seen_objects.add(marker)
        ram = getattr(current, 'ram', None)
        if ram is not None:
            for array in ram.l:
                add(array)
        index = getattr(current, 'index', None)
        if index is not None and not isinstance(index, (int, cint)):
            walk_index(index)

    def walk_index(index):
        marker = id(index)
        if marker in seen_objects:
            return
        seen_objects.add(marker)
        storage = getattr(index, 'l', None)
        if storage is None:
            return
        if hasattr(storage, 'ram'):
            walk_oram(storage)
        elif hasattr(storage, 'l'):
            for array in storage.l:
                add(array)

    walk_oram(graph)
    return arrays


def restore_state(graph):
    offset = 0
    for array in state_arrays(graph):
        array.read_from_file(offset)
        offset += len(array)
    return offset


def persist_state(graph):
    offset = 0
    for array in state_arrays(graph):
        array.write_to_file(position=offset)
        offset += len(array)
    return offset


def shared_matrix(rows, columns):
    result = Matrix(rows, columns, sint)
    result.input_from(0)
    for player in (1, 2):
        incoming = Matrix(rows, columns, sint)
        incoming.input_from(player)
        result.assign_vector(result[:] + incoming[:])
        incoming.delete()
    return result
'''


def render_setup_program(config: PublicConfig) -> str:
    _require_scalable_config(config)
    return (
        "# Generated scalable DORAM setup program.\n"
        + _common_source(config)
        + '''
start_timer(10)
graph_values = shared_matrix(ENTITY_COUNT, BLOCK_FIELDS)
stop_timer(10)

graph = new_graph()
start_timer(11)
graph.batch_init(graph_values)
stop_timer(11)
graph_values.delete()

start_timer(12)
state_share_count = persist_state(graph)
stop_timer(12)

for server in range(SERVER_COUNT):
    print_ln_to(server, 'DORAM_SETUP_READY %s', cint(state_share_count))
'''
    )


def render_query_program(config: PublicConfig) -> str:
    _require_scalable_config(config)
    return (
        "# Generated scalable persistent DORAM query program.\n"
        + _common_source(config)
        + '''
graph = new_graph()
start_timer(20)
state_share_count = restore_state(graph)
stop_timer(20)

start_timer(21)
query = shared_matrix(1, 3)
query_source = query[0][0]
query_relation_1 = query[0][1]
query_relation_2 = query[0][2]
stop_timer(21)

left_evidence = Array(CANDIDATE_COUNT, sint)
right_evidence = Array(CANDIDATE_COUNT, sint)
candidate_score = Array(CANDIDATE_COUNT, sint)
candidate_valid = Array(CANDIDATE_COUNT, sint)
selected = Array(CANDIDATE_COUNT, sint)

# Inputs and indexed graph targets are range-checked by the semi-honest input
# preparation. This constant-size check avoids the legacy O(ENTITY_COUNT)
# equality enumeration that would nullify recursive ORAM scaling.
start_timer(22)
query_source_valid = (query_source != 0) * (query_source < ENTITY_COUNT)
safe_query_source = query_source_valid.if_else(query_source, sint(0))
first_block = graph[safe_query_source]
stop_timer(22)

start_timer(23)
for first_index in range(BLOCK_EDGES):
    first_base = first_index * FIELD_COUNT
    first_target = first_block[first_base]
    first_relation = first_block[first_base + 1]
    first_handle = first_block[first_base + 2]
    first_score = first_block[first_base + 3]
    first_stored_valid = first_block[first_base + 4]
    first_valid = (
        query_source_valid
        * first_stored_valid
        * (first_target != 0)
        * (first_relation == query_relation_1)
    )
    safe_second_address = first_valid.if_else(first_target, sint(0))
    second_block = graph[safe_second_address]

    for second_index in range(BLOCK_EDGES):
        second_base = second_index * FIELD_COUNT
        candidate = first_index * BLOCK_EDGES + second_index
        second_relation = second_block[second_base + 1]
        second_handle = second_block[second_base + 2]
        second_score = second_block[second_base + 3]
        second_stored_valid = second_block[second_base + 4]
        valid = first_valid * second_stored_valid * (
            second_relation == query_relation_2
        )
        left_evidence[candidate] = valid * first_handle
        right_evidence[candidate] = valid * second_handle
        candidate_score[candidate] = valid * (first_score + second_score)
        candidate_valid[candidate] = valid
        selected[candidate] = sint(0)
stop_timer(23)

result_valid = Array(TOP_K, sint)
result_left = Array(TOP_K, sint)
result_right = Array(TOP_K, sint)
result_score = Array(TOP_K, sint)

start_timer(24)
for rank in range(TOP_K):
    best_valid = sint(0)
    best_score = sint(0)
    best_index = sint(0)
    best_left = sint(0)
    best_right = sint(0)
    for candidate in range(CANDIDATE_COUNT):
        available = candidate_valid[candidate] * (sint(1) - selected[candidate])
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
stop_timer(24)

# Every read changes the secret position map, so persist the updated ORAM before
# accepting another query process.
start_timer(25)
persist_state(graph)
stop_timer(25)


def emit_output_shares(rank, field, value):
    share_0 = sint.get_random()
    share_1 = sint.get_random()
    share_2 = value - share_0 - share_1
    print_ln_to(0, 'DORAM_SHARE %s %s 0 %s', rank, field, share_0.reveal_to(0))
    print_ln_to(1, 'DORAM_SHARE %s %s 1 %s', rank, field, share_1.reveal_to(1))
    print_ln_to(2, 'DORAM_SHARE %s %s 2 %s', rank, field, share_2.reveal_to(2))


start_timer(26)
for rank in range(TOP_K):
    emit_output_shares(rank, 0, result_valid[rank])
    emit_output_shares(rank, 1, result_left[rank])
    emit_output_shares(rank, 2, result_right[rank])
    emit_output_shares(rank, 3, result_score[rank])
stop_timer(26)
'''
    )


def write_setup_program(config: PublicConfig, output_dir: str | Path) -> Path:
    destination = Path(output_dir) / f"{setup_program_name(config)}.mpc"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_setup_program(config), encoding="utf-8")
    return destination


def write_query_program(config: PublicConfig, output_dir: str | Path) -> Path:
    destination = Path(output_dir) / f"{query_program_name(config)}.mpc"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_query_program(config), encoding="utf-8")
    return destination
