from __future__ import annotations

import argparse
import re
from pathlib import Path

from .config import (
    EDGE_FIELDS,
    FIELD_PRIME,
    PublicConfig,
    reject_scan_only_options,
)


def program_name(config: PublicConfig) -> str:
    reject_scan_only_options(config, "legacy OptimalORAM backend")
    return f"doram_t2_3pc_{config.digest[:16]}"


def render_program(config: PublicConfig) -> str:
    reject_scan_only_options(config, "legacy OptimalORAM backend")
    slot_bits = max(1, (config.entity_count - 1).bit_length())
    relation_bits = max(1, max(config.relations.values()).bit_length())
    entry_sizes = []
    for _ in range(config.block_edges):
        entry_sizes.extend(
            [slot_bits, relation_bits, config.evidence_bits, config.score_bits, 1]
        )
    return f'''# Generated from public bounds only. Do not add plaintext secrets here.
from Compiler.library import print_ln_to
from Compiler.oram import OptimalORAM
from Compiler.types import Array, sint

program.use_edabit(True)

SERVER_COUNT = 3
ENTITY_COUNT = {config.entity_count}
OWNER_COUNT = {len(config.owners)}
FANOUT_PER_OWNER = {config.fanout_per_owner}
BLOCK_EDGES = {config.block_edges}
CANDIDATE_COUNT = {config.candidate_count}
TOP_K = {config.top_k}
FIELD_COUNT = {len(EDGE_FIELDS)}


def shared_external_input():
    # Every server inputs one externally generated additive share. MP-SPDZ
    # keeps their sum secret throughout the circuit.
    return (
        sint.get_input_from(0)
        + sint.get_input_from(1)
        + sint.get_input_from(2)
    )


def valid_real_entity_address(value):
    # Equality enumeration avoids ever indexing ORAM with a malformed secret
    # address. Slot zero is the dummy block, not a valid external query/target.
    valid = sint(0)
    for address in range(1, ENTITY_COUNT):
        valid = valid + (value == address)
    return valid


query_source = shared_external_input()
query_relation_1 = shared_external_input()
query_relation_2 = shared_external_input()

entry_size = {tuple(entry_sizes)!r}
graph = OptimalORAM(ENTITY_COUNT, entry_size=entry_size)

for entity in range(ENTITY_COUNT):
    block = []
    for owner in range(OWNER_COUNT):
        for local_edge in range(FANOUT_PER_OWNER):
            for field in range(FIELD_COUNT):
                block.append(shared_external_input())
    graph[entity] = tuple(block)

left_evidence = Array(CANDIDATE_COUNT, sint)
right_evidence = Array(CANDIDATE_COUNT, sint)
candidate_score = Array(CANDIDATE_COUNT, sint)
candidate_valid = Array(CANDIDATE_COUNT, sint)
selected = Array(CANDIDATE_COUNT, sint)

# First address is secret. Every possible first-hop edge causes exactly one
# second read; the second address is the secret output of the first read.
query_source_valid = valid_real_entity_address(query_source)
safe_query_source = query_source_valid.if_else(query_source, sint(0))
first_block = graph[safe_query_source]
for first_index in range(BLOCK_EDGES):
    first_base = first_index * FIELD_COUNT
    first_target = first_block[first_base]
    first_relation = first_block[first_base + 1]
    first_handle = first_block[first_base + 2]
    first_score = first_block[first_base + 3]
    first_stored_valid = first_block[first_base + 4]
    target_in_range = valid_real_entity_address(first_target)
    first_valid = (
        query_source_valid
        * first_stored_valid
        * target_in_range
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
        valid = first_valid * second_stored_valid * (second_relation == query_relation_2)
        left_evidence[candidate] = valid * first_handle
        right_evidence[candidate] = valid * second_handle
        candidate_score[candidate] = valid * (first_score + second_score)
        candidate_valid[candidate] = valid
        selected[candidate] = sint(0)

result_valid = Array(TOP_K, sint)
result_left = Array(TOP_K, sint)
result_right = Array(TOP_K, sint)
result_score = Array(TOP_K, sint)

# Stable, data-oblivious top-k. Loop counts and memory traversal depend only
# on public bounds. Ties keep the lower fixed candidate position.
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
        selected[candidate] = selected[candidate] + best_valid * (best_index == candidate)


def emit_output_shares(rank, field, value):
    # The result is never opened to a computation server. Each receives one
    # fresh full-field additive share for the external query client.
    share_0 = sint.get_random()
    share_1 = sint.get_random()
    share_2 = value - share_0 - share_1
    print_ln_to(0, 'DORAM_SHARE %s %s 0 %s', rank, field, share_0.reveal_to(0))
    print_ln_to(1, 'DORAM_SHARE %s %s 1 %s', rank, field, share_1.reveal_to(1))
    print_ln_to(2, 'DORAM_SHARE %s %s 2 %s', rank, field, share_2.reveal_to(2))


for rank in range(TOP_K):
    emit_output_shares(rank, 0, result_valid[rank])
    emit_output_shares(rank, 1, result_left[rank])
    emit_output_shares(rank, 2, result_right[rank])
    emit_output_shares(rank, 3, result_score[rank])
'''


def write_program(config: PublicConfig, output_dir: str | Path) -> Path:
    destination = Path(output_dir) / f"{program_name(config)}.mpc"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_program(config), encoding="utf-8")
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the fixed-bound MP-SPDZ DORAM program")
    parser.add_argument("--config", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    path = write_program(PublicConfig.load(args.config), args.output_dir)
    if not re.fullmatch(r"doram_t2_3pc_[0-9a-f]{16}\.mpc", path.name):
        raise AssertionError("unsafe generated program name")
    print(path)


if __name__ == "__main__":
    main()
