"""Generate a standalone MP-SPDZ recursive read-only ORAM access circuit.

This is a research backend, not yet the KG retrieval backend.  It closes the
most important missing implementation step in ``oram_layout.py``: the owner-
built recursive position map is traversed inside MPC, and only uniformly random
root-to-leaf paths are opened.  A per-level secret stash makes repeated reads
safe without Path-ORAM eviction for a public, bounded, read-only epoch.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .oram_access import OramAccessShape


ORAM_ACCESS_PROGRAM_VERSION = 1


def program_name(shape: OramAccessShape) -> str:
    material = repr((ORAM_ACCESS_PROGRAM_VERSION, shape)).encode("ascii")
    return "readonly_oram_3pc_" + hashlib.sha256(material).hexdigest()[:16]


def _level_constants(shape: OramAccessShape) -> str:
    lines: list[str] = []
    for index, level in enumerate(shape.levels):
        lines.extend(
            (
                f"LEVEL_{index}_SIZE = {level.size}",
                f"LEVEL_{index}_BUCKET_SIZE = {level.bucket_size}",
                f"LEVEL_{index}_DEPTH = {level.depth}",
                f"LEVEL_{index}_SLOTS = {level.slots}",
                f"LEVEL_{index}_FIELDS = {level.field_count}",
            )
        )
    return "\n".join(lines)


def _storage(shape: OramAccessShape) -> str:
    blocks: list[str] = []
    for level_index, level in enumerate(shape.levels):
        blocks.append(f"level_{level_index} = []")
        for field in range(level.field_count):
            blocks.append(
                f"level_{level_index}.append(shared_array(LEVEL_{level_index}_SLOTS))"
            )
    blocks.append("position_base = shared_array(BASE_ENTRIES)")
    blocks.append("requested = shared_array(MAX_ACCESSES)")
    return "\n".join(blocks)


def _stash_storage(shape: OramAccessShape) -> str:
    blocks: list[str] = []
    for level_index, level in enumerate(shape.levels):
        value_width = level.field_count - 3
        blocks.extend(
            (
                f"stash_{level_index}_valid = Array(MAX_ACCESSES, sint)",
                f"stash_{level_index}_index = Array(MAX_ACCESSES, sint)",
                f"stash_{level_index}_values = Matrix(MAX_ACCESSES, {value_width}, sint)",
                f"stash_{level_index}_valid.assign_all(0)",
                f"stash_{level_index}_index.assign_all(0)",
                f"stash_{level_index}_values.assign_all(0)",
            )
        )
    return "\n".join(blocks)


def _access_level(level_index: int, shape: OramAccessShape) -> str:
    level = shape.levels[level_index]
    value_width = level.field_count - 3
    return f'''def access_level_{level_index}(wanted, real_leaf, access_number):
    """Read level {level_index}; open one uniform path regardless of stash hit."""
    stash_hit = sint(0)
    stashed = Array({value_width}, sint)
    stashed.assign_all(0)
    for slot in range(MAX_ACCESSES):
        before = access_number > slot
        same = stash_{level_index}_valid[slot] * before * (
            stash_{level_index}_index[slot] == wanted
        )
        take = same * (sint(1) - stash_hit)
        stash_hit = stash_hit + take
        for field in range({value_width}):
            stashed[field] = stashed[field] + take * stash_{level_index}_values[slot][field]

    # A genuine leaf was assigned uniformly by the owner and is opened at most
    # once.  Every repeat opens a fresh uniform dummy leaf of identical width.
    dummy_leaf = sint.get_random_int(LEVEL_{level_index}_DEPTH)
    opened_leaf = stash_hit.if_else(dummy_leaf, real_leaf).reveal()
    bucket = opened_leaf + 2 ** LEVEL_{level_index}_DEPTH
    fetched = Array({value_width}, sint)
    fetched.assign_all(0)
    found = sint(0)
    for path_offset in range(LEVEL_{level_index}_DEPTH + 1):
        for bucket_offset in range(LEVEL_{level_index}_BUCKET_SIZE):
            physical = bucket * LEVEL_{level_index}_BUCKET_SIZE + bucket_offset
            occupied = sint(1) - level_{level_index}[0][physical]
            match = occupied * (level_{level_index}[1][physical] == wanted)
            take = match * (sint(1) - found)
            found = found + take
            for field in range({value_width}):
                fetched[field] = fetched[field] + take * level_{level_index}[field + 3][physical]
        bucket = bucket // 2

    result = Array({value_width}, sint)
    for field in range({value_width}):
        result[field] = stash_hit.if_else(stashed[field], fetched[field])

    # Each public access number owns one stash slot. A repeated level index
    # leaves a hole, which is harmless and avoids a secret write address.
    new_entry = sint(1) - stash_hit
    for slot in range(MAX_ACCESSES):
        is_slot = access_number == slot
        write = new_entry * is_slot
        stash_{level_index}_valid[slot] = stash_{level_index}_valid[slot] + write
        stash_{level_index}_index[slot] = stash_{level_index}_index[slot] + write * wanted
        for field in range({value_width}):
            stash_{level_index}_values[slot][field] = (
                stash_{level_index}_values[slot][field] + write * fetched[field]
            )
    return result, stash_hit.if_else(sint(1), found)
'''


def _access_body(shape: OramAccessShape) -> str:
    top = len(shape.levels) - 1
    chi_bits = shape.chi.bit_length() - 1
    lines = [
        "for access_number in range(MAX_ACCESSES):",
        "    original = requested[access_number]",
        "    address_ok = (original >= 0) * (original < DATA_SIZE)",
        "    address = address_ok.if_else(original, sint(0))",
        f"    address_bits = address.bit_decompose(DATA_INDEX_BITS)",
        f"    top_index = sint.bit_compose(address_bits[{top * chi_bits}:])",
        "    leaf = sint(0)",
        "    for base_index in range(BASE_ENTRIES):",
        "        leaf = leaf + (top_index == base_index) * position_base[base_index]",
        "    chain_valid = address_ok",
    ]
    for level_index in range(top, -1, -1):
        shift = level_index * chi_bits
        lines.extend(
            (
                f"    level_{level_index}_index = sint.bit_compose(address_bits[{shift}:])",
                f"    level_{level_index}_value, level_{level_index}_found = access_level_{level_index}(",
                f"        level_{level_index}_index, leaf, access_number",
                "    )",
                f"    chain_valid = chain_valid * level_{level_index}_found",
            )
        )
        if level_index > 0:
            child_shift = (level_index - 1) * chi_bits
            lines.extend(
                (
                    f"    child_offset = sint.bit_compose(address_bits[{child_shift}:{child_shift + chi_bits}])",
                    "    leaf = sint(0)",
                    "    for child in range(CHI):",
                    f"        leaf = leaf + (child_offset == child) * level_{level_index}_value[child]",
                )
            )
        else:
            lines.extend(
                (
                    "    emit_output_share(access_number, 0, chain_valid)",
                    "    for field in range(DATA_VALUE_WIDTH):",
                    "        emit_output_share(",
                    "            access_number, field + 1,",
                    "            chain_valid * level_0_value[field]",
                    "        )",
                )
            )
    return "\n".join(lines)


def render_program(shape: OramAccessShape) -> str:
    if not shape.levels:
        raise ValueError("ORAM access requires at least one tree level")
    if shape.max_accesses < 1:
        raise ValueError("max_accesses must be positive")
    if shape.chi < 2 or shape.chi & (shape.chi - 1):
        raise ValueError("chi must be a power of two")
    data_bits = max(1, (shape.levels[0].size - 1).bit_length())
    functions = "\n".join(
        _access_level(index, shape) for index in range(len(shape.levels))
    )
    return f'''# Generated bounded read-only recursive ORAM access (EXPERIMENTAL).
from Compiler.library import print_ln_to
from Compiler.types import Array, Matrix, sint

program.use_edabit(True)
program.timeout = None

SERVER_COUNT = 3
LEVEL_COUNT = {len(shape.levels)}
DATA_SIZE = {shape.levels[0].size}
DATA_INDEX_BITS = {data_bits}
DATA_VALUE_WIDTH = {shape.value_width}
CHI = {shape.chi}
BASE_ENTRIES = {shape.base_entries}
MAX_ACCESSES = {shape.max_accesses}
{_level_constants(shape)}

def shared_array(length):
    result = Array(length, sint)
    result.input_from(0)
    for player in (1, 2):
        incoming = Array(length, sint)
        incoming.input_from(player)
        result.assign_vector(result[:] + incoming[:])
        incoming.delete()
    return result

def emit_output_share(access_number, field, value):
    share_0 = sint.get_random()
    share_1 = sint.get_random()
    share_2 = value - share_0 - share_1
    print_ln_to(0, 'ORAM_ACCESS_SHARE %s %s 0 %s', access_number, field, share_0.reveal_to(0))
    print_ln_to(1, 'ORAM_ACCESS_SHARE %s %s 1 %s', access_number, field, share_1.reveal_to(1))
    print_ln_to(2, 'ORAM_ACCESS_SHARE %s %s 2 %s', access_number, field, share_2.reveal_to(2))

{_storage(shape)}
{_stash_storage(shape)}

{functions}

{_access_body(shape)}
'''


def write_program(home: str | Path, shape: OramAccessShape) -> tuple[str, Path]:
    name = program_name(shape)
    destination = Path(home) / "Programs" / "Source" / f"{name}.mpc"
    destination.write_text(render_program(shape), encoding="utf-8")
    return name, destination
