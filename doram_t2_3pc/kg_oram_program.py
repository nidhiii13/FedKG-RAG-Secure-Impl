"""Generated end-to-end two-hop KG retrieval over owner-built read-only ORAMs.

Every owner has an independently randomized ORAM over the same public dense
``(entity, relation)`` keyspace.  Records contain fixed-width packed adjacency
slots.  Both the first lookup and every dependent second lookup traverse the
recursive position map inside MPC; only uniformly distributed path labels are
opened.  The secret first-hop target is used directly in the affine second-hop
address and is never reconstructed.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .kg_oram import OwnerKgOram
from .oram_access import OramAccessShape
from .oram_access import OramLevelShape
from .oram_layout import secure_tree_shape
from .packed import packed_edge_bits, packing_widths
from .relation_pages import RelationPageConfig


KG_ORAM_PROGRAM_VERSION = 3
MAX_QUERY_COUNT = 10


def planned_shape(
    config: RelationPageConfig,
    query_count: int,
    *,
    chi: int = 256,
    base_threshold: int = 64,
    statistical_security_bits: int = 80,
) -> OramAccessShape:
    """Derive the public KG-ORAM shape without constructing private records."""

    if chi < 2 or chi & (chi - 1):
        raise ValueError("chi must be a power of two")
    logical = config.base.entity_count * config.relation_count
    current = logical
    levels: list[OramLevelShape] = []
    level_index = 0
    while True:
        bucket, depth = secure_tree_shape(
            current, statistical_security_bits=statistical_security_bits
        )
        value_width = config.pages.slots_per_key if level_index == 0 else chi
        levels.append(OramLevelShape(
            size=current,
            bucket_size=bucket,
            depth=depth,
            slots=(2 ** (depth + 1)) * bucket,
            field_count=3 + value_width,
        ))
        if current <= base_threshold or current <= chi:
            break
        current = -(-current // chi)
        level_index += 1
    return OramAccessShape(
        levels=tuple(levels),
        base_entries=current,
        chi=chi,
        value_width=config.pages.slots_per_key,
        max_accesses=access_count_per_owner(config, query_count),
    )


def cost_report(config: RelationPageConfig, query_count: int, **shape_options: int) -> dict[str, object]:
    shape = planned_shape(config, query_count, **shape_options)
    path_entries = sum(
        (level.depth + 1) * level.bucket_size for level in shape.levels
    ) + shape.base_entries
    owner_count = len(config.base.owners)
    logical = config.base.entity_count * config.relation_count
    return {
        "logical_records_per_owner": logical,
        "owners": owner_count,
        "query_count": query_count,
        "accesses_per_owner": shape.max_accesses,
        "recursive_levels": len(shape.levels),
        "base_entries": shape.base_entries,
        "shared_field_values_per_owner": shape.owner_values,
        "shared_field_values_per_server_all_owners": shape.owner_values * owner_count,
        "path_entries_per_logical_access": path_entries,
        "path_entries_all_accesses": path_entries * shape.max_accesses * owner_count,
        "linear_entries_equivalent_accesses": logical * shape.max_accesses * owner_count,
        "entry_touch_reduction": round(logical / path_entries, 2),
        "statistical_security_bits": shape_options.get("statistical_security_bits", 80),
        "setup_is_linear": True,
        "online_access_is_sublinear": True,
    }


def access_count_per_owner(config: RelationPageConfig, query_count: int) -> int:
    frontier = config.pages.frontier_slots(len(config.base.owners))
    return query_count * (1 + frontier)


def common_shape(
    config: RelationPageConfig,
    owners: list[OwnerKgOram],
    query_count: int,
) -> OramAccessShape:
    if [owner.owner for owner in owners] != list(config.base.owners):
        raise ValueError("KG ORAM owners must appear exactly in public config order")
    maximum = access_count_per_owner(config, query_count)
    shapes = [OramAccessShape.from_stack(owner.stack, max_accesses=maximum) for owner in owners]
    if not shapes or any(shape != shapes[0] for shape in shapes[1:]):
        raise ValueError("every owner KG ORAM must have the same public shape")
    if shapes[0].value_width != config.pages.slots_per_key:
        raise ValueError("KG ORAM record width does not match slots_per_key")
    return shapes[0]


def program_name(config: RelationPageConfig, shape: OramAccessShape, query_count: int) -> str:
    material = repr((KG_ORAM_PROGRAM_VERSION, config.digest, shape, query_count)).encode("ascii")
    return "kg_readonly_oram_3pc_" + hashlib.sha256(material).hexdigest()[:16]


def _constants(shape: OramAccessShape) -> str:
    lines: list[str] = []
    for index, level in enumerate(shape.levels):
        lines.extend((
            f"LEVEL_{index}_SIZE = {level.size}",
            f"LEVEL_{index}_BUCKET_SIZE = {level.bucket_size}",
            f"LEVEL_{index}_DEPTH = {level.depth}",
            f"LEVEL_{index}_SLOTS = {level.slots}",
            f"LEVEL_{index}_FIELDS = {level.field_count}",
        ))
    return "\n".join(lines)


def _storage(config: RelationPageConfig, shape: OramAccessShape) -> str:
    lines: list[str] = ["orams = []", "position_bases = []"]
    for owner in range(len(config.base.owners)):
        lines.append(f"owner_{owner}_levels = []")
        for level_index, level in enumerate(shape.levels):
            lines.append(
                f"owner_{owner}_level_{level_index} = "
                f"shared_array(LEVEL_{level_index}_SLOTS * LEVEL_{level_index}_FIELDS)"
            )
            lines.append(f"owner_{owner}_levels.append(owner_{owner}_level_{level_index})")
        lines.append(f"orams.append(owner_{owner}_levels)")
        lines.append(f"position_bases.append(shared_array(BASE_ENTRIES))")
    lines.extend((
        "queries = Matrix(QUERY_COUNT, 3, sint)",
        "queries.input_from(0)",
        "for player in (1, 2):",
        "    incoming_queries = Matrix(QUERY_COUNT, 3, sint)",
        "    incoming_queries.input_from(player)",
        "    queries.assign_vector(queries[:] + incoming_queries[:])",
        "    incoming_queries.delete()",
    ))
    return "\n".join(lines)


def _stashes(config: RelationPageConfig, shape: OramAccessShape) -> str:
    lines = ["stash_valids = []", "stash_indices = []", "stash_values = []"]
    for owner in range(len(config.base.owners)):
        lines.extend((f"owner_{owner}_stash_valids = []", f"owner_{owner}_stash_indices = []", f"owner_{owner}_stash_values = []"))
        for level_index, level in enumerate(shape.levels):
            width = level.field_count - 3
            lines.extend((
                f"sv = Array(MAX_ACCESSES_PER_OWNER, sint); sv.assign_all(0)",
                f"si = Array(MAX_ACCESSES_PER_OWNER, sint); si.assign_all(0)",
                f"sx = Matrix(MAX_ACCESSES_PER_OWNER, {width}, sint); sx.assign_all(0)",
                f"owner_{owner}_stash_valids.append(sv)",
                f"owner_{owner}_stash_indices.append(si)",
                f"owner_{owner}_stash_values.append(sx)",
            ))
        lines.extend((
            f"stash_valids.append(owner_{owner}_stash_valids)",
            f"stash_indices.append(owner_{owner}_stash_indices)",
            f"stash_values.append(owner_{owner}_stash_values)",
        ))
    return "\n".join(lines)


def _owner_reader(owner: int, shape: OramAccessShape) -> str:
    top = len(shape.levels) - 1
    chi_bits = shape.chi.bit_length() - 1
    lines = [
        f"def read_owner_{owner}(original, access_number):",
        "    address_ok = (original >= 0) * (original < LOGICAL_RECORDS)",
        "    address = address_ok.if_else(original, sint(0))",
        "    address_bits = address.bit_decompose(RECORD_INDEX_BITS)",
        f"    top_index = sint.bit_compose(address_bits[{top * chi_bits}:])",
        "    leaf = sint(0)",
        "    for base_index in range(BASE_ENTRIES):",
        f"        leaf += (top_index == base_index) * position_bases[{owner}][base_index]",
        "    chain_valid = address_ok",
    ]
    for level_index in range(top, -1, -1):
        shift = level_index * chi_bits
        width = shape.levels[level_index].field_count - 3
        lines.extend((
            f"    level_index = sint.bit_compose(address_bits[{shift}:])",
            "    value, found = read_oram_level(",
            f"        orams[{owner}][{level_index}], stash_valids[{owner}][{level_index}],",
            f"        stash_indices[{owner}][{level_index}], stash_values[{owner}][{level_index}],",
            f"        level_index, leaf, access_number, LEVEL_{level_index}_DEPTH,",
            f"        LEVEL_{level_index}_BUCKET_SIZE, {width}",
            "    )",
            "    chain_valid *= found",
        ))
        if level_index:
            child_shift = (level_index - 1) * chi_bits
            lines.extend((
                f"    child_offset = sint.bit_compose(address_bits[{child_shift}:{child_shift + chi_bits}])",
                "    leaf = sint(0)",
                "    for child in range(CHI):",
                "        leaf += (child_offset == child) * value[child]",
            ))
    lines.append("    return value, chain_valid")
    return "\n".join(lines)


def _read_dispatch(config: RelationPageConfig) -> str:
    lines = ["def read_owner(owner, address, access_number):"]
    for owner in range(len(config.base.owners)):
        prefix = "if" if owner == 0 else "elif"
        lines.extend((f"    {prefix} owner == {owner}:", f"        return read_owner_{owner}(address, access_number)"))
    lines.append("    raise CompilerError('invalid public owner index')")
    return "\n".join(lines)


def render_program(config: RelationPageConfig, shape: OramAccessShape, query_count: int) -> str:
    if not 1 <= query_count <= MAX_QUERY_COUNT:
        raise ValueError(f"query_count must be in [1, {MAX_QUERY_COUNT}]")
    owner_count = len(config.base.owners)
    params = config.pages
    frontier = params.frontier_slots(owner_count)
    second_width = owner_count * params.slots_per_key
    candidates = frontier * second_width
    if config.base.top_k > candidates:
        raise ValueError("top_k exceeds KG ORAM candidate capacity")
    if shape.max_accesses != access_count_per_owner(config, query_count):
        raise ValueError("ORAM epoch access bound does not match circuit shape")
    slot_bits, relation_bits, evidence_bits, score_bits, _ = packing_widths(config.base)
    readers = "\n\n".join(_owner_reader(owner, shape) for owner in range(owner_count))
    return f'''# Generated end-to-end federated KG retrieval over recursive read-only ORAMs.
from Compiler.library import print_ln_to
from Compiler.types import Array, Matrix, regint, sint
from Compiler.exceptions import CompilerError

program.use_edabit(True)
program.timeout = None

SERVER_COUNT = 3
OWNER_COUNT = {owner_count}
QUERY_COUNT = {query_count}
ENTITY_COUNT = {config.base.entity_count}
RELATION_COUNT = {config.relation_count}
LOGICAL_RECORDS = {config.base.entity_count * config.relation_count}
RECORD_INDEX_BITS = {max(1, (config.base.entity_count * config.relation_count - 1).bit_length())}
SLOTS_PER_KEY = {params.slots_per_key}
GLOBAL_FRONTIER = {frontier}
SECOND_WIDTH = {second_width}
CANDIDATE_COUNT = {candidates}
TOP_K = {config.base.top_k}
DEDUPLICATE = {int(config.base.deduplicate_terminal_answers)}
CHI = {shape.chi}
BASE_ENTRIES = {shape.base_entries}
MAX_ACCESSES_PER_OWNER = {shape.max_accesses}
PACKED_EDGE_BITS = {packed_edge_bits(config.base)}
SLOT_BITS = {slot_bits}
RELATION_BITS = {relation_bits}
EVIDENCE_BITS = {evidence_bits}
SCORE_BITS = {score_bits}
{_constants(shape)}

def shared_array(length):
    result = Array(length, sint); result.input_from(0)
    for player in (1, 2):
        incoming = Array(length, sint); incoming.input_from(player)
        result.assign_vector(result[:] + incoming[:]); incoming.delete()
    return result

def unpack_edge(packed):
    bits = packed.bit_decompose(PACKED_EDGE_BITS)
    target = sint.bit_compose(bits[:SLOT_BITS])
    relation_start = SLOT_BITS
    relation = sint.bit_compose(bits[relation_start:relation_start + RELATION_BITS])
    evidence_start = relation_start + RELATION_BITS
    evidence = sint.bit_compose(bits[evidence_start:evidence_start + EVIDENCE_BITS])
    score_start = evidence_start + EVIDENCE_BITS
    score = sint.bit_compose(bits[score_start:score_start + SCORE_BITS])
    return target, relation, evidence, score, bits[PACKED_EDGE_BITS - 1]

def read_oram_level(tree, stash_valid, stash_index, stash_value,
                    wanted, real_leaf, access_number, depth, bucket_size, width):
    if access_number < 0 or access_number >= MAX_ACCESSES_PER_OWNER:
        raise CompilerError('public ORAM access number exceeds its epoch budget')
    hit = sint(0); cached = Array(width, sint); cached.assign_all(0)
    # access_number is public and fixed by the generated schedule. Future stash
    # slots are known empty, so skipping them cannot reveal the secret address.
    for slot in range(access_number):
        same = stash_valid[slot] * (stash_index[slot] == wanted)
        take = same * (sint(1) - hit); hit += take
        cached.assign_vector(cached[:] + take * stash_value[slot][:])
    dummy = sint.get_random_int(depth)
    opened = hit.if_else(dummy, real_leaf).reveal().to_regint(n_bits=max(1, depth))
    bucket = opened + 2 ** depth
    fetched = Array(width, sint); fetched.assign_all(0); found = sint(0)
    for path_offset in range(depth + 1):
        for offset in range(bucket_size):
            physical = bucket * bucket_size + offset
            base = physical * (width + 3)
            match = (sint(1) - tree[base]) * (tree[base + 1] == wanted)
            take = match * (sint(1) - found); found += take
            fetched.assign_vector(fetched[:] + take * tree.get_vector(base + 3, width))
        bucket = bucket // 2
    result = Array(width, sint)
    result.assign_vector(hit.if_else(cached[:], fetched[:]))
    write = sint(1) - hit
    stash_valid[access_number] = write
    stash_index[access_number] = write * wanted
    stash_value[access_number].assign_vector(write * fetched[:])
    return result, hit.if_else(sint(1), found)

def emit(query, rank, field, value):
    s0 = sint.get_random(); s1 = sint.get_random(); s2 = value - s0 - s1
    print_ln_to(0, 'DORAM_BATCH_SHARE %s %s %s 0 %s', query, rank, field, s0.reveal_to(0))
    print_ln_to(1, 'DORAM_BATCH_SHARE %s %s %s 1 %s', query, rank, field, s1.reveal_to(1))
    print_ln_to(2, 'DORAM_BATCH_SHARE %s %s %s 2 %s', query, rank, field, s2.reveal_to(2))

{_storage(config, shape)}
{_stashes(config, shape)}

{readers}

{_read_dispatch(config)}

owner_access = [0] * OWNER_COUNT
hop1_targets = Array(QUERY_COUNT * SECOND_WIDTH, sint)
hop1_handles = Array(QUERY_COUNT * SECOND_WIDTH, sint)
hop1_scores = Array(QUERY_COUNT * SECOND_WIDTH, sint)
hop1_valid = Array(QUERY_COUNT * SECOND_WIDTH, sint)
for query in range(QUERY_COUNT):
    source, relation1, relation2 = queries[query][0], queries[query][1], queries[query][2]
    query_ok = (source != 0) * (source < ENTITY_COUNT) * (relation1 != 0) * (relation1 <= RELATION_COUNT)
    address = query_ok.if_else(source * RELATION_COUNT + relation1 - 1, sint(0))
    for owner in range(OWNER_COUNT):
        record, found = read_owner(owner, address, owner_access[owner]); owner_access[owner] += 1
        for slot in range(SLOTS_PER_KEY):
            target, stored_relation, handle, score, stored = unpack_edge(record[slot])
            flat = query * SECOND_WIDTH + owner * SLOTS_PER_KEY + slot
            valid = query_ok * found * stored * (target != 0) * (target < ENTITY_COUNT)
            hop1_valid[flat] = valid; hop1_targets[flat] = valid * target
            hop1_handles[flat] = valid * handle; hop1_scores[flat] = valid * score

# Stable global compaction hides which owner supplied each frontier entry.
frontier_targets = Array(QUERY_COUNT * GLOBAL_FRONTIER, sint)
frontier_handles = Array(QUERY_COUNT * GLOBAL_FRONTIER, sint)
frontier_scores = Array(QUERY_COUNT * GLOBAL_FRONTIER, sint)
frontier_valid = Array(QUERY_COUNT * GLOBAL_FRONTIER, sint)
for query in range(QUERY_COUNT):
    used = Array(SECOND_WIDTH, sint); used.assign_all(0)
    for output in range(GLOBAL_FRONTIER):
        got = sint(0); target = sint(0); handle = sint(0); score = sint(0)
        for slot in range(SECOND_WIDTH):
            flat = query * SECOND_WIDTH + slot
            take = hop1_valid[flat] * (sint(1) - used[slot]) * (sint(1) - got)
            got += take; used[slot] += take
            target += take * hop1_targets[flat]; handle += take * hop1_handles[flat]
            score += take * hop1_scores[flat]
        flat = query * GLOBAL_FRONTIER + output
        frontier_valid[flat] = got; frontier_targets[flat] = target
        frontier_handles[flat] = handle; frontier_scores[flat] = score

hop2_targets = Array(QUERY_COUNT * GLOBAL_FRONTIER * SECOND_WIDTH, sint)
hop2_handles = Array(QUERY_COUNT * GLOBAL_FRONTIER * SECOND_WIDTH, sint)
hop2_scores = Array(QUERY_COUNT * GLOBAL_FRONTIER * SECOND_WIDTH, sint)
hop2_valid = Array(QUERY_COUNT * GLOBAL_FRONTIER * SECOND_WIDTH, sint)
for query in range(QUERY_COUNT):
    relation2 = queries[query][2]
    relation_ok = (relation2 != 0) * (relation2 <= RELATION_COUNT)
    for frontier in range(GLOBAL_FRONTIER):
        first = query * GLOBAL_FRONTIER + frontier
        active = frontier_valid[first] * relation_ok
        address = active.if_else(frontier_targets[first] * RELATION_COUNT + relation2 - 1, sint(0))
        for owner in range(OWNER_COUNT):
            record, found = read_owner(owner, address, owner_access[owner]); owner_access[owner] += 1
            for slot in range(SLOTS_PER_KEY):
                target, stored_relation, handle, score, stored = unpack_edge(record[slot])
                local = owner * SLOTS_PER_KEY + slot
                flat = (query * GLOBAL_FRONTIER + frontier) * SECOND_WIDTH + local
                valid = active * found * stored * (target != 0) * (target < ENTITY_COUNT)
                hop2_valid[flat] = valid; hop2_targets[flat] = valid * target
                hop2_handles[flat] = valid * handle; hop2_scores[flat] = valid * score

for owner in range(OWNER_COUNT):
    if owner_access[owner] != MAX_ACCESSES_PER_OWNER:
        raise CompilerError('ORAM epoch access schedule mismatch')

for query in range(QUERY_COUNT):
    valid = Array(CANDIDATE_COUNT, sint); score = Array(CANDIDATE_COUNT, sint)
    left = Array(CANDIDATE_COUNT, sint); right = Array(CANDIDATE_COUNT, sint)
    terminal = Array(CANDIDATE_COUNT, sint); selected = Array(CANDIDATE_COUNT, sint); selected.assign_all(0)
    for frontier in range(GLOBAL_FRONTIER):
        first = query * GLOBAL_FRONTIER + frontier
        for local in range(SECOND_WIDTH):
            candidate = frontier * SECOND_WIDTH + local
            second = (query * GLOBAL_FRONTIER + frontier) * SECOND_WIDTH + local
            ok = frontier_valid[first] * hop2_valid[second]
            valid[candidate] = ok; score[candidate] = ok * (frontier_scores[first] + hop2_scores[second])
            left[candidate] = ok * frontier_handles[first]; right[candidate] = ok * hop2_handles[second]
            terminal[candidate] = ok * hop2_targets[second]
    for rank in range(TOP_K):
        best_valid = sint(0); best_score = sint(0); best_left = sint(0); best_right = sint(0); best_terminal = sint(0)
        became = Array(CANDIDATE_COUNT, sint)
        for candidate in range(CANDIDATE_COUNT):
            available = valid[candidate] * (sint(1) - selected[candidate])
            better = available * ((sint(1) - best_valid) + best_valid * (score[candidate] > best_score))
            best_valid = better.if_else(available, best_valid); best_score = better.if_else(score[candidate], best_score)
            best_left = better.if_else(left[candidate], best_left); best_right = better.if_else(right[candidate], best_right)
            best_terminal = better.if_else(terminal[candidate], best_terminal); became[candidate] = better
        if DEDUPLICATE:
            for candidate in range(CANDIDATE_COUNT):
                selected[candidate] += best_valid * (terminal[candidate] == best_terminal)
        else:
            later = sint(0)
            for reverse in range(CANDIDATE_COUNT):
                candidate = CANDIDATE_COUNT - 1 - reverse
                winner = became[candidate] * (sint(1) - later); selected[candidate] += winner; later += winner
        emit(query, rank, 0, best_valid); emit(query, rank, 1, best_valid * best_left)
        emit(query, rank, 2, best_valid * best_right); emit(query, rank, 3, best_valid * best_score)
'''


def write_program(config: RelationPageConfig, shape: OramAccessShape, query_count: int, output: str | Path) -> Path:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_program(config, shape, query_count), encoding="utf-8")
    return destination
