"""Generated MPC for relation-directory ORAM plus relation-page ORAM.

The owner-input order is exactly the contract in
``relation_paged_oram_shares.py``: for each owner, directory stack then page
stack, followed by the client's query shares after all owners.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .oram_access import OramAccessShape, OramLevelShape
from .oram_layout import secure_tree_shape
from .packed import packed_edge_bits, packing_widths
from .relation_paged_oram_epoch import dual_access_counts
from .relation_paged_oram_shares import RelationPagedOramShape
from .relation_pages import RelationPageConfig


PROGRAM_VERSION = 2
MAX_QUERY_COUNT = 10


def _planned_stack(
    *,
    logical_records: int,
    value_width: int,
    max_accesses: int,
    chi: int,
    base_threshold: int,
    statistical_security_bits: int,
) -> OramAccessShape:
    current = logical_records
    levels: list[OramLevelShape] = []
    level_index = 0
    while True:
        bucket, depth = secure_tree_shape(
            current, statistical_security_bits=statistical_security_bits
        )
        width = value_width if level_index == 0 else chi
        levels.append(OramLevelShape(
            size=current,
            bucket_size=bucket,
            depth=depth,
            slots=(2 ** (depth + 1)) * bucket,
            field_count=3 + width,
        ))
        # Mirror build_owner_oram_stack: a next level of ceil(current/chi)==1
        # carries no hidden address and is represented by this secret base.
        if current <= base_threshold or current <= chi:
            break
        current = -(-current // chi)
        level_index += 1
    return OramAccessShape(
        levels=tuple(levels),
        base_entries=current,
        chi=chi,
        value_width=value_width,
        max_accesses=max_accesses,
    )


def planned_shape(
    config: RelationPageConfig,
    query_count: int,
    *,
    chi: int = 256,
    base_threshold: int = 64,
    statistical_security_bits: int = 80,
) -> RelationPagedOramShape:
    if config.uses_hybrid_directory or config.pages.uses_compact_directory:
        raise ValueError("dual-ORAM circuit currently requires a dense directory")
    if chi < 2 or chi & (chi - 1):
        raise ValueError("chi must be a power of two")
    directory_accesses, page_accesses = dual_access_counts(config, query_count)
    options = {
        "chi": chi,
        "base_threshold": base_threshold,
        "statistical_security_bits": statistical_security_bits,
    }
    return RelationPagedOramShape(
        directory=_planned_stack(
            logical_records=config.directory_rows,
            value_width=1,
            max_accesses=directory_accesses,
            **options,
        ),
        pages=_planned_stack(
            logical_records=config.pages.pool_rows,
            value_width=config.pages.page_size,
            max_accesses=page_accesses,
            **options,
        ),
    )


def program_name(
    config: RelationPageConfig,
    shape: RelationPagedOramShape,
    query_count: int,
) -> str:
    material = repr((PROGRAM_VERSION, config.digest, shape, query_count)).encode("ascii")
    return "relation_paged_recursive_oram_3pc_" + hashlib.sha256(material).hexdigest()[:16]


def _constants(prefix: str, shape: OramAccessShape) -> str:
    lines = []
    for index, level in enumerate(shape.levels):
        lines.extend((
            f"{prefix}_LEVEL_{index}_SIZE = {level.size}",
            f"{prefix}_LEVEL_{index}_BUCKET_SIZE = {level.bucket_size}",
            f"{prefix}_LEVEL_{index}_DEPTH = {level.depth}",
            f"{prefix}_LEVEL_{index}_SLOTS = {level.slots}",
            f"{prefix}_LEVEL_{index}_FIELDS = {level.field_count}",
        ))
    return "\n".join(lines)


def _allocate_owner(owner: int, kind: str, prefix: str, shape: OramAccessShape) -> str:
    lines = [f"owner_{owner}_{kind}_levels = []"]
    for level_index, _ in enumerate(shape.levels):
        lines.extend((
            f"owner_{owner}_{kind}_level_{level_index} = shared_array("
            f"{prefix}_LEVEL_{level_index}_SLOTS * {prefix}_LEVEL_{level_index}_FIELDS)",
            f"owner_{owner}_{kind}_levels.append(owner_{owner}_{kind}_level_{level_index})",
        ))
    lines.extend((
        f"{kind}_orams.append(owner_{owner}_{kind}_levels)",
        f"{kind}_position_bases.append(shared_array({prefix}_BASE_ENTRIES))",
    ))
    return "\n".join(lines)


def _storage(owner_count: int, shape: RelationPagedOramShape) -> str:
    lines = [
        "directory_orams = []", "directory_position_bases = []",
        "page_orams = []", "page_position_bases = []",
    ]
    # This owner-major order is security-critical input framing.
    for owner in range(owner_count):
        lines.append(_allocate_owner(owner, "directory", "DIRECTORY", shape.directory))
        lines.append(_allocate_owner(owner, "page", "PAGE", shape.pages))
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


def _stashes(owner_count: int, kind: str, shape: OramAccessShape) -> str:
    upper = kind.upper()
    lines = [
        f"{kind}_stash_valids = []", f"{kind}_stash_indices = []",
        f"{kind}_stash_values = []",
    ]
    for owner in range(owner_count):
        lines.extend((
            f"owner_{owner}_{kind}_stash_valids = []",
            f"owner_{owner}_{kind}_stash_indices = []",
            f"owner_{owner}_{kind}_stash_values = []",
        ))
        for level in shape.levels:
            width = level.field_count - 3
            lines.extend((
                f"sv = Array({upper}_MAX_ACCESSES, sint); sv.assign_all(0)",
                f"si = Array({upper}_MAX_ACCESSES, sint); si.assign_all(0)",
                f"sx = Matrix({upper}_MAX_ACCESSES, {width}, sint); sx.assign_all(0)",
                f"owner_{owner}_{kind}_stash_valids.append(sv)",
                f"owner_{owner}_{kind}_stash_indices.append(si)",
                f"owner_{owner}_{kind}_stash_values.append(sx)",
            ))
        lines.extend((
            f"{kind}_stash_valids.append(owner_{owner}_{kind}_stash_valids)",
            f"{kind}_stash_indices.append(owner_{owner}_{kind}_stash_indices)",
            f"{kind}_stash_values.append(owner_{owner}_{kind}_stash_values)",
        ))
    return "\n".join(lines)


def _reader(owner: int, kind: str, prefix: str, shape: OramAccessShape) -> str:
    top = len(shape.levels) - 1
    chi_bits = shape.chi.bit_length() - 1
    lines = [
        f"def read_owner_{owner}_{kind}(original, access_number):",
        f"    address_ok = (original >= 0) * (original < {prefix}_LOGICAL_RECORDS)",
        "    address = address_ok.if_else(original, sint(0))",
        f"    address_bits = address.bit_decompose({prefix}_INDEX_BITS)",
        f"    top_index = sint.bit_compose(address_bits[{top * chi_bits}:])",
        "    leaf = sint(0)",
        f"    for base_index in range({prefix}_BASE_ENTRIES):",
        f"        leaf += (top_index == base_index) * {kind}_position_bases[{owner}][base_index]",
        "    chain_valid = address_ok",
    ]
    for level_index in range(top, -1, -1):
        shift = level_index * chi_bits
        width = shape.levels[level_index].field_count - 3
        lines.extend((
            f"    level_index = sint.bit_compose(address_bits[{shift}:])",
            "    value, found = read_oram_level(",
            f"        {kind}_orams[{owner}][{level_index}],",
            f"        {kind}_stash_valids[{owner}][{level_index}],",
            f"        {kind}_stash_indices[{owner}][{level_index}],",
            f"        {kind}_stash_values[{owner}][{level_index}],",
            f"        level_index, leaf, access_number, {prefix}_LEVEL_{level_index}_DEPTH,",
            f"        {prefix}_LEVEL_{level_index}_BUCKET_SIZE, {width}, {prefix}_MAX_ACCESSES)",
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


def _dispatch(
    owner_count: int,
    *,
    kind: str,
    arguments: str,
    targets: str,
    indent: str,
) -> str:
    lines: list[str] = []
    for owner in range(owner_count):
        keyword = "if" if owner == 0 else "elif"
        lines.extend((
            f"{indent}{keyword} owner == {owner}:",
            f"{indent}    {targets} = read_owner_{owner}_{kind}({arguments})",
        ))
    lines.extend((
        f"{indent}else:",
        f"{indent}    raise CompilerError('invalid public owner index')",
    ))
    return "\n".join(lines)


def render_program(
    config: RelationPageConfig,
    shape: RelationPagedOramShape,
    query_count: int,
) -> str:
    if not 1 <= query_count <= MAX_QUERY_COUNT:
        raise ValueError(f"query_count must be in [1, {MAX_QUERY_COUNT}]")
    expected_directory_accesses, expected_page_accesses = dual_access_counts(
        config, query_count
    )
    if shape.directory.max_accesses != expected_directory_accesses:
        raise ValueError("directory access budget does not match query schedule")
    if shape.pages.max_accesses != expected_page_accesses:
        raise ValueError("page access budget does not match query schedule")
    if shape.directory.value_width != 1:
        raise ValueError("directory ORAM payload must be one descriptor")
    if shape.pages.value_width != config.pages.page_size:
        raise ValueError("page ORAM payload does not match page_size")
    if shape.directory.chi != shape.pages.chi:
        raise ValueError("both recursive stacks must use the same chi")

    owner_count = len(config.base.owners)
    frontier = config.pages.frontier_slots(owner_count)
    second_width = owner_count * config.pages.slots_per_key
    candidates = frontier * second_width
    if config.base.top_k > candidates:
        raise ValueError("top_k exceeds dual-ORAM candidate capacity")
    slot_bits, relation_bits, evidence_bits, score_bits, _ = packing_widths(config.base)
    readers = "\n\n".join(
        _reader(owner, kind, prefix, selected)
        for owner in range(owner_count)
        for kind, prefix, selected in (
            ("directory", "DIRECTORY", shape.directory),
            ("page", "PAGE", shape.pages),
        )
    )
    directory_dispatch = _dispatch(
        owner_count,
        kind="directory",
        arguments="address, directory_access",
        targets="descriptor_record, descriptor_found",
        indent="    ",
    )
    page_dispatch = _dispatch(
        owner_count,
        kind="page",
        arguments="wanted_page, page_access + page_offset",
        targets="page, page_found",
        indent="        ",
    )
    return f'''# Generated relation-paged recursive-ORAM KG retrieval.
from Compiler.library import print_ln_to
from Compiler.types import Array, Matrix, sint
from Compiler.exceptions import CompilerError

program.use_edabit(True)
program.timeout = None

OWNER_COUNT = {owner_count}
QUERY_COUNT = {query_count}
ENTITY_COUNT = {config.base.entity_count}
RELATION_COUNT = {config.relation_count}
DIRECTORY_LOGICAL_RECORDS = {config.directory_rows}
PAGE_LOGICAL_RECORDS = {config.pages.pool_rows}
DIRECTORY_INDEX_BITS = {max(1, (config.directory_rows - 1).bit_length())}
PAGE_INDEX_BITS = {max(1, (config.pages.pool_rows - 1).bit_length())}
DIRECTORY_BASE_ENTRIES = {shape.directory.base_entries}
PAGE_BASE_ENTRIES = {shape.pages.base_entries}
DIRECTORY_MAX_ACCESSES = {shape.directory.max_accesses}
PAGE_MAX_ACCESSES = {shape.pages.max_accesses}
CHI = {shape.directory.chi}
PAGE_SIZE = {config.pages.page_size}
PAGES_PER_KEY = {config.pages.pages_per_key}
PAGE_BASE_BITS = {config.pages.page_base_bits}
PAGE_COUNT_BITS = {config.pages.page_count_bits}
DESCRIPTOR_BITS = {config.pages.descriptor_bits}
SLOTS_PER_KEY = {config.pages.slots_per_key}
GLOBAL_FRONTIER = {frontier}
SECOND_WIDTH = {second_width}
CANDIDATE_COUNT = {candidates}
TOP_K = {config.base.top_k}
DEDUPLICATE = {int(config.base.deduplicate_terminal_answers)}
PACKED_EDGE_BITS = {packed_edge_bits(config.base)}
SLOT_BITS = {slot_bits}
RELATION_BITS = {relation_bits}
EVIDENCE_BITS = {evidence_bits}
SCORE_BITS = {score_bits}
{_constants("DIRECTORY", shape.directory)}
{_constants("PAGE", shape.pages)}

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
                    wanted, real_leaf, access_number, depth, bucket_size,
                    width, max_accesses):
    if access_number < 0 or access_number >= max_accesses:
        raise CompilerError('public ORAM access number exceeds its epoch budget')
    hit = sint(0); cached = Array(width, sint); cached.assign_all(0)
    # access_number is a compile-time public schedule value. Future slots are
    # known empty, so touching them adds compiler work but no privacy. Scan only
    # prior public slots; which secret logical index matches remains hidden.
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
    # The destination is public and unique to this scheduled access. A repeated
    # secret address leaves this slot invalid; a first read caches its payload.
    stash_valid[access_number] = write
    stash_index[access_number] = write * wanted
    stash_value[access_number].assign_vector(write * fetched[:])
    return result, hit.if_else(sint(1), found)

def emit(query, rank, field, value):
    s0 = sint.get_random(); s1 = sint.get_random(); s2 = value - s0 - s1
    print_ln_to(0, 'DORAM_BATCH_SHARE %s %s %s 0 %s', query, rank, field, s0.reveal_to(0))
    print_ln_to(1, 'DORAM_BATCH_SHARE %s %s %s 1 %s', query, rank, field, s1.reveal_to(1))
    print_ln_to(2, 'DORAM_BATCH_SHARE %s %s %s 2 %s', query, rank, field, s2.reveal_to(2))

{_storage(owner_count, shape)}
{_stashes(owner_count, "directory", shape.directory)}
{_stashes(owner_count, "page", shape.pages)}

{readers}

def read_relation_key(owner, entity, relation, directory_access, page_access):
    key_ok = (entity != 0) * (entity < ENTITY_COUNT) * (relation != 0) * (relation <= RELATION_COUNT)
    address = key_ok.if_else(entity * RELATION_COUNT + relation - 1, sint(0))
{directory_dispatch}
    descriptor_bits = descriptor_record[0].bit_decompose(DESCRIPTOR_BITS)
    page_base = sint.bit_compose(descriptor_bits[:PAGE_BASE_BITS])
    page_count = sint.bit_compose(descriptor_bits[PAGE_BASE_BITS:])
    result = Array(SLOTS_PER_KEY, sint); result.assign_all(0)
    for page_offset in range(PAGES_PER_KEY):
        active = key_ok * descriptor_found * (page_count > page_offset)
        wanted_page = active.if_else(page_base + page_offset, sint(0))
{page_dispatch}
        result.assign_part_vector(
            active * page_found * page[:], page_offset * PAGE_SIZE
        )
    return result

directory_access = [0] * OWNER_COUNT
page_access = [0] * OWNER_COUNT
hop1_targets = Array(QUERY_COUNT * SECOND_WIDTH, sint)
hop1_handles = Array(QUERY_COUNT * SECOND_WIDTH, sint)
hop1_scores = Array(QUERY_COUNT * SECOND_WIDTH, sint)
hop1_valid = Array(QUERY_COUNT * SECOND_WIDTH, sint)
for query in range(QUERY_COUNT):
    source, relation1 = queries[query][0], queries[query][1]
    for owner in range(OWNER_COUNT):
        record = read_relation_key(owner, source, relation1, directory_access[owner], page_access[owner])
        directory_access[owner] += 1; page_access[owner] += PAGES_PER_KEY
        for slot in range(SLOTS_PER_KEY):
            target, stored_relation, handle, score, stored = unpack_edge(record[slot])
            flat = query * SECOND_WIDTH + owner * SLOTS_PER_KEY + slot
            valid = stored * (target != 0) * (target < ENTITY_COUNT)
            hop1_valid[flat] = valid; hop1_targets[flat] = valid * target
            hop1_handles[flat] = valid * handle; hop1_scores[flat] = valid * score

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
    for frontier in range(GLOBAL_FRONTIER):
        first = query * GLOBAL_FRONTIER + frontier
        middle = frontier_valid[first] * frontier_targets[first]
        for owner in range(OWNER_COUNT):
            record = read_relation_key(owner, middle, relation2, directory_access[owner], page_access[owner])
            directory_access[owner] += 1; page_access[owner] += PAGES_PER_KEY
            for slot in range(SLOTS_PER_KEY):
                target, stored_relation, handle, score, stored = unpack_edge(record[slot])
                local = owner * SLOTS_PER_KEY + slot
                flat = (query * GLOBAL_FRONTIER + frontier) * SECOND_WIDTH + local
                valid = frontier_valid[first] * stored * (target != 0) * (target < ENTITY_COUNT)
                hop2_valid[flat] = valid; hop2_targets[flat] = valid * target
                hop2_handles[flat] = valid * handle; hop2_scores[flat] = valid * score

for owner in range(OWNER_COUNT):
    if directory_access[owner] != DIRECTORY_MAX_ACCESSES:
        raise CompilerError('directory ORAM access schedule mismatch')
    if page_access[owner] != PAGE_MAX_ACCESSES:
        raise CompilerError('page ORAM access schedule mismatch')

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


def write_program(
    config: RelationPageConfig,
    shape: RelationPagedOramShape,
    query_count: int,
    output: str | Path,
) -> Path:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        render_program(config, shape, query_count), encoding="utf-8"
    )
    return destination
