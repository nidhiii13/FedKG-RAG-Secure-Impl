"""Tests for the relation-paged secret-sharing path and MP-SPDZ circuit.

These do not execute MP-SPDZ. They pin the share/assembly contract, the exact
private-input shape the runner validates, and the circuit properties a security
claim depends on: no value is ever opened except a per-server output share, and
every address is range-checked before it indexes a table.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from doram_t2_3pc.config import PublicConfig
from doram_t2_3pc.packed import create_packed_query_batch_shards
from doram_t2_3pc.page_program import (
    MAX_BATCH_QUERIES,
    page_cost_estimate,
    program_name,
    render_program,
    write_program,
)
from doram_t2_3pc.paged_shares import (
    assemble_paged_batch_from_paths,
    assemble_paged_batch_input,
    create_paged_owner_shards,
    expected_private_input_values,
    owner_flat_vector,
    validate_private_input,
)
from doram_t2_3pc.relation_pages import RelationPageConfig
from doram_t2_3pc.sharing import reconstruct


FIXTURE = Path("doram_t2_3pc/examples/ten_query")


@pytest.fixture
def config() -> RelationPageConfig:
    return RelationPageConfig.load(FIXTURE / "config_relation_pages.json")


def _owner_edges() -> dict[str, list[dict]]:
    return {
        owner: json.loads((FIXTURE / f"{owner}.json").read_text())
        for owner in ("owner_a", "owner_b", "owner_c")
    }


# --------------------------------------------------------------------------
# Sharing and assembly
# --------------------------------------------------------------------------


def test_owner_shares_reconstruct_to_the_built_layout(
    tmp_path: Path, config: RelationPageConfig
):
    edges = _owner_edges()["owner_a"]
    directory, pages = owner_flat_vector(config, "owner_a", edges)
    paths = create_paged_owner_shards(config, "owner_a", FIXTURE / "owner_a.json", tmp_path)
    assert len(paths) == 3

    documents = [json.loads(path.read_text()) for path in paths]
    for index, document in enumerate(documents):
        assert document["server"] == index
        assert document["kind"] == "paged-owner-shard"
        assert document["layout_digest"] == config.digest
        assert paths[index].stat().st_mode & 0o077 == 0

    prime = config.base.field_prime
    assert [
        reconstruct(column, modulus=prime)
        for column in zip(*[document["directory"] for document in documents])
    ] == directory
    assert [
        reconstruct(column, modulus=prime)
        for column in zip(*[document["pages"] for document in documents])
    ] == pages


def test_assembled_input_matches_program_consumption_order(
    tmp_path: Path, config: RelationPageConfig
):
    owners = config.base.owners
    owner_dirs = []
    for owner in owners:
        directory = tmp_path / owner
        create_paged_owner_shards(config, owner, FIXTURE / f"{owner}.json", directory)
        owner_dirs.append(directory)
    query_dir = tmp_path / "query"
    queries = json.loads((FIXTURE / "queries.json").read_text())[:2]
    query_file = tmp_path / "queries.json"
    query_file.write_text(json.dumps(queries))
    create_packed_query_batch_shards(config.base, query_file, query_dir)

    server_values = []
    for server in range(3):
        output = tmp_path / "instance" / f"Input-P{server}-0"
        assemble_paged_batch_from_paths(
            config,
            server,
            2,
            query_dir / f"query-batch-to-server-{server}.json",
            [
                owner_dirs[index] / f"paged-owner-{index}-to-server-{server}.json"
                for index in range(len(owners))
            ],
            output,
        )
        assert output.stat().st_mode & 0o077 == 0
        server_values.append([int(line) for line in output.read_text().splitlines()])

    prime = config.base.field_prime
    combined = [
        reconstruct(column, modulus=prime) for column in zip(*server_values)
    ]
    assert len(combined) == expected_private_input_values(config, 2)

    expected = []
    for query in queries:
        expected.extend(
            (
                config.base.entities[query["source"]],
                config.base.relations[query["relation_1"]],
                config.base.relations[query["relation_2"]],
            )
        )
    layouts = {
        owner: owner_flat_vector(config, owner, _owner_edges()[owner])
        for owner in owners
    }
    # Directory rows carry one packed element per column: several owners'
    # descriptors sit in disjoint bit ranges of the same field element, summed
    # modulo the prime. Reconstructing the sum here checks both the ordering and
    # that the packing itself is the one the circuit will unpack.
    prime = config.base.field_prime
    for row in range(config.directory_rows):
        columns = [0] * config.directory_columns
        for owner_index, owner in enumerate(owners):
            column, offset = config.directory_slot(owner_index)
            columns[column] = (
                columns[column] + (layouts[owner][0][row] << offset)
            ) % prime
        expected.extend(columns)
    # Page pools are owner-major so each owner's pool is one contiguous scan.
    for owner in owners:
        expected.extend(layouts[owner][1])
    assert combined == expected


def test_assembly_rejects_wrong_server_duplicate_and_incomplete_shards(
    tmp_path: Path, config: RelationPageConfig
):
    owner_dirs = []
    for owner in config.base.owners:
        directory = tmp_path / owner
        create_paged_owner_shards(config, owner, FIXTURE / f"{owner}.json", directory)
        owner_dirs.append(directory)

    def document(owner_index: int, server: int) -> dict:
        return json.loads(
            (
                owner_dirs[owner_index]
                / f"paged-owner-{owner_index}-to-server-{server}.json"
            ).read_text()
        )

    with pytest.raises(ValueError, match="metadata mismatch"):
        assemble_paged_batch_input(
            config, 0, [], [document(0, 1)], tmp_path / "out"
        )
    with pytest.raises(ValueError, match="duplicate"):
        assemble_paged_batch_input(
            config, 0, [], [document(0, 0), document(0, 0)], tmp_path / "out"
        )
    with pytest.raises(ValueError, match="incomplete"):
        assemble_paged_batch_input(
            config, 0, [], [document(0, 0)], tmp_path / "out"
        )
    corrupted = document(0, 0)
    corrupted["pages"] = corrupted["pages"][:-1]
    with pytest.raises(ValueError, match="wrong value count"):
        assemble_paged_batch_input(
            config, 0, [], [corrupted], tmp_path / "out"
        )
    non_canonical = document(0, 0)
    non_canonical["directory"][0] = config.base.field_prime
    with pytest.raises(ValueError, match="non-canonical"):
        assemble_paged_batch_input(
            config, 0, [], [non_canonical], tmp_path / "out"
        )


def test_private_input_validation_matches_the_expected_shape(
    tmp_path: Path, config: RelationPageConfig
):
    expected = expected_private_input_values(config, 3)
    good = tmp_path / "good"
    good.write_text("0\n" * expected)
    validate_private_input(config, 3, good)

    short = tmp_path / "short"
    short.write_text("0\n" * (expected - 1))
    with pytest.raises(ValueError, match="expected"):
        validate_private_input(config, 3, short)

    bad = tmp_path / "bad"
    bad.write_text("\n".join(["0"] * (expected - 1) + ["not-an-integer"]) + "\n")
    with pytest.raises(ValueError, match="non-integer"):
        validate_private_input(config, 3, bad)

    over = tmp_path / "over"
    over.write_text(
        "\n".join(["0"] * (expected - 1) + [str(config.base.field_prime)]) + "\n"
    )
    with pytest.raises(ValueError, match="non-canonical"):
        validate_private_input(config, 3, over)


# --------------------------------------------------------------------------
# Circuit properties
# --------------------------------------------------------------------------


def test_program_name_is_bound_to_the_layout_digest(config: RelationPageConfig):
    name = program_name(config, 2)
    assert re.fullmatch(r"paged_kg_3pc_[0-9a-f]{16}", name)
    assert program_name(config, 2) == name
    assert program_name(config, 3) != name


def test_hybrid_circuit_reads_both_type_block_and_hashed_residual():
    hybrid = RelationPageConfig.load(
        FIXTURE / "config_relation_pages_hybrid.json"
    )
    source = render_program(hybrid, 1)
    assert "TYPE_COEFFICIENTS" in source
    assert "blocked_ok.if_else(address, sint(0))" in source
    assert "first_blocked = read_directory" in source
    assert "first_residual = read_compact_directory" in source
    assert "first_blocked[:] + first_residual[:]" in source
    assert "second_blocked[:] + second_residual[:]" in source
    assert source.count("reveal_to(") == 3


def test_relation_partitioned_residual_is_smaller_and_losslessly_tagged():
    from doram_t2_3pc.compact_directory import bucket_of
    from doram_t2_3pc.relation_pages import build_owner_page_layout

    old = RelationPageConfig.load(FIXTURE / "config_relation_pages_hybrid.json")
    config = RelationPageConfig.load(
        FIXTURE / "config_relation_pages_hybrid_partitioned.json"
    )
    owner_count = len(config.base.owners)
    width = owner_count * config.pages.bucket_slots
    assert config.residual_directory_rows * width == 12
    assert (
        old.residual_directory_rows * owner_count * old.pages.bucket_slots == 48
    )

    for owner_index, owner in enumerate(config.base.owners):
        edges = _owner_edges()[owner]
        layout = build_owner_page_layout(config, owner, edges)
        directory, _ = owner_flat_vector(config, owner, edges)
        residual = directory[config.directory_rows:]
        for combined_tag, descriptor in (layout.residual_descriptors or {}).items():
            dense = combined_tag - 1
            source = dense // config.relation_count
            relation = dense % config.relation_count + 1
            tag = source + 1
            row = (
                (relation - 1) * config.pages.directory_buckets
                + bucket_of(tag, config.pages.directory_buckets)
            )
            packed = residual[row * width + owner_index]
            assert packed >> config.pages.descriptor_bits == tag
            assert packed & ((1 << config.pages.descriptor_bits) - 1) == descriptor


def test_partitioned_residual_relation_is_part_of_secret_row_address():
    config = RelationPageConfig.load(
        FIXTURE / "config_relation_pages_hybrid_partitioned.json"
    )
    source = render_program(config, 10)
    assert "RESIDUAL_ROWS = 4" in source
    assert "tag = valids[address].if_else(entities[address] + 1" in source
    assert "(relations[address] - 1) * DIRECTORY_BUCKETS" in source
    assert "selectors = demux_matrix(row_bits" in source
    assert "if DIRECTORY_BUCKETS == 1:" in source
    assert "return sint(0, size=address_count)" in source
    assert source.count("reveal_to(") == 3


def test_partitioned_residual_fails_closed_on_relation_bucket_overflow():
    config = RelationPageConfig.load(
        FIXTURE / "config_relation_pages_hybrid_partitioned.json"
    )
    edges = list(_owner_edges()["owner_a"])
    edges.append(
        {
            "source": "carol",
            "relation": "treated_with",
            "target": "drug_y",
            "evidence": 123456,
            "score": 1,
        }
    )
    with pytest.raises(ValueError, match="bucket 0 overflows"):
        owner_flat_vector(config, "owner_a", edges)


def test_hybrid_hop_two_folds_primary_block_once_and_keeps_residual_lookup():
    hybrid = RelationPageConfig.load(
        FIXTURE / "config_relation_pages_hybrid.json"
    )
    source = render_program(hybrid, 2)
    assert "TYPE_BLOCK_STARTS" in source
    assert "TYPE_MAX_BLOCK" in source
    assert "def fold_type_block_directory(" in source
    assert "def read_folded_type_block(" in source
    assert "fold_type_block_directory(\n        relation_2, relation_ok" in source
    assert "read_folded_type_block(" in source
    assert "second_residual.assign_vector(read_compact_directory(" in source
    # The optimized path validates relation_2 once per query and does not invoke
    # directory_address's relation demux independently for every frontier slot.
    assert "ok, address = directory_address(frontier_targets[flat]" not in source
    assert "second_blocked = read_directory(" not in source

    ablated = render_program(hybrid, 2, ablate_folded_directory=True)
    assert "second_blocked = read_directory(" in ablated
    assert "ok, address = directory_address(frontier_targets[flat]" in ablated
    assert "second_residual = read_compact_directory(" in ablated
    assert program_name(hybrid, 2) != program_name(
        hybrid, 2, ablate_folded_directory=True
    )


def test_partitioned_residual_is_folded_once_per_query_with_exact_ablation():
    hybrid = RelationPageConfig.load(
        FIXTURE / "config_relation_pages_hybrid_partitioned.json"
    )
    source = render_program(hybrid, 2)
    assert "def fold_partitioned_residuals(" in source
    assert "def read_folded_residuals(" in source
    assert "folded_residuals = fold_partitioned_residuals(" in source
    assert "second_residual.assign_vector(read_folded_residuals(" in source
    assert "second_residual.assign_vector(read_compact_directory(" not in source
    assert source.count("reveal_to(") == 3

    ablated = render_program(hybrid, 2, ablate_folded_residual=True)
    assert "second_residual.assign_vector(read_compact_directory(" in ablated
    assert "folded_residuals = fold_partitioned_residuals(" not in ablated
    assert program_name(hybrid, 2) != program_name(
        hybrid, 2, ablate_folded_residual=True
    )


def test_hybrid_fold_uses_public_fixed_width_and_secret_range_gate():
    hybrid = RelationPageConfig.load(
        FIXTURE / "config_relation_pages_hybrid.json"
    )
    source = render_program(hybrid, 2)
    assert "folded = sint(0, size=TYPE_MAX_BLOCK * DIRECTORY_COLUMNS)" in source
    assert "padding = (TYPE_MAX_BLOCK - width) * DIRECTORY_COLUMNS" in source
    assert "in_block = (entity >= type_start) * (entity < type_start + type_width)" in source
    assert "offsets[address] = use.if_else(entity - type_start, sint(0))" in source
    # No relation, type block, entity offset, or selected descriptor is opened.
    assert source.count("reveal_to(") == 3


def test_residual_hash_and_wanted_tag_decompositions_are_batched():
    hybrid = RelationPageConfig.load(
        FIXTURE / "config_relation_pages_hybrid.json"
    )
    source = render_program(hybrid, 2)
    # One vector decomposition hashes all requested tags. The old renderer
    # called compact_bucket(tag) inside the address loop.
    assert "def compact_buckets(tags, address_count):" in source
    assert "products.assign_vector(tags[:] * HASH_MULTIPLIER)" in source
    assert "buckets.assign_vector(compact_buckets(tags, address_count))" in source
    assert "compact_bucket(tag)" not in source
    # Wanted tags are decomposed at address_count width once, then their secret
    # bits are broadcast over public bucket columns. They are not materialised
    # BUCKET_WIDTH times and decomposed again.
    assert "tag_bits = tags[:].bit_decompose(TAG_BITS)" in source
    assert "broadcast[address * BUCKET_WIDTH + column] = lanes[address]" in source
    assert "wanted.get_vector(0, total_slots).bit_decompose(TAG_BITS)" not in source
    assert source.count("reveal_to(") == 3


def test_descriptor_and_page_unpacking_are_batched_across_owners():
    hybrid = RelationPageConfig.load(
        FIXTURE / "config_relation_pages_hybrid.json"
    )
    source = render_program(hybrid, 10)
    assert "packed_bits = descriptors[:].bit_decompose(" in source
    assert "window = read_page_windows(bases, address_count)" in source
    assert "window[:].bit_decompose(PACKED_EDGE_BITS)" in source
    assert "page_bases = sint.bit_compose(" in source
    assert "edge_targets = sint.bit_compose(" in source
    assert "valid_values = Array.create_from(ok)" in source
    # The scalar helpers remain for the explicit relation-check ablation, but
    # the default read_keys body must not invoke either one per element.
    read_keys = source.split("def read_keys(descriptors, valids, address_count):", 1)[1]
    read_keys = read_keys.split("def emit_output_shares", 1)[0]
    assert "unpack_descriptor(" not in read_keys
    assert "unpack_edge(" not in read_keys

    owner_ablated = render_program(hybrid, 10, ablate_owner_batching=True)
    ast.parse(owner_ablated)
    assert "packed_descriptors[:].bit_decompose(" in owner_ablated
    assert "window = read_page_window(owner, bases, address_count)" in owner_ablated
    assert "read_page_windows(" not in owner_ablated

    ablated = render_program(hybrid, 1, ablate_relation_check=True)
    assert "unpack_descriptor(" in ablated
    assert "unpack_edge(" in ablated
    assert "ablation_relation == wanted[address]" in ablated


def test_circuit_never_opens_a_value_except_output_shares(
    config: RelationPageConfig,
):
    source = render_program(config, 2)
    # A plain .reveal() would open a value to every server.
    assert ".reveal()" not in source
    assert source.count("reveal_to(0)") == 1
    assert source.count("reveal_to(1)") == 1
    assert source.count("reveal_to(2)") == 1
    # Output shares must be freshly masked, not the computed value itself.
    assert "share_2 = value - share_0 - share_1" in source
    assert "sint.get_random()" in source
    # No honest-majority protocol may be selected from this backend.
    assert "replicated" not in source.lower()


def test_circuit_range_checks_every_secret_address(config: RelationPageConfig):
    source = render_program(config, 2)
    # Directory address: both components checked before use.
    assert "entity_ok = (entity != 0) * (entity < ENTITY_COUNT)" in source
    assert "relation_ok = (relation != 0) * (relation <= RELATION_COUNT)" in source
    assert "ok.if_else(address, sint(0))" in source
    # Descriptor: page base and count clamped to the reserved dummy page.
    assert "usable = (page_base < PAGE_BUDGET) * (page_count <= PAGES_PER_KEY)" in source
    assert "usable.if_else(page_base, sint(0))" in source
    # Second-hop targets checked before becoming addresses.
    assert "(edge_targets != 0)" in source
    assert "(edge_targets < ENTITY_COUNT)" in source


def test_circuit_uses_one_demux_per_page_window(config: RelationPageConfig):
    """The window optimization must be present, not silently reverted."""

    source = render_program(config, 2)
    # Four demux sites, one per lookup stage. Naming them means adding a fifth
    # (or losing one) fails here rather than passing a bare count.
    assert source.count("demux_matrix(") == 5, (
        "unexpected demux count; every selector site must be accounted for"
    )
    assert "selectors = demux_matrix(address_bits" in source      # hop-one read
    assert "selector = demux_matrix(relation_bits" in source      # relation fold
    assert "selectors = demux_matrix(entity_bits" in source       # folded read
    assert "selectors = demux_matrix(row_bits" in source          # compact read
    # The shifted access is what lets one selector serve every offset.
    assert "(batch_start + local_owner) * POOL_ROWS + page + offset" in source
    assert "POOL_ROWS = " in source


def test_hop_two_folds_the_relation_out_of_the_directory(
    config: RelationPageConfig,
):
    """Hop two must not pay DIRECTORY_ROWS per frontier address.

    Every hop-two address carries the same relation_2, so the relation is
    contracted out once and each address then scans ENTITY_COUNT rows instead
    of ENTITY_COUNT * RELATION_COUNT. Reverting to the combined address would
    silently multiply the dominant term by the frontier width.
    """

    source = render_program(config, 2)
    assert "def fold_directory(" in source
    assert "read_folded_directory(slice_entities, folded, FRONTIER_SLOTS)" in source
    # The unfolded read must survive for hop one, which has nothing to amortise.
    assert "read_directory(first_addresses, QUERY_COUNT)" in source
    # ...and hop two must not be using it.
    assert "read_directory(second_addresses" not in source

    ablated = render_program(config, 2, ablate_folded_directory=True)
    assert "second_descriptors = read_directory(second_addresses" in ablated
    assert "def fold_directory(" in ablated  # rendered but unused
    # The two variants must compile to different programs, or an A/B run would
    # silently reuse one circuit for both arms.
    from doram_t2_3pc.page_program import program_name

    assert program_name(config, 2) != program_name(
        config, 2, ablate_folded_directory=True
    )


def test_circuit_computes_the_directory_address_without_multiplication(
    config: RelationPageConfig,
):
    """source * RELATION_COUNT + relation - 1 is affine in two secrets."""

    source = render_program(config, 2)
    assert "address = entity * RELATION_COUNT + relation - 1" in source


def test_circuit_has_no_first_hop_relation_equality_test(
    config: RelationPageConfig,
):
    """The index resolves the relation; the per-slot comparison must be gone."""

    source = render_program(config, 2)
    assert "relation == relation_1" not in source
    assert "relation_1" not in source


def test_default_topk_suppresses_winner_without_secret_index_equality(
    config: RelationPageConfig,
):
    source = render_program(config, 2)
    assert "became_best[candidate].assign_vector(better)" in source
    assert "candidate = CANDIDATE_COUNT - 1 - reverse_offset" in source
    assert "winner = became_best[candidate][:] * (one - later_winner)" in source
    assert "best_index" not in source


def test_terminal_dedup_keeps_terminal_suppression(config: RelationPageConfig):
    dedup = RelationPageConfig(
        base=replace(config.base, deduplicate_terminal_answers=True),
        pages=config.pages,
    )
    source = render_program(dedup, 2)
    assert "same_terminal = candidate_terminal[candidate][:] == best_terminal" in source
    assert "became_best" not in source
    assert "best_index" not in source


def test_batch_candidate_and_topk_are_simd_vectorized(config: RelationPageConfig):
    source = render_program(config, 10)
    assert "Matrix(CANDIDATE_COUNT, QUERY_COUNT, sint)" in source
    assert "one = sint(1, size=QUERY_COUNT)" in source
    assert "best_valid = sint(0, size=QUERY_COUNT)" in source
    assert "candidate_valid[candidate].assign_vector(valid)" in source
    assert "result_valid[rank].assign_vector(best_valid)" in source
    # Candidate/ranking has one timer pair for the whole SIMD batch rather than
    # ten independently emitted scalar blocks.
    assert "start_timer(20)" in source
    assert "start_timer(20 + query_index * 2)" not in source


def test_one_query_keeps_scalar_candidate_topk_reference(config: RelationPageConfig):
    source = render_program(config, 1)
    assert "left_evidence = Array(CANDIDATE_COUNT, sint)" in source
    assert "became_best[candidate] = better" in source
    assert "sint(0, size=QUERY_COUNT)" not in source


def test_circuit_compaction_is_present_and_bounded(config: RelationPageConfig):
    source = render_program(config, 2)
    assert "FRONTIER_PER_OWNER = " in source
    assert "take = available * (sint(1) - found)" in source


def test_render_rejects_unsupported_configurations(
    tmp_path: Path, config: RelationPageConfig
):
    with pytest.raises(ValueError, match="query_count"):
        render_program(config, 0)
    with pytest.raises(ValueError, match="query_count"):
        render_program(config, MAX_BATCH_QUERIES + 1)

    raw = json.loads((FIXTURE / "config_relation_pages.json").read_text())
    raw["relation_fanout_per_owner"] = 1
    path = tmp_path / "conflicting.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="frontier_per_owner"):
        render_program(RelationPageConfig.load(path), 1)

    legacy = json.loads((FIXTURE / "config_relation_pages.json").read_text())
    legacy["field_prime"] = 2305843009213693951
    legacy_path = tmp_path / "legacy.json"
    legacy_path.write_text(json.dumps(legacy))
    with pytest.raises(ValueError, match="field_prime"):
        render_program(RelationPageConfig.load(legacy_path), 1)


def test_write_program_emits_a_safely_named_file(
    tmp_path: Path, config: RelationPageConfig
):
    path = write_program(config, 1, tmp_path)
    assert re.fullmatch(r"paged_kg_3pc_[0-9a-f]{16}\.mpc", path.name)
    assert path.read_text() == render_program(config, 1)


def test_cost_estimate_agrees_with_the_assembled_input_size(
    config: RelationPageConfig,
):
    estimate = page_cost_estimate(config, 4)
    assert estimate["private_input_values_per_server"] == (
        expected_private_input_values(config, 4)
    )
    assert estimate["second_hop_products"] > estimate["first_hop_products"]


def test_hybrid_cost_estimate_reports_folded_primary_separately():
    hybrid = RelationPageConfig.load(
        FIXTURE / "config_relation_pages_hybrid.json"
    )
    estimate = page_cost_estimate(hybrid, 10)
    assert estimate["hybrid_primary_second_hop_folded_products"] < estimate[
        "hybrid_primary_second_hop_unfolded_products"
    ]
    assert estimate["hybrid_primary_folded_product_ratio"] > 1


def test_distributed_runner_validates_its_own_shard_before_contacting_peers(
    tmp_path: Path, config: RelationPageConfig
):
    """Deployment entry point must fail closed on a wrong or malformed shard."""

    from doram_t2_3pc import run_pages_party

    expected = expected_private_input_values(config, 2)
    wrong = tmp_path / "wrong"
    wrong.write_text("0\n" * (expected - 1))
    with pytest.raises(ValueError, match="expected"):
        run_pages_party.run_party(
            server_id=0,
            config_path=FIXTURE / "config_relation_pages.json",
            query_count=2,
            private_input=wrong,
            ip_file=tmp_path / "absent",
            mpspdz_home=tmp_path,
            output_log=tmp_path / "log",
        )
    good = tmp_path / "good"
    good.write_text("0\n" * expected)
    with pytest.raises(ValueError, match="server_id"):
        run_pages_party.run_party(
            server_id=3,
            config_path=FIXTURE / "config_relation_pages.json",
            query_count=2,
            private_input=good,
            ip_file=tmp_path / "absent",
            mpspdz_home=tmp_path,
            output_log=tmp_path / "log",
        )
    # A valid shard still fails closed when the IP file is absent, i.e. the
    # runner never starts a party it cannot connect correctly.
    with pytest.raises(FileNotFoundError, match="IP file"):
        run_pages_party.run_party(
            server_id=0,
            config_path=FIXTURE / "config_relation_pages.json",
            query_count=2,
            private_input=good,
            ip_file=tmp_path / "absent",
            mpspdz_home=tmp_path,
            output_log=tmp_path / "log",
        )


def test_multi_page_overflow_layout_is_addressable_end_to_end(tmp_path: Path):
    """The window mechanism must survive pages_per_key > 1 in the layout.

    The corresponding MPC execution is recorded in
    benchmarks/relation_paged_overflow_validation.json.
    """

    from doram_t2_3pc.relation_pages import (
        build_owner_page_layout,
        evaluate_paged_cleartext,
    )

    raw = json.loads((FIXTURE / "config_relation_pages.json").read_text())
    raw["relation_page_layout"] = {
        "page_size": 1,
        "pages_per_key": 2,
        "page_budget": 32,
    }
    path = tmp_path / "overflow.json"
    path.write_text(json.dumps(raw))
    config = RelationPageConfig.load(path)

    # Two edges under one key with page_size 1 forces a second page.
    edges = {
        "owner_a": [
            {
                "source": "alice",
                "relation": "referred_to",
                "target": target,
                "evidence": index + 1,
                "score": 3 - index,
            }
            for index, target in enumerate(("bob", "carol"))
        ],
        "owner_b": [],
        "owner_c": [
            {
                "source": "bob",
                "relation": "diagnosed_with",
                "target": "cancer",
                "evidence": 50,
                "score": 4,
            }
        ],
    }
    layout = build_owner_page_layout(config, "owner_a", edges["owner_a"])
    base, count = config.unpack_descriptor(
        layout.directory[
            config.directory_index(
                config.base.entities["alice"],
                config.base.relations["referred_to"],
            )
        ]
    )
    assert count == 2, "fixture must actually exercise the overflow path"
    assert len(layout.pages) == config.pages.pool_rows

    results = evaluate_paged_cleartext(
        config,
        edges,
        {
            "source": "alice",
            "relation_1": "referred_to",
            "relation_2": "diagnosed_with",
        },
    )
    # Only the alice->bob->cancer path exists; it must be found through the
    # first overflow page, not lost with it.
    assert results[0]["valid"] == 1
    assert results[0]["right_evidence"] == 50


def test_compaction_bound_is_enforced_at_preparation_not_in_the_circuit(
    tmp_path: Path,
):
    """A frontier bound below the realized degree must fail closed.

    This is what makes compaction lossless: the circuit compacts to a fixed
    width and never checks for overflow, so preparation has to guarantee no
    match is dropped.
    """

    from doram_t2_3pc.relation_pages import build_owner_page_layout

    raw = json.loads((FIXTURE / "config_relation_pages.json").read_text())
    raw["relation_page_layout"] = {
        "page_size": 2,
        "pages_per_key": 1,
        "page_budget": 16,
        "frontier_per_owner": 1,
    }
    path = tmp_path / "tight.json"
    path.write_text(json.dumps(raw))
    config = RelationPageConfig.load(path)

    edges = [
        {
            "source": "alice",
            "relation": "referred_to",
            "target": target,
            "evidence": index + 1,
            "score": 1,
        }
        for index, target in enumerate(("bob", "carol"))
    ]
    with pytest.raises(ValueError, match="frontier_per_owner"):
        build_owner_page_layout(config, "owner_a", edges)


# --------------------------------------------------------------------------
# Ablation switches
#
# These exist only to attribute measured speedups to individual optimizations.
# They must never be reachable from a configuration file, and must never change
# what the circuit returns or what it opens.
# --------------------------------------------------------------------------


ABLATIONS = (
    {"ablate_relation_check": True},
    {"ablate_window_demux": True},
    {"ablate_owner_batching": True},
)


def _paged_config(tmp_path: Path, **layout) -> RelationPageConfig:
    raw = json.loads((FIXTURE / "config_relation_pages.json").read_text())
    raw["relation_page_layout"] = {**raw["relation_page_layout"], **layout}
    path = tmp_path / f"layout-{'-'.join(map(str, layout.values()))}.json"
    path.write_text(json.dumps(raw))
    return RelationPageConfig.load(path)


@pytest.mark.parametrize("ablation", ABLATIONS)
def test_ablations_get_their_own_program_name(
    config: RelationPageConfig, ablation: dict
):
    """A variant must never reuse the real program's compiled schedule."""

    assert program_name(config, 2, **ablation) != program_name(config, 2)


@pytest.mark.parametrize("ablation", ABLATIONS)
def test_ablations_open_nothing_beyond_output_shares(
    config: RelationPageConfig, ablation: dict
):
    source = render_program(config, 2, **ablation)
    assert ".reveal()" not in source
    assert source.count("reveal_to(") == 3


def test_ablation_flags_are_not_configuration_fields(tmp_path: Path):
    """A layout file must not be able to turn an ablation on."""

    raw = json.loads((FIXTURE / "config_relation_pages.json").read_text())
    raw["relation_page_layout"]["ablate_relation_check"] = True
    path = tmp_path / "sneaky.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError):
        RelationPageConfig.load(path)


def test_relation_check_ablation_restores_the_redundant_equality_test(
    config: RelationPageConfig,
):
    base = render_program(config, 1)
    ablated = render_program(config, 1, ablate_relation_check=True)
    assert "ablation_relation" not in base
    assert "ablation_relation" in ablated
    assert "ok = ok * (ablation_relation == wanted[address])" in ablated


def test_window_demux_ablation_builds_one_selector_per_offset(
    config: RelationPageConfig,
):
    base = render_program(config, 1)
    ablated = render_program(config, 1, ablate_window_demux=True)
    # Both variants retain owner batching. The ablation moves selector creation
    # inside the public page-offset loop and therefore rebuilds it per offset.
    assert "for offset in range(PAGES_PER_KEY):\n        base_bits" not in base
    assert "for offset in range(PAGES_PER_KEY):\n        base_bits" in ablated
    assert "def scan_owner_pages(" in ablated
    assert "for offset in range(PAGES_PER_KEY):" in ablated


def test_compaction_ablation_is_refused_when_it_would_drop_matches(tmp_path: Path):
    """Skipping compaction is only sound when the frontier is already full width.

    With a narrower declared frontier the aliasing would silently discard real
    matches, so the renderer must refuse rather than produce a wrong circuit.
    """

    narrow = _paged_config(tmp_path, pages_per_key=2, frontier_per_owner=2)
    assert narrow.pages.effective_frontier_per_owner < narrow.pages.slots_per_key
    with pytest.raises(ValueError, match="ablate_compaction requires"):
        render_program(narrow, 1, ablate_compaction=True)
    with pytest.raises(ValueError, match="ablate_compaction requires"):
        program_name(narrow, 1, ablate_compaction=True)


def test_compaction_ablation_removes_the_loop_and_aliases_the_frontier(
    tmp_path: Path,
):
    full = _paged_config(tmp_path, pages_per_key=2, frontier_per_owner=4)
    assert full.pages.effective_frontier_per_owner == full.pages.slots_per_key

    base = render_program(full, 1)
    ablated = render_program(full, 1, ablate_compaction=True)
    assert "for compact_slot in range(FRONTIER_PER_OWNER):" in base
    assert "for compact_slot in range(FRONTIER_PER_OWNER):" not in ablated
    assert "frontier_targets = hop1_targets" in ablated
    assert ".reveal()" not in ablated
    assert program_name(full, 1, ablate_compaction=True) != program_name(full, 1)


def test_ablations_keep_the_timer_boundaries_comparable(
    config: RelationPageConfig,
):
    """Every variant must report the same timer regions, or A/B is meaningless."""

    variants = [
        render_program(config, 1),
        render_program(config, 1, ablate_relation_check=True),
        render_program(config, 1, ablate_window_demux=True),
    ]
    for source in variants:
        for timer in (10, 11, 12, 13):
            assert source.count(f"start_timer({timer})") == 1
            assert source.count(f"stop_timer({timer})") == 1


def test_packed_descriptors_recover_every_owner_independently(
    config: RelationPageConfig,
):
    """The packing must be invertible per owner, which is what the circuit does.

    Owners never coordinate: each shares only its own descriptor shifted into
    its own bit range, and the servers' additive sum is the packed element. This
    checks that reconstruction recovers exactly what each owner put in.
    """

    owners = list(config.base.owners)
    layouts = {
        owner: owner_flat_vector(config, owner, _owner_edges()[owner])[0]
        for owner in owners
    }
    width = config.pages.descriptor_bits
    mask = (1 << width) - 1
    for row in range(config.directory_rows):
        columns = [0] * config.directory_columns
        for index, owner in enumerate(owners):
            column, offset = config.directory_slot(index)
            columns[column] += layouts[owner][row] << offset
        for index, owner in enumerate(owners):
            column, offset = config.directory_slot(index)
            assert (columns[column] >> offset) & mask == layouts[owner][row]


def test_packing_never_overflows_the_usable_field(config: RelationPageConfig):
    """Disjoint bit ranges only stay disjoint while they fit in the field."""

    per_element = config.owners_per_directory_element
    assert per_element >= 1
    assert per_element * config.pages.descriptor_bits <= config.base.field_usable_bits
    # Every owner must land inside a real column at a legal offset.
    for index in range(len(config.base.owners)):
        column, offset = config.directory_slot(index)
        assert 0 <= column < config.directory_columns
        assert offset + config.pages.descriptor_bits <= config.base.field_usable_bits


def test_packing_cuts_the_directory_scan_by_the_owner_count(
    config: RelationPageConfig,
):
    owners = len(config.base.owners)
    estimate = page_cost_estimate(config, 1)
    unpacked = config.directory_rows * owners
    packed = config.directory_rows * config.directory_columns
    assert packed < unpacked
    assert estimate["first_hop_products"] < unpacked + owners * (
        config.pages.pages_per_key * config.pages.page_budget * config.pages.page_size
    )


def test_compile_shape_report_flags_the_stage_that_actually_failed():
    """Program size tracks map_sum OUTPUT WIDTH, not iteration count.

    Three circuits failed to compile before this was understood. The dense
    directory read iterates 200,000 times at width ~1 and compiles in seconds;
    the compact bucket fetch iterated 16 times at width 1,425 and never finished.
    This pins the predictor so the wall is visible from a configuration instead
    of after a 30-minute timeout.
    """

    from doram_t2_3pc.page_program import (
        MAP_SUM_WIDTH_WARNING,
        compile_shape_report,
    )

    config = RelationPageConfig.load(FIXTURE / "config_relation_pages.json")
    report = compile_shape_report(config, 1)
    stages = report["stages"]

    # The dense read is narrow no matter how tall the directory is -- that is
    # exactly why it compiles where the bucket fetch did not.
    assert stages["dense_directory_read"] <= 8
    # The relation fold emits one entry per entity, so it is the stage whose
    # width grows with the graph. Naming it here keeps that visible.
    assert stages["relation_fold"] == (
        config.base.entity_count * config.directory_columns
    )
    assert report["widest_stage"] in stages
    assert report["threshold"] == MAP_SUM_WIDTH_WARNING


def test_relation_fold_width_predicts_the_evaluation_fixtures_will_not_compile():
    """A measured speedup does not imply the projection can be run.

    relation_folded_directory.json projects per-query cost for the MetaQA and
    WebQSP evaluation fixtures by extrapolating a fitted line. Those fixtures
    have entity counts of 6,573 and 1,529, so the relation fold's map_sum would
    be that wide -- comparable to or larger than the 1,425 that repeatedly failed
    to compile. The projections are therefore not merely unrun, they are probably
    unrunnable in the current emission, and that belongs beside them.
    """

    from doram_t2_3pc.page_program import (
        MAP_SUM_WIDTH_WARNING,
        compile_shape_report,
    )

    class _Fixture:
        def __init__(self, entities):
            self.entities = entities

    # Every fixture that compiled had a fold width at or below ~216.
    assert MAP_SUM_WIDTH_WARNING > 216, (
        "the threshold must not flag fixtures that are known to compile"
    )
    # And both evaluation fixtures are far above it.
    for entity_count in (1529, 6573):
        assert entity_count > MAP_SUM_WIDTH_WARNING
