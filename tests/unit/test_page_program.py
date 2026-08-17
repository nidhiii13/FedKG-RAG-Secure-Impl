"""Tests for the relation-paged secret-sharing path and MP-SPDZ circuit.

These do not execute MP-SPDZ. They pin the share/assembly contract, the exact
private-input shape the runner validates, and the circuit properties a security
claim depends on: no value is ever opened except a per-server output share, and
every address is range-checked before it indexes a table.
"""

from __future__ import annotations

import json
import re
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
    assert "(target != 0)" in source and "(target < ENTITY_COUNT)" in source


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
    assert "selectors = demux_matrix(bucket_bits" in source       # compact read
    # The shifted access is what lets one selector serve every offset.
    assert "pages[row_offset + page + offset][slot]" in source
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
    # The textual demux_matrix count is equal in both because the ablated call
    # sits inside a loop, so compare the structure that actually differs.
    assert "parts.append(Array.create_from(scan_page()))" not in base
    assert "parts.append(Array.create_from(scan_page()))" in ablated
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
