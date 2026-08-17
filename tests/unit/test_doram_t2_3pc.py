import json
from dataclasses import replace
from pathlib import Path

import pytest

from doram_t2_3pc.config import (
    EDGE_FIELDS,
    FIELD_PRIME,
    SCALABLE_FIELD_PRIME,
    PublicConfig,
)
from doram_t2_3pc.decode_batch import decode_batch_logs
from doram_t2_3pc.decode import decode_logs
from doram_t2_3pc.packed import (
    assemble_packed_batch_from_paths,
    create_packed_owner_shards,
    create_packed_query_batch_shards,
    pack_edge,
    packed_edge_bits,
    packed_owner_capacity_report,
    packed_owner_vector,
    unpack_edge,
)
from doram_t2_3pc.prepare import (
    assemble_server_input,
    create_owner_shards,
    create_query_shards,
    owner_plain_vector,
)
from doram_t2_3pc.program import render_program
from doram_t2_3pc.reference import evaluate_cleartext
from doram_t2_3pc.run_mpspdz import PROTOCOL_SCRIPT, run
from doram_t2_3pc.run_party import validate_private_input
from doram_t2_3pc.scalable_program import query_program_name
from doram_t2_3pc.sharing import reconstruct, share
from doram_t2_3pc.scan_program import (
    render_program as render_scan_program,
    scan_cost_estimate,
)
from doram_t2_3pc.sqrt_program import program_name as sqrt_program_name


@pytest.fixture
def config_path() -> Path:
    return Path("doram_t2_3pc/examples/config.json")


@pytest.fixture
def config(config_path: Path) -> PublicConfig:
    return PublicConfig.load(config_path)


@pytest.fixture
def scalable_config() -> PublicConfig:
    return PublicConfig.load("doram_t2_3pc/examples/ten_query/config_scalable.json")


def _edges(owner: str):
    return json.loads(Path(f"doram_t2_3pc/examples/{owner}.json").read_text())


def test_additive_sharing_reconstructs_and_any_two_fit_every_secret():
    pieces = share(918273645)
    assert reconstruct(pieces) == 918273645

    # Fix any two observed shares. For every hypothetical secret there is a
    # unique missing share producing it, so the pair cannot rule a secret out.
    for missing in range(3):
        observed = {index: pieces[index] for index in range(3) if index != missing}
        for possible_secret in (0, 1, 918273645, FIELD_PRIME - 1):
            completion = (possible_secret - sum(observed.values())) % FIELD_PRIME
            candidate = [observed.get(index, completion) for index in range(3)]
            assert reconstruct(candidate) == possible_secret


def test_owner_and_query_shards_assemble_in_program_consumption_order(
    tmp_path: Path, config: PublicConfig, config_path: Path
):
    owner_dirs = []
    for owner in config.owners:
        directory = tmp_path / owner
        create_owner_shards(
            config,
            owner,
            Path(f"doram_t2_3pc/examples/{owner}.json"),
            directory,
        )
        owner_dirs.append(directory)
    query_dir = tmp_path / "query"
    create_query_shards(config, "doram_t2_3pc/examples/query.json", query_dir)

    server_values = []
    for server in range(3):
        output = tmp_path / "instance" / f"Input-P{server}-0"
        assemble_server_input(
            config,
            server,
            query_dir / f"query-to-server-{server}.json",
            [
                owner_dirs[index] / f"owner-{index}-to-server-{server}.json"
                for index in range(len(config.owners))
            ],
            output,
        )
        assert output.stat().st_mode & 0o077 == 0
        server_values.append([int(line) for line in output.read_text().splitlines()])

    reconstructed = [reconstruct(column) for column in zip(*server_values)]
    expected = [config.entities["alice"], config.relations["referred_to"], config.relations["diagnosed_with"]]
    owner_vectors = {
        owner: owner_plain_vector(config, owner, _edges(owner)) for owner in config.owners
    }
    width = config.fanout_per_owner * len(EDGE_FIELDS)
    for entity in range(config.entity_count):
        start = entity * width
        for owner in config.owners:
            expected.extend(owner_vectors[owner][start : start + width])
    assert reconstructed == expected


def test_cleartext_specification_returns_expected_ranked_paths(config: PublicConfig):
    query = json.loads(Path("doram_t2_3pc/examples/query.json").read_text())
    result = evaluate_cleartext(
        config,
        {"hospital_a": _edges("hospital_a"), "hospital_b": _edges("hospital_b")},
        query,
    )
    assert result == [
        {"valid": 1, "left_evidence": 11, "right_evidence": 12, "score": 7},
        {"valid": 1, "left_evidence": 21, "right_evidence": 22, "score": 6},
    ]


def test_capacity_overflow_fails_closed(config: PublicConfig):
    rows = [
        {"source": "alice", "relation": "referred_to", "target": "bob", "evidence": i + 1, "score": 1}
        for i in range(config.fanout_per_owner + 1)
    ]
    with pytest.raises(ValueError, match="public bound"):
        owner_plain_vector(config, "hospital_a", rows)


def test_server_assembler_rejects_wrong_server_shard(tmp_path: Path, config: PublicConfig):
    query_dir = tmp_path / "query"
    create_query_shards(config, "doram_t2_3pc/examples/query.json", query_dir)
    owner_shards = []
    for index, owner in enumerate(config.owners):
        directory = tmp_path / owner
        create_owner_shards(
            config, owner, f"doram_t2_3pc/examples/{owner}.json", directory
        )
        owner_shards.append(directory / f"owner-{index}-to-server-0.json")
    with pytest.raises(ValueError, match="different configuration or server"):
        assemble_server_input(
            config,
            0,
            query_dir / "query-to-server-1.json",
            owner_shards,
            tmp_path / "Input-P0-0",
        )


def test_generated_program_keeps_adaptive_address_secret_and_reshare_outputs(config: PublicConfig):
    source = render_program(config)
    assert "second_block = graph[safe_second_address]" in source
    assert "first_block = graph[safe_query_source]" in source
    assert "valid_real_entity_address(first_target)" in source
    assert "share_2 = value - share_0 - share_1" in source
    assert ".reveal()" not in source
    assert "reveal_to(0)" in source and "reveal_to(1)" in source and "reveal_to(2)" in source
    assert "replicated" not in source.lower()


def test_client_decoder_requires_all_three_output_shares(tmp_path: Path, config: PublicConfig):
    expected = [
        {"valid": 1, "left_evidence": 11, "right_evidence": 12, "score": 7},
        {"valid": 0, "left_evidence": 0, "right_evidence": 0, "score": 0},
    ]
    logs = [tmp_path / f"server-{server}.log" for server in range(3)]
    lines = [[], [], []]
    field_names = ("valid", "left_evidence", "right_evidence", "score")
    for rank, row in enumerate(expected):
        for field, name in enumerate(field_names):
            pieces = share(row[name])
            for server in range(3):
                lines[server].append(f"DORAM_SHARE {rank} {field} {server} {pieces[server]}")
    for server, path in enumerate(logs):
        path.write_text("\n".join(lines[server]) + "\n")
    assert decode_logs(config, logs) == expected
    with pytest.raises(ValueError, match="exactly one output log"):
        decode_logs(config, logs[:2])


def test_runner_is_pinned_to_semi_and_rejects_a_fourth_server(
    tmp_path: Path, config_path: Path
):
    assert PROTOCOL_SCRIPT == "semi.sh"
    home = tmp_path / "mpspdz"
    (home / "Scripts").mkdir(parents=True)
    for relative in ("compile.py", "semi-party.x", "Scripts/semi.sh"):
        path = home / relative
        path.write_text("placeholder")
    instance = tmp_path / "instance"
    instance.mkdir()
    for server in range(4):
        (instance / f"Input-P{server}-0").write_text("0\n")
    with pytest.raises(ValueError, match="exactly three servers"):
        run(instance, config_path, home)


def test_distributed_runner_validates_exact_private_input_shape(
    tmp_path: Path, config: PublicConfig
):
    expected = (
        3
        + config.entity_count
        * len(config.owners)
        * config.fanout_per_owner
        * len(EDGE_FIELDS)
    )
    valid = tmp_path / "valid"
    valid.write_text("0\n" * expected)
    validate_private_input(config, valid)
    invalid = tmp_path / "invalid"
    invalid.write_text("0\n" * (expected - 1))
    with pytest.raises(ValueError, match="expected"):
        validate_private_input(config, invalid)


def test_packed_edge_round_trip_and_field_headroom(scalable_config: PublicConfig):
    assert scalable_config.field_prime == SCALABLE_FIELD_PRIME
    assert packed_edge_bits(scalable_config) == 77
    fields = (10, 3, (1 << 50) - 1, (1 << 20) - 1, 1)
    packed = pack_edge(scalable_config, *fields)
    assert unpack_edge(scalable_config, packed) == fields
    assert packed.bit_length() <= scalable_config.field_usable_bits


def test_packed_batch_assembly_reconstructs_queries_and_graph(
    tmp_path: Path, scalable_config: PublicConfig
):
    query_file = tmp_path / "queries.json"
    queries = json.loads(
        Path("doram_t2_3pc/examples/ten_query/queries.json").read_text()
    )[:2]
    query_file.write_text(json.dumps(queries))
    query_dir = tmp_path / "queries"
    create_packed_query_batch_shards(scalable_config, query_file, query_dir)

    owner_dirs = []
    owner_vectors = []
    for owner in scalable_config.owners:
        directory = tmp_path / owner
        edge_file = Path(f"doram_t2_3pc/examples/ten_query/{owner}.json")
        create_packed_owner_shards(scalable_config, owner, edge_file, directory)
        owner_dirs.append(directory)
        owner_vectors.append(
            packed_owner_vector(
                scalable_config,
                owner,
                json.loads(edge_file.read_text()),
            )
        )

    server_values = []
    for server in range(3):
        output = tmp_path / "instance" / f"Input-P{server}-0"
        assemble_packed_batch_from_paths(
            scalable_config,
            server,
            2,
            query_dir / f"query-batch-to-server-{server}.json",
            [
                owner_dirs[index]
                / f"packed-owner-{index}-to-server-{server}.json"
                for index in range(len(scalable_config.owners))
            ],
            output,
        )
        server_values.append([int(value) for value in output.read_text().splitlines()])

    reconstructed = [
        reconstruct(column, modulus=scalable_config.field_prime)
        for column in zip(*server_values)
    ]
    expected = []
    for query in queries:
        expected.extend(
            (
                scalable_config.entities[query["source"]],
                scalable_config.relations[query["relation_1"]],
                scalable_config.relations[query["relation_2"]],
            )
        )
    for entity in range(scalable_config.entity_count):
        start = entity * scalable_config.fanout_per_owner
        for owner_index in range(len(scalable_config.owners)):
            expected.extend(
                owner_vectors[owner_index][
                    start : start + scalable_config.fanout_per_owner
                ]
            )
    assert reconstructed == expected


def test_scan_program_has_two_constant_trace_batch_reads_and_no_address_open(
    scalable_config: PublicConfig,
):
    source = render_scan_program(scalable_config, 2)
    assert source.count("oblivious_batch_read(") == 3  # definition plus two calls
    assert "selectors = demux_matrix" in source
    assert "selected[address] * block[edge]" in source
    assert "second_addresses[flat] = valid.if_else(target, sint(0))" in source
    assert ".reveal()" not in source
    assert "reveal_to(0)" in source


def test_relation_frontier_bound_fails_closed_without_truncation(
    scalable_config: PublicConfig,
):
    compact = replace(scalable_config, relation_fanout_per_owner=1)
    compact.validate()
    edges = json.loads(
        Path("doram_t2_3pc/examples/ten_query/owner_a.json").read_text()
    )
    report = packed_owner_capacity_report(compact, "owner_a", edges)
    assert report["audit_scope"] == "supplied_file_only"
    assert report["supplied_input_fits_declared_capacity"] is True
    assert report["required_fanout_per_owner"] == 2
    assert report["required_relation_fanout_per_owner"] == 1

    duplicate_relation = [
        *edges,
        {
            "source": "alice",
            "relation": "referred_to",
            "target": "carol",
            "evidence": 999,
            "score": 1,
        },
    ]
    overflow = packed_owner_capacity_report(
        compact, "owner_a", duplicate_relation
    )
    assert overflow["supplied_input_fits_declared_capacity"] is False
    assert overflow["source_relation_overflow_bucket_count"] == 1
    with pytest.raises(ValueError, match="relation_fanout_per_owner"):
        packed_owner_vector(compact, "owner_a", duplicate_relation)

    source_only_overflow = [
        {
            "source": "alice",
            "relation": relation,
            "target": target,
            "evidence": 900 + index,
            "score": 1,
        }
        for index, (relation, target) in enumerate(
            (
                ("referred_to", "bob"),
                ("diagnosed_with", "cancer"),
                ("treated_with", "drug_x"),
            )
        )
    ]
    source_overflow = packed_owner_capacity_report(
        compact, "owner_a", source_only_overflow
    )
    assert source_overflow["supplied_input_fits_declared_capacity"] is False
    assert source_overflow["source_overflow_bucket_count"] == 1
    assert source_overflow["source_relation_overflow_bucket_count"] == 0
    with pytest.raises(ValueError, match="public bound is 2"):
        packed_owner_vector(compact, "owner_a", source_only_overflow)


def test_scan_only_options_are_rejected_by_unsupported_oram_experiments(
    scalable_config: PublicConfig,
):
    compact = replace(
        scalable_config,
        relation_fanout_per_owner=1,
        deduplicate_terminal_answers=True,
    )
    compact.validate()
    with pytest.raises(ValueError, match="does not implement scan-only"):
        render_program(compact)
    with pytest.raises(ValueError, match="does not implement scan-only"):
        query_program_name(compact)
    with pytest.raises(ValueError, match="does not implement scan-only"):
        sqrt_program_name(compact, 1)


def test_compacted_scan_reduces_dependent_addresses_without_opening_frontier(
    scalable_config: PublicConfig,
):
    compact = replace(scalable_config, relation_fanout_per_owner=1)
    compact.validate()
    assert compact.block_edges == 6
    assert compact.frontier_edges == 3
    assert compact.compacted_candidate_count == 18

    source = render_scan_program(compact, 2)
    assert "FRONTIER_EDGES = 3" in source
    assert "CANDIDATE_COUNT = 18" in source
    assert "raw_first_valids" in source
    assert "for owner_index in range(OWNER_COUNT):" in source
    assert "consumed = Array(FANOUT_PER_OWNER, sint)" in source
    assert "prefix_rank =" not in source
    assert "second_blocks = oblivious_batch_read(second_addresses, FIRST_COUNT)" in source
    assert ".reveal()" not in source
    assert "candidate_terminal =" not in source
    assert "same_terminal =" not in source

    costs = scan_cost_estimate(compact, 2)
    assert costs["legacy_second_scan_selected_products"] == 792
    assert costs["second_scan_selected_products"] == 396
    assert costs["frontier_compaction_selection_cells"] == 12
    assert costs["deduplication_candidate_comparisons"] == 0
    assert costs["second_scan_reduction_factor"] == 2.0
    assert scan_cost_estimate(scalable_config, 2)[
        "frontier_compaction_selection_cells"
    ] == 0

    owners = {
        owner: json.loads(
            Path(f"doram_t2_3pc/examples/ten_query/{owner}.json").read_text()
        )
        for owner in compact.owners
    }
    queries = json.loads(
        Path("doram_t2_3pc/examples/ten_query/queries.json").read_text()
    )
    for query in queries:
        assert evaluate_cleartext(compact, owners, query) == evaluate_cleartext(
            scalable_config, owners, query
        )


@pytest.mark.parametrize("relation_fanout_per_owner", [None, 1])
def test_terminal_answer_deduplication_keeps_distinct_answers_in_topk(
    scalable_config: PublicConfig, relation_fanout_per_owner: int | None
):
    deduplicated = replace(
        scalable_config,
        relation_fanout_per_owner=relation_fanout_per_owner,
        deduplicate_terminal_answers=True,
    )
    deduplicated.validate()
    owners = {
        owner: json.loads(
            Path(f"doram_t2_3pc/examples/ten_query/{owner}.json").read_text()
        )
        for owner in deduplicated.owners
    }
    query = json.loads(
        Path("doram_t2_3pc/examples/ten_query/queries.json").read_text()
    )[0]
    result = evaluate_cleartext(deduplicated, owners, query)

    # Deduplication is about which TERMINALS survive into the top-k, not about
    # particular evidence handles. Asserting literal handles pinned this test to
    # one allocation, and it broke when the fixture moved to owner-blind
    # handles; the property it exists to check did not change.
    assert len(result) == deduplicated.top_k
    assert [row["valid"] for row in result] == [1, 1, 0, 0]
    assert [row["score"] for row in result[:2]] == [12, 11]
    for row in result[2:]:
        assert row == {"valid": 0, "left_evidence": 0, "right_evidence": 0, "score": 0}

    # The surviving handles must be real ones from the fixture, not fabricated.
    fixture_handles = {
        edge["evidence"] for edges in owners.values() for edge in edges
    }
    for row in result[:2]:
        assert row["left_evidence"] in fixture_handles
        assert row["right_evidence"] in fixture_handles


def test_batch_decoder_requires_every_server_and_query(
    tmp_path: Path, scalable_config: PublicConfig
):
    expected = [
        [
            {"valid": 1, "left_evidence": 7, "right_evidence": 8, "score": 9},
            {"valid": 0, "left_evidence": 0, "right_evidence": 0, "score": 0},
            {"valid": 0, "left_evidence": 0, "right_evidence": 0, "score": 0},
            {"valid": 0, "left_evidence": 0, "right_evidence": 0, "score": 0},
        ]
    ]
    lines = [[], [], []]
    for rank, row in enumerate(expected[0]):
        for field, name in enumerate(("valid", "left_evidence", "right_evidence", "score")):
            pieces = share(row[name], modulus=scalable_config.field_prime)
            for server in range(3):
                lines[server].append(
                    f"DORAM_BATCH_SHARE 0 {rank} {field} {server} {pieces[server]}"
                )
    logs = []
    for server in range(3):
        path = tmp_path / f"server-{server}.log"
        path.write_text("\n".join(lines[server]) + "\n")
        logs.append(path)
    assert decode_batch_logs(scalable_config, 1, logs) == expected
    with pytest.raises(ValueError, match="exactly one output log"):
        decode_batch_logs(scalable_config, 1, logs[:2])
