from __future__ import annotations

import random
import json
from dataclasses import asdict

import pytest

from doram_t2_3pc.config import PublicConfig
from doram_t2_3pc.oram_layout import stack_lookup
from doram_t2_3pc.packed import unpack_edge
from doram_t2_3pc.relation_paged_oram import (
    build_owner_relation_paged_oram,
    evaluate_relation_paged_oram_cleartext,
    read_owner_relation_pages,
    planned_relation_paged_oram_cost_report,
    relation_paged_oram_cost_report,
)
from doram_t2_3pc.relation_paged_oram_epoch import (
    RelationPagedOramEpochAuthorization,
    consume_relation_paged_oram_epoch_once,
    dual_access_counts,
)
from doram_t2_3pc.relation_paged_oram_shares import (
    assemble_server_input,
    create_owner_shards,
    create_query_shards,
    flatten_relation_paged_oram,
    write_owner_shards,
)
from doram_t2_3pc.relation_paged_oram_program import (
    planned_shape,
    program_name,
    render_program,
)
from doram_t2_3pc.relation_pages import (
    RelationPageConfig,
    RelationPageParameters,
    evaluate_paged_cleartext,
)


def _config(*, pages_per_key: int = 2) -> RelationPageConfig:
    return RelationPageConfig(
        base=PublicConfig.from_dict({
            "owners": ["a", "b"],
            "entities": {"alice": 1, "bob": 2, "carol": 3, "dave": 4},
            "relations": {"knows": 1, "likes": 2},
            "fanout_per_owner": 4,
            "top_k": 2,
            "field_prime": 2**127 - 1,
        }),
        pages=RelationPageParameters(
            page_size=2,
            pages_per_key=pages_per_key,
            page_budget=12,
            global_frontier=3,
        ),
    )


def _owner_edges():
    return {
        "a": [
            {"source": "alice", "relation": "knows", "target": "bob", "evidence": 11, "score": 4},
            {"source": "alice", "relation": "knows", "target": "carol", "evidence": 12, "score": 3},
            {"source": "alice", "relation": "knows", "target": "dave", "evidence": 13, "score": 2},
            {"source": "bob", "relation": "likes", "target": "dave", "evidence": 14, "score": 5},
        ],
        "b": [
            {"source": "carol", "relation": "likes", "target": "dave", "evidence": 21, "score": 7},
            {"source": "dave", "relation": "likes", "target": "bob", "evidence": 22, "score": 1},
        ],
    }


def test_builder_reuses_exact_relation_directory_and_pages():
    config = _config()
    owner = build_owner_relation_paged_oram(
        config, "a", _owner_edges()["a"], chi=4, base_threshold=4,
        rng=random.Random(7),
    )
    assert [stack_lookup(owner.directory_stack, row)[0] for row in range(config.directory_rows)] == owner.layout.directory
    assert [stack_lookup(owner.page_stack, row) for row in range(config.pages.pool_rows)] == owner.layout.pages


def test_lookup_reads_overflow_pages_and_fixed_dummy_tail():
    config = _config()
    owner = build_owner_relation_paged_oram(
        config, "a", _owner_edges()["a"], chi=4, base_threshold=4,
        rng=random.Random(8),
    )
    packed = read_owner_relation_pages(config, owner, 1, 1)
    assert len(packed) == config.pages.slots_per_key == 4
    decoded = [unpack_edge(config.base, value)[0] if value else 0 for value in packed]
    assert decoded == [2, 3, 4, 0]

    absent = read_owner_relation_pages(config, owner, 4, 1)
    assert absent == [0] * config.pages.slots_per_key


def test_end_to_end_dual_oram_matches_existing_paged_semantics():
    config = _config()
    query = {"source": "alice", "relation_1": "knows", "relation_2": "likes"}
    expected = evaluate_paged_cleartext(config, _owner_edges(), query)
    actual = evaluate_relation_paged_oram_cleartext(
        config, _owner_edges(), query, chi=4, base_threshold=4
    )
    assert actual == expected
    assert actual[0] == {
        "valid": 1,
        "left_evidence": 12,
        "right_evidence": 21,
        "score": 10,
    }


def test_existing_page_overflow_check_is_preserved():
    config = _config(pages_per_key=1)
    with pytest.raises(ValueError, match="needs 2 pages"):
        build_owner_relation_paged_oram(config, "a", _owner_edges()["a"])


def test_cost_report_separates_linear_setup_and_sublinear_reads():
    config = _config()
    owner = build_owner_relation_paged_oram(
        config, "a", _owner_edges()["a"], chi=4, base_threshold=4,
        rng=random.Random(9),
    )
    report = relation_paged_oram_cost_report(config, owner, query_count=2)
    assert report["setup_is_linear"] is True
    assert report["online_access_is_sublinear_in_directory_and_page_pool"] is True
    assert report["fresh_read_only_epoch_required"] is True
    assert report["directory_reads_per_owner"] == 2 * (1 + 3)
    assert report["page_reads_per_owner"] == 2 * report["directory_reads_per_owner"]
    assert report["shared_values_per_server_all_owners"] > 0


def test_planned_capacity_report_exposes_quadratic_epoch_stash():
    config = _config()
    one = planned_relation_paged_oram_cost_report(
        config, query_count=1, chi=4, base_threshold=4
    )
    two = planned_relation_paged_oram_cost_report(
        config, query_count=2, chi=4, base_threshold=4
    )
    assert one["tree_path_access_is_sublinear_in_database_size"] is True
    assert one["current_epoch_stash_is_quadratic_in_access_count"] is True
    assert two["online_path_entries_all_owners"] == 2 * one["online_path_entries_all_owners"]
    assert two["replay_stash_comparisons_all_owners"] > 2 * one["replay_stash_comparisons_all_owners"]


def test_position_map_stops_before_pointless_single_record_level():
    # 20,054 / 256 rounds to 79. A further packing would produce one record;
    # the 79 position labels are instead the secret linear base.
    config = _config()
    config = RelationPageConfig(
        base=config.base,
        pages=RelationPageParameters(
            page_size=2,
            pages_per_key=1,
            page_budget=20_054,
            global_frontier=3,
        ),
    )
    shape = planned_shape(config, 1, chi=256, base_threshold=64)
    assert [level.size for level in shape.pages.levels] == [20_054, 79]
    assert shape.pages.base_entries == 79
    built = build_owner_relation_paged_oram(
        config,
        "a",
        _owner_edges()["a"][:2],
        chi=256,
        base_threshold=64,
        rng=random.Random(99),
        statistical_security_bits=80,
    )
    from doram_t2_3pc.relation_paged_oram_shares import shape_for_owner

    assert shape_for_owner(config, built, query_count=1) == shape


def _built_owners(config):
    return [
        build_owner_relation_paged_oram(
            config,
            name,
            _owner_edges()[name],
            chi=4,
            base_threshold=4,
            rng=random.Random(40 + index),
        )
        for index, name in enumerate(config.base.owners)
    ]


def test_role_separated_dual_stack_shares_assemble_without_reconstruction():
    config = _config()
    owners = _built_owners(config)
    epoch = "a" * 64
    owner_shards = [
        create_owner_shards(
            config, owner, index, query_count=1, epoch_id=epoch
        )
        for index, owner in enumerate(owners)
    ]
    queries = create_query_shards(
        config,
        [{"source": "alice", "relation_1": "knows", "relation_2": "likes"}],
        epoch_id=epoch,
    )
    authorization = RelationPagedOramEpochAuthorization.accepted(
        config, epoch_id=epoch, query_count=1, bound_violations=0
    )
    expected_directory, expected_pages = dual_access_counts(config, 1)
    for server in range(3):
        shape, values = assemble_server_input(
            config,
            server,
            [shards[server] for shards in owner_shards],
            queries[server],
            authorization,
        )
        assert shape.directory.max_accesses == expected_directory
        assert shape.pages.max_accesses == expected_pages
        assert len(values) == len(owners) * shape.owner_values + 3


def test_dual_stack_shares_reject_cross_epoch_mix():
    config = _config()
    owners = _built_owners(config)
    owner_epoch = "b" * 64
    owner_shards = [
        create_owner_shards(
            config, owner, index, query_count=1, epoch_id=owner_epoch
        )
        for index, owner in enumerate(owners)
    ]
    wrong_queries = create_query_shards(
        config,
        [{"source": "alice", "relation_1": "knows", "relation_2": "likes"}],
        epoch_id="c" * 64,
    )
    authorization = RelationPagedOramEpochAuthorization.accepted(
        config, epoch_id=owner_epoch, query_count=1, bound_violations=0
    )
    with pytest.raises(ValueError, match="different epochs"):
        assemble_server_input(
            config,
            0,
            [shards[0] for shards in owner_shards],
            wrong_queries[0],
            authorization,
        )


def test_streamed_dual_stack_shares_reconstruct_in_program_order(tmp_path):
    config = _config()
    owner = _built_owners(config)[0]
    paths = [tmp_path / f"owner-P{server}" for server in range(3)]
    write_owner_shards(owner, paths, modulus=config.base.field_prime)
    rows = [[int(value) for value in path.read_text().splitlines()] for path in paths]
    expected = flatten_relation_paged_oram(owner)
    from doram_t2_3pc.sharing import reconstruct

    assert len(rows[0]) == len(expected)
    assert [
        reconstruct(
            (rows[0][index], rows[1][index], rows[2][index]),
            modulus=config.base.field_prime,
        )
        for index in range(len(expected))
    ] == expected


def test_dual_epoch_replay_is_rejected_for_both_stacks(tmp_path):
    config = _config()
    authorization = RelationPagedOramEpochAuthorization.accepted(
        config, epoch_id="d" * 64, query_count=1, bound_violations=0
    )
    marker = consume_relation_paged_oram_epoch_once(tmp_path, 0, authorization)
    assert marker.is_file()
    with pytest.raises(ValueError, match="already been consumed"):
        consume_relation_paged_oram_epoch_once(tmp_path, 0, authorization)


def test_generated_program_uses_secret_descriptor_for_fixed_page_reads():
    config = _config()
    owners = _built_owners(config)
    shape = planned_shape(config, 1, chi=4, base_threshold=4)
    assert shape == create_owner_shards(
        config, owners[0], 0, query_count=1, epoch_id="e" * 64
    )[0].shape
    source = render_program(config, shape, 1)
    assert "entity * RELATION_COUNT + relation - 1" in source
    assert "descriptor_record[0].bit_decompose(DESCRIPTOR_BITS)" in source
    assert "active.if_else(page_base + page_offset, sint(0))" in source
    assert "for page_offset in range(PAGES_PER_KEY)" in source
    assert "frontier_valid[first] * frontier_targets[first]" in source
    assert "directory ORAM access schedule mismatch" in source
    assert "page ORAM access schedule mismatch" in source
    assert "for slot in range(access_number)" in source
    assert "stash_valid[access_number] = write" in source
    assert "for slot in range(max_accesses)" not in source
    assert "DORAM_BATCH_SHARE" in source
    assert program_name(config, shape, 1).startswith(
        "relation_paged_recursive_oram_3pc_"
    )
    assert json.loads(json.dumps(asdict(shape)))["directory"]["levels"][0]["size"] == 10
