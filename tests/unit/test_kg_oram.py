from __future__ import annotations

import random

import pytest

from doram_t2_3pc.kg_oram import (
    build_owner_adjacency_records,
    build_owner_kg_oram,
    dense_key_address,
)
from doram_t2_3pc.config import PublicConfig
from doram_t2_3pc.oram_layout import stack_lookup
from doram_t2_3pc.kg_oram_program import (
    access_count_per_owner,
    common_shape,
    cost_report,
    program_name,
    planned_shape,
    render_program,
)
from doram_t2_3pc.kg_oram_shares import (
    assemble_server_input,
    create_owner_shards,
    create_query_shards,
    flatten_kg_stack,
    write_owner_stack_shards,
)
from doram_t2_3pc.oram_epoch import KgOramEpochAuthorization, consume_epoch_once
from doram_t2_3pc.packed import unpack_edge
from doram_t2_3pc.relation_pages import RelationPageConfig, RelationPageParameters


def _config() -> RelationPageConfig:
    return RelationPageConfig(
        base=PublicConfig.from_dict({
            "owners": ["a", "b"],
            "entities": {"alice": 1, "bob": 2, "carol": 3},
            "relations": {"knows": 1, "likes": 2},
            "fanout_per_owner": 2,
            "top_k": 1,
            "field_prime": 2**127 - 1,
        }),
        pages=RelationPageParameters(
            page_size=2, pages_per_key=1, page_budget=8, global_frontier=2
        ),
    )


def _edges():
    return [
        {"source": "alice", "relation": "knows", "target": "bob", "evidence": 11, "score": 4},
        {"source": "alice", "relation": "knows", "target": "carol", "evidence": 12, "score": 3},
        {"source": "bob", "relation": "likes", "target": "carol", "evidence": 13, "score": 2},
    ]


def test_dense_key_is_affine_and_covers_dummy_entity():
    config = _config()
    assert dense_key_address(config, 0, 1) == 0
    assert dense_key_address(config, 1, 1) == 2
    assert dense_key_address(config, 1, 2) == 3


def test_owner_records_are_fixed_width_lossless_and_padded():
    config = _config()
    records = build_owner_adjacency_records(config, "a", _edges())
    assert len(records) == config.base.entity_count * config.relation_count
    assert {len(record) for record in records} == {2}
    key = records[dense_key_address(config, 1, 1)]
    assert [unpack_edge(config.base, value)[0] for value in key] == [2, 3]
    absent = records[dense_key_address(config, 3, 2)]
    assert absent == [0, 0]


def test_recursive_stack_returns_exact_packed_adjacency_record():
    config = _config()
    owner = build_owner_kg_oram(
        config, "a", _edges(), chi=4, base_threshold=4, rng=random.Random(9)
    )
    for address, expected in enumerate(owner.records):
        assert stack_lookup(owner.stack, address) == expected


def test_record_overflow_fails_instead_of_truncating():
    config = _config()
    edges = _edges() + [
        {"source": "alice", "relation": "knows", "target": "alice", "evidence": 14, "score": 1}
    ]
    with pytest.raises(ValueError, match="ORAM record width"):
        build_owner_adjacency_records(config, "a", edges)


def test_end_to_end_program_binds_secret_dependent_second_address():
    config = _config()
    owners = [
        build_owner_kg_oram(
            config, owner, _edges() if owner == "a" else [],
            chi=4, base_threshold=4, rng=random.Random(9 + index),
        )
        for index, owner in enumerate(config.base.owners)
    ]
    shape = common_shape(config, owners, 1)
    source = render_program(config, shape, 1)
    assert access_count_per_owner(config, 1) == 1 + config.pages.frontier_slots(2)
    assert "frontier_targets[first] * RELATION_COUNT + relation2 - 1" in source
    assert source.count("opened = hit.if_else(dummy, real_leaf).reveal().to_regint") == 1
    assert "tree.get_vector(base + 3, width)" in source
    assert "shared_array(LEVEL_0_SLOTS * LEVEL_0_FIELDS)" in source
    assert "DORAM_BATCH_SHARE" in source
    assert "Stable global compaction" in source
    assert "owner_access[owner] != MAX_ACCESSES_PER_OWNER" in source
    assert "for slot in range(access_number)" in source
    assert "stash_valid[access_number] = write" in source
    assert "for slot in range(MAX_ACCESSES_PER_OWNER)" not in source
    assert program_name(config, shape, 1).startswith("kg_readonly_oram_3pc_")
    assert planned_shape(config, 1, chi=4, base_threshold=4) == shape


def test_epoch_bound_owner_and_client_inputs_assemble_without_plaintext_union():
    config = _config()
    owners = [
        build_owner_kg_oram(
            config, owner, _edges() if owner == "a" else [],
            chi=4, base_threshold=4, rng=random.Random(30 + index),
        )
        for index, owner in enumerate(config.base.owners)
    ]
    epoch = "a" * 64
    owner_shards = [
        create_owner_shards(config, owner, index, query_count=1, epoch_id=epoch)
        for index, owner in enumerate(owners)
    ]
    queries = create_query_shards(
        config,
        [{"source": "alice", "relation_1": "knows", "relation_2": "likes"}],
        epoch_id=epoch,
    )
    authorization = KgOramEpochAuthorization.accepted(
        config, epoch_id=epoch, query_count=1, bound_violations=0
    )
    for server in range(3):
        shape, values = assemble_server_input(
            config, server, [shares[server] for shares in owner_shards], queries[server], authorization
        )
        assert len(values) == len(owners) * shape.owner_values + 3

    wrong_epoch = create_query_shards(
        config,
        [{"source": "alice", "relation_1": "knows", "relation_2": "likes"}],
        epoch_id="b" * 64,
    )
    with pytest.raises(ValueError, match="different epochs"):
        assemble_server_input(
            config, 0, [shares[0] for shares in owner_shards], wrong_epoch[0], authorization
        )


def test_epoch_authorization_rejects_bound_failure_and_replay(tmp_path):
    config = _config()
    with pytest.raises(ValueError, match="violations"):
        KgOramEpochAuthorization.accepted(
            config, epoch_id="c" * 64, query_count=1, bound_violations=1
        )
    authorization = KgOramEpochAuthorization.accepted(
        config, epoch_id="c" * 64, query_count=1, bound_violations=0
    )
    marker = consume_epoch_once(tmp_path, 0, authorization)
    assert marker.is_file()
    with pytest.raises(ValueError, match="already been consumed"):
        consume_epoch_once(tmp_path, 0, authorization)


def test_cost_report_separates_linear_setup_from_sublinear_access():
    report = cost_report(_config(), 1, chi=4, base_threshold=4)
    assert report["setup_is_linear"] is True
    assert report["online_access_is_sublinear"] is True
    assert report["shared_field_values_per_server_all_owners"] > 0
    assert report["path_entries_all_accesses"] > 0


def test_streamed_owner_shards_reconstruct_without_materializing_flat_copy(tmp_path):
    config = _config()
    owner = build_owner_kg_oram(
        config, "a", _edges(), chi=4, base_threshold=4, rng=random.Random(50)
    )
    paths = [tmp_path / f"owner-P{server}" for server in range(3)]
    write_owner_stack_shards(owner, paths, modulus=config.base.field_prime)
    rows = [[int(value) for value in path.read_text().splitlines()] for path in paths]
    from doram_t2_3pc.sharing import reconstruct

    expected = flatten_kg_stack(owner)
    assert len(rows[0]) == len(expected)
    assert [
        reconstruct((rows[0][index], rows[1][index], rows[2][index]), modulus=config.base.field_prime)
        for index in range(len(expected))
    ] == expected
