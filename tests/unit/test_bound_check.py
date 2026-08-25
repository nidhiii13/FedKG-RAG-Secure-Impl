"""Tests for the one-time federation-wide global_frontier verification.

The retrieval circuit compacts the frontier to a fixed federation-wide width
without checking for overflow, so an understated global_frontier does not fail
closed -- it silently drops matches at the second hop. Owner-local preparation
cannot catch it, because the bound is a cross-owner sum. This check is what
makes the bound sound rather than trusted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from doram_t2_3pc.bound_check_program import (
    bound_check_cost_estimate,
    overflow_polynomial,
    program_name,
    render_program,
)
from doram_t2_3pc.paged_shares import (
    assemble_bound_check_input,
    create_paged_owner_shards,
)
from doram_t2_3pc.relation_pages import (
    RelationPageConfig,
    owner_occupancy_vector,
)


FIXTURE = Path("doram_t2_3pc/examples/ten_query")
OWNERS = ("owner_a", "owner_b", "owner_c")


def _configs(tmp_path: Path, bound: int | None):
    raw = json.loads((FIXTURE / "config_relation_pages.json").read_text())
    if bound is not None:
        raw["relation_page_layout"]["global_frontier"] = bound
    path = tmp_path / f"cfg_{bound}.json"
    path.write_text(json.dumps(raw))
    return RelationPageConfig.load(path)


def _edges() -> dict[str, list[dict]]:
    return {o: json.loads((FIXTURE / f"{o}.json").read_text()) for o in OWNERS}


def test_occupancy_counts_this_owners_edges_per_key(tmp_path: Path):
    config = _configs(tmp_path, 3)
    edges = _edges()["owner_a"]
    occupancy = owner_occupancy_vector(config, "owner_a", edges)
    assert len(occupancy) == config.directory_rows
    # Every edge is counted exactly once, so the vector sums to the edge count.
    assert sum(occupancy) == len(edges)


def test_occupancy_sums_across_owners_without_unpacking(tmp_path: Path):
    """Every owner writes at the same position, so shares add to the total.

    This is what lets the check avoid any oblivious machinery: the servers'
    additive reconstruction is already the federation-wide per-key count.
    """

    from collections import Counter

    config = _configs(tmp_path, 3)
    edges = _edges()
    totals = [0] * config.directory_rows
    for owner in OWNERS:
        for row, value in enumerate(owner_occupancy_vector(config, owner, edges[owner])):
            totals[row] += value

    expected = Counter()
    for owner in OWNERS:
        for edge in edges[owner]:
            expected[
                config.directory_index(
                    config.base.entities[edge["source"]],
                    config.base.relations[edge["relation"]],
                )
            ] += 1
    assert totals == [expected.get(row, 0) for row in range(config.directory_rows)]


def test_check_is_refused_when_no_global_bound_is_declared(tmp_path: Path):
    config = _configs(tmp_path, None)
    with pytest.raises(ValueError, match="global_frontier"):
        render_program(config)
    with pytest.raises(ValueError, match="global_frontier"):
        program_name(config)


def test_check_opens_exactly_one_aggregate_value(tmp_path: Path):
    """It must not reveal per-key counts or which keys overflowed."""

    config = _configs(tmp_path, 3)
    source = render_program(config)
    assert ".reveal()" not in source
    assert source.count("reveal_to(") == 1
    # The opened value is the violation count, nothing per-key.
    assert "PAGED_BOUND_VIOLATIONS" in source
    assert "violations = overflow.sum()" in source
    assert "overflow = overflow * counts + coefficient" in source
    assert "occupancy[:] > GLOBAL_FRONTIER" not in source
    assert "for row in range(DIRECTORY_ROWS)" not in source


def test_check_uses_no_oblivious_indexing(tmp_path: Path):
    """The whole point: it verifies every key, so every index is public."""

    config = _configs(tmp_path, 3)
    source = render_program(config)
    for oblivious in ("demux_matrix", "demux(", "map_sum"):
        assert oblivious not in source, (
            f"{oblivious} would make this a per-query cost rather than a "
            "one-time linear pass"
        )
    estimate = bound_check_cost_estimate(config)
    assert estimate["oblivious_reads"] == 0
    assert estimate["comparisons"] == 0
    assert estimate["field_multiplications"] == (
        config.directory_rows
        * len(config.base.owners)
        * config.pages.slots_per_key
    )
    assert estimate["opened_values"] == 1


@pytest.mark.parametrize("bound", range(6))
def test_overflow_polynomial_is_exact_on_the_promised_domain(bound: int):
    from doram_t2_3pc.config import (
        HE_SCALABLE_FIELD_PRIME,
        SCALABLE_FIELD_PRIME,
    )

    maximum = 6
    for prime in (SCALABLE_FIELD_PRIME, HE_SCALABLE_FIELD_PRIME):
        coefficients = overflow_polynomial(bound, maximum, prime)
        for count in range(maximum + 1):
            value = sum(
                coefficient * pow(count, degree, prime)
                for degree, coefficient in enumerate(coefficients)
            ) % prime
            assert value == int(count > bound)


def test_shards_carry_occupancy_only_when_the_bound_is_declared(tmp_path: Path):
    for bound, expected in ((3, True), (None, False)):
        config = _configs(tmp_path, bound)
        out = tmp_path / f"shards_{bound}"
        paths = create_paged_owner_shards(
            config, "owner_a", FIXTURE / "owner_a.json", out
        )
        document = json.loads(paths[0].read_text())
        assert ("occupancy" in document) is expected


def test_assembly_rejects_shards_without_occupancy(tmp_path: Path):
    """A layout declaring the bound must not be checkable with stale shards."""

    plain = _configs(tmp_path, None)
    for owner in OWNERS:
        create_paged_owner_shards(plain, owner, FIXTURE / f"{owner}.json", tmp_path / owner)

    # Same digest is impossible across the two configs, so build shards under the
    # bounded config and then strip the occupancy vector to simulate staleness.
    bounded = _configs(tmp_path, 3)
    shard_dirs = []
    for owner in OWNERS:
        directory = tmp_path / f"b_{owner}"
        create_paged_owner_shards(bounded, owner, FIXTURE / f"{owner}.json", directory)
        shard_dirs.append(directory)
    stale = []
    for index, directory in enumerate(shard_dirs):
        path = directory / f"paged-owner-{index}-to-server-0.json"
        document = json.loads(path.read_text())
        document.pop("occupancy")
        path.write_text(json.dumps(document))
        stale.append(path)
    with pytest.raises(ValueError, match="occupancy"):
        assemble_bound_check_input(bounded, 0, stale, tmp_path / "out")


def test_assembled_input_reconstructs_to_the_federation_wide_counts(tmp_path: Path):
    from doram_t2_3pc.sharing import reconstruct

    config = _configs(tmp_path, 3)
    edges = _edges()
    shard_dirs = []
    for index, owner in enumerate(OWNERS):
        directory = tmp_path / owner
        create_paged_owner_shards(config, owner, FIXTURE / f"{owner}.json", directory)
        shard_dirs.append(directory)

    per_server = []
    for server in range(3):
        output = tmp_path / f"Input-P{server}-0"
        assemble_bound_check_input(
            config,
            server,
            [
                shard_dirs[index] / f"paged-owner-{index}-to-server-{server}.json"
                for index in range(len(OWNERS))
            ],
            output,
        )
        per_server.append([int(line) for line in output.read_text().split()])

    prime = config.base.field_prime
    combined = [reconstruct(col, modulus=prime) for col in zip(*per_server)]
    expected = [0] * config.directory_rows
    for owner in OWNERS:
        for row, value in enumerate(owner_occupancy_vector(config, owner, edges[owner])):
            expected[row] += value
    assert combined == expected
    assert max(combined) <= config.pages.global_frontier
