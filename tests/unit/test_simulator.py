"""The executable form of Definition 1.

IDEAL_FUNCTIONALITY.md claims the two-server view is simulatable from L. These
tests check the components that claim rests on: that a simulator with no access
to the data reproduces a real view's observable surface, and that two different
owner profiles satisfying the same L and inducing the same answer are
indistinguishable.

They are not a proof; see the module docstring for why not.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from doram_t2_3pc import simulator
from doram_t2_3pc.packed import create_packed_query_batch_shards
from doram_t2_3pc.paged_shares import (
    assemble_paged_batch_from_paths,
    create_paged_owner_shards,
    expected_private_input_values,
)
from doram_t2_3pc.relation_pages import RelationPageConfig, evaluate_paged_cleartext
from doram_t2_3pc.simulator import (
    real_server_view,
    simulate_server_view,
    views_are_indistinguishable,
)


FIXTURE = Path("doram_t2_3pc/examples/ten_query")
OWNERS = ("owner_a", "owner_b", "owner_c")


@pytest.fixture
def config() -> RelationPageConfig:
    return RelationPageConfig.load(FIXTURE / "config_relation_pages.json")


def _prepare(tmp_path: Path, config, edges_by_owner, queries, tag: str) -> Path:
    """Prepare one server's real private input from given edges."""

    query_file = tmp_path / f"q_{tag}.json"
    query_file.write_text(json.dumps(queries))
    query_dir = tmp_path / f"qs_{tag}"
    create_packed_query_batch_shards(config.base, query_file, query_dir)

    shard_paths = []
    for index, owner in enumerate(config.base.owners):
        edge_file = tmp_path / f"{tag}_{owner}.json"
        edge_file.write_text(json.dumps(edges_by_owner[owner]))
        out = tmp_path / f"{tag}_{owner}_shards"
        create_paged_owner_shards(config, owner, edge_file, out)
        shard_paths.append(out / f"paged-owner-{index}-to-server-0.json")

    instance = tmp_path / f"inst_{tag}"
    instance.mkdir(exist_ok=True)
    return assemble_paged_batch_from_paths(
        config, 0, len(queries),
        query_dir / "query-batch-to-server-0.json",
        shard_paths, instance / "Input-P0-0",
    )


def test_simulator_takes_only_public_parameters():
    """A simulator that could read the data would prove nothing."""

    params = set(inspect.signature(simulate_server_view).parameters)
    assert params == {"config", "query_count", "server", "rng"}
    for forbidden in ("edges", "queries", "owner_edges", "shares", "instance"):
        assert forbidden not in params


def test_simulated_view_matches_a_real_view_in_every_observable(
    tmp_path: Path, config: RelationPageConfig
):
    edges = {o: json.loads((FIXTURE / f"{o}.json").read_text()) for o in OWNERS}
    queries = json.loads((FIXTURE / "queries.json").read_text())[:2]
    real_path = _prepare(tmp_path, config, edges, queries, "real")

    real = real_server_view(config, len(queries), 0, str(real_path))
    simulated = simulate_server_view(config, len(queries), 0)
    verdict = views_are_indistinguishable(real, simulated)
    assert verdict["indistinguishable"], verdict
    assert verdict["same_shape"] and verdict["same_circuit"]


def test_definition_1_two_profiles_same_answer_are_indistinguishable(
    tmp_path: Path, config: RelationPageConfig
):
    """The executable form of Definition 1.

    Two profiles that satisfy the same declared bounds and induce the same
    answer must produce identical observable views. Here the same edges are
    redistributed between two owners, which changes every owner's per-query
    match count while leaving the answer alone.
    """

    edges = {o: json.loads((FIXTURE / f"{o}.json").read_text()) for o in OWNERS}
    queries = json.loads((FIXTURE / "queries.json").read_text())[:2]

    # Move owner_a's edges to owner_b and vice versa: same union, same answer,
    # completely different per-owner contributions.
    swapped = dict(edges)
    swapped["owner_a"], swapped["owner_b"] = edges["owner_b"], edges["owner_a"]

    for query in queries:
        assert evaluate_paged_cleartext(config, edges, query) == \
            evaluate_paged_cleartext(config, swapped, query), (
                "the swap must not change the answer, or Definition 1 does not apply"
            )

    a = real_server_view(
        config, len(queries), 0,
        str(_prepare(tmp_path, config, edges, queries, "orig")))
    b = real_server_view(
        config, len(queries), 0,
        str(_prepare(tmp_path, config, swapped, queries, "swap")))

    verdict = views_are_indistinguishable(a, b)
    assert verdict["indistinguishable"], verdict
    # The share values differ -- they are uniform -- but nothing observable does.
    assert a.private_input != b.private_input


def test_simulated_input_length_is_the_declared_one(config: RelationPageConfig):
    for query_count in (1, 3, 10):
        view = simulate_server_view(config, query_count, 1)
        assert len(view.private_input) == expected_private_input_values(
            config, query_count
        )


def test_shares_are_uniform_in_the_field(config: RelationPageConfig):
    """Any two of three additive shares must carry no information."""

    view = simulate_server_view(config, 2, 0)
    prime = config.base.field_prime
    assert all(0 <= value < prime for value in view.private_input)
    # A degenerate simulator returning constants would pass everything else.
    assert len(set(view.private_input)) > len(view.private_input) // 2


def test_every_server_sees_the_same_circuit(config: RelationPageConfig):
    views = [simulate_server_view(config, 2, s) for s in range(3)]
    assert len({v.circuit for v in views}) == 1
    assert len({len(v.private_input) for v in views}) == 1


def test_invalid_server_is_refused(config: RelationPageConfig):
    with pytest.raises(ValueError, match="server must be"):
        simulate_server_view(config, 1, 3)
    with pytest.raises(ValueError, match="server must be"):
        real_server_view(config, 1, -1, "unused")


def test_comparison_excludes_share_values_deliberately(config: RelationPageConfig):
    """Requiring equal shares would demand the simulator guess, not simulate."""

    first = simulate_server_view(config, 1, 0)
    second = simulate_server_view(config, 1, 0)
    assert first.private_input != second.private_input
    assert views_are_indistinguishable(first, second)["indistinguishable"]
    assert "uniform in both" in views_are_indistinguishable(first, second)["note"]
