"""Tests for the raw-dataset capacity planner and the experimental
relation-paged adjacency layout.

The layout is an experimental backend. These tests pin down the two properties
a paper claim would rest on: it is lossless up to its declared public bounds
(and fails closed otherwise), and its cleartext semantics agree with the
independent oracle of the supported packed-scan backend.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from doram_t2_3pc.capacity_planning import (
    bound_overflow,
    degree_profile,
    page_amplification,
    plan_owner_capacity,
    retention,
)
from doram_t2_3pc.reference import evaluate_cleartext
from doram_t2_3pc.relation_pages import (
    RelationPageConfig,
    RelationPageParameters,
    build_owner_page_layout,
    evaluate_paged_cleartext,
    owner_layout_report,
    paged_cost_estimate,
    relation_split_cost_advantage,
)


FIXTURE = Path("doram_t2_3pc/examples/ten_query")


def _owner_edges() -> dict[str, list[dict]]:
    return {
        owner: json.loads((FIXTURE / f"{owner}.json").read_text())
        for owner in ("owner_a", "owner_b", "owner_c")
    }


def _paged_config(tmp_path: Path, **layout) -> RelationPageConfig:
    raw = json.loads((FIXTURE / "config_scalable.json").read_text())
    raw["relation_page_layout"] = {
        "page_size": 2,
        "pages_per_key": 1,
        "page_budget": 16,
        **layout,
    }
    path = tmp_path / "config_paged.json"
    path.write_text(json.dumps(raw))
    return RelationPageConfig.load(path)


# --------------------------------------------------------------------------
# Capacity planning on raw, unbounded datasets
# --------------------------------------------------------------------------


def test_degree_profile_separates_source_and_source_relation_degree():
    edges = [
        {"source": "a", "relation": "r1", "target": "t1"},
        {"source": "a", "relation": "r1", "target": "t2"},
        {"source": "a", "relation": "r2", "target": "t3"},
        {"source": "b", "relation": "r1", "target": "t4"},
    ]
    profile = degree_profile(edges)
    assert profile["edge_count"] == 4
    assert profile["max_source_degree"] == 3
    assert profile["max_source_relation_degree"] == 2
    assert profile["distinct_source_relation_keys"] == 3
    # This ratio is the whole reason the paged layout can be narrower.
    assert profile["relation_split_reduction_factor"] == pytest.approx(1.5)


def test_degree_profile_accepts_raw_triples_without_evidence_or_score():
    # A raw dataset can be profiled before handles/scores are assigned.
    profile = degree_profile([{"source": "a", "relation": "r", "target": "b"}])
    assert profile["edge_count"] == 1


def test_degree_profile_rejects_malformed_rows():
    with pytest.raises(ValueError, match="missing required key"):
        degree_profile([{"source": "a", "relation": "r"}])
    with pytest.raises(ValueError, match="non-empty string"):
        degree_profile([{"source": "a", "relation": "r", "target": ""}])


def test_bound_overflow_reports_what_a_capped_builder_would_drop():
    edges = [
        {"source": "a", "relation": "r1", "target": f"t{i}"} for i in range(5)
    ] + [{"source": "b", "relation": "r1", "target": "t9"}]
    report = bound_overflow(edges, fanout_per_owner=2)
    assert report["fits_declared_capacity"] is False
    assert report["source_overflow_bucket_count"] == 1
    assert report["source_overflow_edge_count"] == 3
    # Source "a" keeps 2 of 5, source "b" keeps its single edge.
    assert report["upper_bound_retained_edge_count"] == 3
    assert report["upper_bound_retained_edge_fraction"] == pytest.approx(0.5)


def test_bound_overflow_applies_the_binding_bound_per_source():
    # Two relations of two edges each: the relation bound keeps 1 per relation
    # (2 total), and the source bound of 3 is then not binding.
    edges = [
        {"source": "a", "relation": rel, "target": f"t{i}"}
        for rel in ("r1", "r2")
        for i in range(2)
    ]
    report = bound_overflow(
        edges, fanout_per_owner=3, relation_fanout_per_owner=1
    )
    assert report["upper_bound_retained_edge_count"] == 2
    assert report["source_relation_overflow_edge_count"] == 2


def test_bound_overflow_rejects_relation_bound_above_source_bound():
    with pytest.raises(ValueError, match="must not exceed"):
        bound_overflow(
            [], fanout_per_owner=2, relation_fanout_per_owner=4
        )


def test_page_amplification_measures_padding_and_losslessness():
    edges = [
        {"source": "a", "relation": "r1", "target": f"t{i}"} for i in range(3)
    ]
    tight = page_amplification(edges, page_size=1, pages_per_key=3)
    assert tight["pages_needed"] == 3
    assert tight["slot_amplification"] == pytest.approx(1.0)
    assert tight["lossless_at_this_bound"] is True

    # One page of size 4 stores all three edges but wastes a slot.
    padded = page_amplification(edges, page_size=4, pages_per_key=1)
    assert padded["pages_needed"] == 1
    assert padded["slot_amplification"] == pytest.approx(4 / 3)
    assert padded["lossless_at_this_bound"] is True

    # A single page of size 2 cannot hold three edges.
    overflowing = page_amplification(edges, page_size=2, pages_per_key=1)
    assert overflowing["lossless_at_this_bound"] is False
    assert overflowing["key_overflow_count"] == 1
    assert overflowing["overflow_edge_count"] == 1
    assert overflowing["max_pages_required_by_any_key"] == 2


def test_retention_compares_raw_and_bounded_files():
    raw = [
        {"source": "a", "relation": "r", "target": f"t{i}"} for i in range(4)
    ]
    report = retention(raw, raw[:2])
    assert report["retained_edge_fraction"] == pytest.approx(0.5)
    assert report["raw_triples_dropped"] == 2
    assert report["bounded_triples_absent_from_raw"] == 0


def test_plan_owner_capacity_finds_smallest_lossless_page_size():
    edges = [
        {"source": "a", "relation": "r1", "target": f"t{i}"} for i in range(3)
    ]
    plan = plan_owner_capacity(
        edges, candidate_page_sizes=(1, 2, 4), pages_per_key=1
    )
    assert plan["audit_scope"] == "supplied_file_only"
    assert plan["smallest_lossless_relation_page_size"] == 4
    assert plan["degree_profile"]["max_source_relation_degree"] == 3


def test_plan_owner_capacity_reports_none_when_no_candidate_is_lossless():
    edges = [
        {"source": "a", "relation": "r1", "target": f"t{i}"} for i in range(9)
    ]
    plan = plan_owner_capacity(
        edges, candidate_page_sizes=(1, 2), pages_per_key=1
    )
    assert plan["smallest_lossless_relation_page_size"] is None


# --------------------------------------------------------------------------
# Relation-paged layout
# --------------------------------------------------------------------------


def test_page_parameters_reject_degenerate_budgets():
    with pytest.raises(ValueError, match="page_budget must reserve"):
        RelationPageParameters(page_size=2, pages_per_key=1, page_budget=1).validate()
    with pytest.raises(ValueError, match="must be positive"):
        RelationPageParameters(page_size=0, pages_per_key=1, page_budget=8).validate()


def test_paged_config_requires_the_layout_block(tmp_path: Path):
    raw = json.loads((FIXTURE / "config_scalable.json").read_text())
    path = tmp_path / "no_layout.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="requires a relation_page_layout"):
        RelationPageConfig.load(path)


def test_directory_address_is_an_affine_function_of_the_secret_pair(
    tmp_path: Path,
):
    config = _paged_config(tmp_path)
    relations = config.relation_count
    # The circuit computes source * relation_count + (relation - 1); the
    # mapping must be injective so no two keys collide in the directory.
    seen = set()
    for source in range(config.base.entity_count):
        for relation in range(1, relations + 1):
            index = config.directory_index(source, relation)
            assert index == source * relations + (relation - 1)
            assert index not in seen
            seen.add(index)
    assert len(seen) == config.directory_rows


def test_descriptor_packing_round_trips(tmp_path: Path):
    config = _paged_config(tmp_path, page_budget=64, pages_per_key=3)
    for page_base in (0, 1, 63):
        for page_count in (0, 1, 3):
            packed = config.pack_descriptor(page_base, page_count)
            assert config.unpack_descriptor(packed) == (page_base, page_count)


def test_owner_layout_is_lossless_and_pads_to_the_public_budget(tmp_path: Path):
    config = _paged_config(tmp_path)
    edges = _owner_edges()["owner_a"]
    layout = build_owner_page_layout(config, "owner_a", edges)
    report = owner_layout_report(layout, config)

    assert report["stored_edge_count"] == len(edges)
    assert len(layout.pages) == config.pages.page_budget
    assert len(layout.directory) == config.directory_rows
    # Page zero is the reserved dummy every absent key resolves to.
    assert layout.pages[0] == [0] * config.pages.page_size
    assert report["realized_page_count"] <= config.pages.page_budget


def test_layout_fails_closed_when_a_key_needs_too_many_pages(tmp_path: Path):
    config = _paged_config(tmp_path, page_size=1, pages_per_key=1)
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
    with pytest.raises(ValueError, match="pages_per_key"):
        build_owner_page_layout(config, "owner_a", edges)


def test_layout_fails_closed_when_the_page_budget_is_exhausted(tmp_path: Path):
    config = _paged_config(tmp_path, page_size=1, pages_per_key=1, page_budget=2)
    edges = [
        {
            "source": source,
            "relation": "referred_to",
            "target": "bob",
            "evidence": index + 1,
            "score": 1,
        }
        for index, source in enumerate(("alice", "carol"))
    ]
    with pytest.raises(ValueError, match="page_budget"):
        build_owner_page_layout(config, "owner_a", edges)


def test_layout_rejects_unknown_owner_and_ontology(tmp_path: Path):
    config = _paged_config(tmp_path)
    with pytest.raises(ValueError, match="unknown owner"):
        build_owner_page_layout(config, "nobody", [])
    with pytest.raises(ValueError, match="unknown ontology item"):
        build_owner_page_layout(
            config,
            "owner_a",
            [
                {
                    "source": "not_an_entity",
                    "relation": "referred_to",
                    "target": "bob",
                    "evidence": 1,
                    "score": 1,
                }
            ],
        )


def test_multi_page_overflow_stores_every_edge(tmp_path: Path):
    # Three edges under one (source, relation) key with page_size 2 must use
    # two pages and lose nothing.
    config = _paged_config(tmp_path, page_size=2, pages_per_key=2)
    edges = [
        {
            "source": "alice",
            "relation": "referred_to",
            "target": target,
            "evidence": index + 1,
            "score": 1,
        }
        for index, target in enumerate(("bob", "carol", "dave"))
    ]
    layout = build_owner_page_layout(config, "owner_a", edges)
    assert owner_layout_report(layout, config)["stored_edge_count"] == 3
    base, count = config.unpack_descriptor(
        layout.directory[
            config.directory_index(
                config.base.entities["alice"], config.base.relations["referred_to"]
            )
        ]
    )
    assert count == 2
    stored = [
        value for page in layout.pages[base : base + count] for value in page
    ]
    assert sum(1 for value in stored if value != 0) == 3


@pytest.mark.parametrize("query_index", range(10))
def test_paged_oracle_matches_the_packed_scan_oracle(
    tmp_path: Path, query_index: int
):
    """Two independent layouts and two independent oracles must agree.

    The packed-scan reference walks per-source buckets and filters by relation;
    the paged reference resolves a (source, relation) directory and reads
    fixed-size pages. Agreement on every fixture query is meaningful
    cross-validation of the paged semantics.
    """

    config = _paged_config(tmp_path)
    owners = _owner_edges()
    query = json.loads((FIXTURE / "queries.json").read_text())[query_index]
    assert evaluate_paged_cleartext(config, owners, query) == evaluate_cleartext(
        config.base, owners, query
    )


def test_paged_oracle_rejects_incomplete_owner_sets_and_bad_queries(
    tmp_path: Path,
):
    config = _paged_config(tmp_path)
    owners = _owner_edges()
    with pytest.raises(ValueError, match="every configured owner"):
        evaluate_paged_cleartext(config, {"owner_a": owners["owner_a"]}, {})
    with pytest.raises(ValueError, match="source/relation_1/relation_2"):
        evaluate_paged_cleartext(config, owners, {"source": "alice"})


def test_paged_oracle_pads_missing_answers_to_top_k(tmp_path: Path):
    config = _paged_config(tmp_path)
    owners = _owner_edges()
    # A source with no outgoing referred_to edges yields no candidate at all.
    results = evaluate_paged_cleartext(
        config,
        owners,
        {"source": "cancer", "relation_1": "referred_to", "relation_2": "referred_to"},
    )
    assert len(results) == config.base.top_k
    assert all(row["valid"] == 0 for row in results)


def test_cost_estimate_exposes_the_dependent_read_tuning_knob(tmp_path: Path):
    config = _paged_config(tmp_path)
    full = paged_cost_estimate(config, 1)
    compacted = paged_cost_estimate(config, 1, compacted_frontier_slots=1)

    assert full["dependent_reads_per_query"] == full["frontier_slots"]
    assert compacted["dependent_reads_per_query"] == 1
    # The second hop dominates, so compaction must reduce total lookup cost.
    assert compacted["second_hop_products"] < full["second_hop_products"]
    assert compacted["total_lookup_products"] < full["total_lookup_products"]
    assert full["per_address_directory_products"] == (
        config.directory_rows * len(config.base.owners)
    )


def test_cost_estimate_rejects_an_out_of_range_compaction_bound(tmp_path: Path):
    config = _paged_config(tmp_path)
    slots = paged_cost_estimate(config, 1)["frontier_slots"]
    with pytest.raises(ValueError, match="compacted_frontier_slots"):
        paged_cost_estimate(config, 1, compacted_frontier_slots=slots + 1)
    with pytest.raises(ValueError, match="query_count must be positive"):
        paged_cost_estimate(config, 0)


def test_lossless_comparison_uses_the_fanout_the_scan_would_actually_need(
    tmp_path: Path,
):
    """The honest losslessness comparison, not a comparison against a cap.

    A packed scan that must represent a max-source-degree-D dataset needs
    fanout_per_owner = D, which widens every bucket. The paged layout only
    widens the keys that need it, so its advantage grows quadratically in D.
    """

    config = _paged_config(tmp_path)
    small = relation_split_cost_advantage(config, 4, 1)
    large = relation_split_cost_advantage(config, 64, 1)
    assert (
        large["paged_speedup_vs_lossless_packed_scan"]
        > small["paged_speedup_vs_lossless_packed_scan"]
    )
    assert large["lossless_packed_scan_block_edges"] == 64 * len(
        config.base.owners
    )
    with pytest.raises(ValueError, match="lossless_fanout_per_owner"):
        relation_split_cost_advantage(config, 0, 1)


def test_paged_layout_is_deterministic(tmp_path: Path):
    """Reproducible layouts keep digests and tie-breaking stable across owners."""

    config = _paged_config(tmp_path)
    edges = _owner_edges()["owner_c"]
    first = build_owner_page_layout(config, "owner_c", edges)
    shuffled = list(reversed(edges))
    second = build_owner_page_layout(config, "owner_c", shuffled)
    assert first.directory == second.directory
    assert first.pages == second.pages


def test_shipped_paged_example_config_builds_every_owner():
    """The documented fixture must stay loadable and lossless."""

    config = RelationPageConfig.load(FIXTURE / "config_relation_pages.json")
    owners = _owner_edges()
    for owner, edges in owners.items():
        layout = build_owner_page_layout(config, owner, edges)
        assert owner_layout_report(layout, config)["stored_edge_count"] == len(
            edges
        )
    query = json.loads((FIXTURE / "queries.json").read_text())[0]
    assert evaluate_paged_cleartext(config, owners, query) == evaluate_cleartext(
        config.base, owners, query
    )


def test_skewed_fixture_generator_realizes_the_declared_narrowing_factor():
    """The crossover experiment is only meaningful if the skew is what it says."""

    import argparse
    import sys

    sys.path.insert(0, "scripts")
    from build_skewed_fixture import build  # noqa: E402

    args = argparse.Namespace(
        entities=100,
        relations=8,
        owners=2,
        hub_sources=8,
        degree_per_relation=2,
        top_k=4,
        query_count=1,
    )
    built = build(args)
    profile = built["profile"]
    assert profile["narrowing_factor"] == 8
    assert profile["max_source_degree_per_owner"] == 16
    assert profile["max_source_relation_degree_per_owner"] == 2

    # Verify the claimed degrees against the emitted edges, not the arithmetic.
    for rows in built["owner_edges"].values():
        measured = degree_profile(rows)
        assert measured["max_source_degree"] == 16
        assert measured["max_source_relation_degree"] == 2
    # Both configurations must describe the same edges for a fair A/B.
    assert built["scan_config"]["entities"] == built["paged_config"]["entities"]
    assert (
        built["scan_config"]["fanout_per_owner"]
        == profile["max_source_degree_per_owner"]
    )
    assert (
        built["paged_config"]["relation_page_layout"]["page_size"]
        == profile["max_source_relation_degree_per_owner"]
    )


def test_crossover_and_null_result_benchmarks_are_reported_together():
    """Neither measurement may be published without the other.

    The paged layout wins on skew and loses without it. Reporting only the
    favourable fixture would misstate the contribution.
    """

    import json

    benchmarks = Path("doram_t2_3pc/benchmarks")
    crossover = json.loads((benchmarks / "relation_paged_crossover.json").read_text())
    null_result = json.loads(
        (benchmarks / "relation_paged_backend_ab.json").read_text()
    )
    assert "SLOWER" in null_result["headline_finding"]
    assert "1.15x SLOWER" in crossover["headline_finding"]
    assert crossover["correctness"]["paged_mpc_matches_scan_mpc"] is True
    assert crossover["what_this_does_not_show"]


def test_cost_model_script_flags_assumed_inputs_and_scope():
    """The recorded model must not read as a measurement."""

    import sys

    sys.path.insert(0, "scripts")
    from analyze_relation_page_layout import parse_args, sweep  # noqa: E402

    import argparse

    args = argparse.Namespace(
        entity_count=1000,
        relation_count=4,
        owner_count=2,
        query_count=1,
        top_k=2,
        lossless_max_source_degree=100,
        assumed_max_source_relation_degree=8,
        distinct_keys_per_owner=500,
        pages_per_key=1,
        page_sizes=[4, 8],
        compaction_slots=[1, 4],
    )
    result = sweep(args)
    assert "not a measurement" in result["model_kind"]
    assert result["scope_warning"]
    assert result["assumed_inputs_requiring_measurement"]["how_to_measure"]
    assert result["rows"]
    # A wider page is lossless but costs more; the model must show both.
    lossless = [row for row in result["rows"] if row["lossless_at_this_page_size"]]
    assert lossless
    for row in result["rows"]:
        assert row["paged_speedup_vs_lossless_packed_scan"] > 1
    assert callable(parse_args)


# --------------------------------------------------------------------------
# Federation-wide frontier compaction
#
# Without it the second hop dereferences owners * frontier_per_owner slots, so
# total cost is near quadratic in the size of the federation. With it the
# second hop is a fixed width and cost becomes linear in owners.
# --------------------------------------------------------------------------


def _disjoint_fixture(tmp_path, owners: int, coverage: int = 2, deg: int = 2):
    """Owners hold overlapping-but-not-identical key sets, as a federation does."""

    import json

    hubs, relations, entities = 4, 4, 60
    per_owner = [[] for _ in range(owners)]
    ev = 1
    for h in range(hubs):
        for r in range(relations):
            for c in range(coverage):
                o = (h * relations + r + c) % owners
                for d in range(deg):
                    per_owner[o].append({
                        "source": f"e{h}", "relation": f"r{r}",
                        "target": f"e{(h * 7 + r * 3 + d + 1) % entities}",
                        "evidence": ev, "score": d + 1 + r})
                    ev += 1
    cfg = {
        "owners": [f"owner_{i}" for i in range(owners)],
        "entities": {f"e{i}": i + 1 for i in range(entities)},
        "relations": {f"r{i}": i + 1 for i in range(relations)},
        "fanout_per_owner": relations * deg, "top_k": 4,
        "field_prime": 170141183460469231731687303715884105727,
        "relation_page_layout": {
            "page_size": deg, "pages_per_key": 1,
            "page_budget": hubs * relations + 1, "frontier_per_owner": deg},
    }
    a = tmp_path / f"per_owner_{owners}.json"
    a.write_text(json.dumps(cfg))
    glob = json.loads(json.dumps(cfg))
    glob["relation_page_layout"]["global_frontier"] = coverage * deg
    b = tmp_path / f"global_{owners}.json"
    b.write_text(json.dumps(glob))
    edges = {f"owner_{i}": per_owner[i] for i in range(owners)}
    return RelationPageConfig.load(a), RelationPageConfig.load(b), edges


def test_global_frontier_is_independent_of_federation_size(tmp_path):
    widths = set()
    for owners in (2, 3, 4, 6):
        _, glob, _ = _disjoint_fixture(tmp_path, owners)
        widths.add(glob.pages.frontier_slots(owners))
    assert len(widths) == 1, "global frontier must not grow with the federation"


def test_per_owner_frontier_does_grow_with_federation_size(tmp_path):
    """The behaviour the global bound exists to fix."""

    widths = [
        _disjoint_fixture(tmp_path, owners)[0].pages.frontier_slots(owners)
        for owners in (2, 3, 4, 6)
    ]
    assert widths == sorted(widths) and widths[0] < widths[-1]


@pytest.mark.parametrize("owners", (2, 3, 4, 6))
def test_global_frontier_preserves_semantics(tmp_path, owners: int):
    """Narrowing the frontier must not change a single returned row."""

    per_owner, glob, edges = _disjoint_fixture(tmp_path, owners)
    query = {"source": "e0", "relation_1": "r0", "relation_2": "r1"}
    assert evaluate_paged_cleartext(per_owner, edges, query) == \
        evaluate_paged_cleartext(glob, edges, query)


def test_global_frontier_check_rejects_an_understated_bound(tmp_path):
    """It bounds a cross-owner sum, so it must fail closed like the local one."""

    import json

    from doram_t2_3pc.relation_pages import check_global_frontier

    _, glob, edges = _disjoint_fixture(tmp_path, 4)
    report = check_global_frontier(glob, edges)
    assert report["headroom"] >= 0

    raw = json.loads((tmp_path / "global_4.json").read_text())
    raw["relation_page_layout"]["global_frontier"] = 1
    tight = tmp_path / "too_tight.json"
    tight.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="global_frontier"):
        check_global_frontier(RelationPageConfig.load(tight), edges)


def test_global_frontier_records_that_deployment_enforcement_is_missing(tmp_path):
    """No owner can verify a cross-owner sum alone; that gap must stay stated."""

    from doram_t2_3pc.relation_pages import check_global_frontier

    _, glob, edges = _disjoint_fixture(tmp_path, 3)
    assert "not implemented" in check_global_frontier(glob, edges)["enforcement"]
