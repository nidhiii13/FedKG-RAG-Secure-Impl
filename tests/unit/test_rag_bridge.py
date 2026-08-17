"""Tests for the query-graph to oblivious-retrieval bridge.

The project is named for RAG but every measurement in this package is
cryptographic cost. This bridge connects the existing SimGRAG pipeline to the
paged backend so retrieval QUALITY can be measured too. These tests pin the
mapping and, in particular, that an unrepresentable query graph is refused
rather than approximated -- silently mangling one would credit the evaluation
for retrieval that never happened.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from doram_t2_3pc.rag_bridge import (
    INVERSE_SUFFIX,
    Hops,
    UnsupportedQueryGraph,
    build_handle_resolver,
    evidence_hit,
    query_graph_to_hops,
    rows_to_evidence,
)


FIXTURE = Path("doram_t2_3pc/examples/ten_query")


def test_two_hop_chain_maps_to_the_backends_query():
    graph = [["Kismet", "acted in", "UNKNOWN"],
             ["UNKNOWN", "acted in", "A Foreign Affair"]]
    assert query_graph_to_hops(graph) == Hops("Kismet", "acted in", "acted in")
    assert query_graph_to_hops(graph).as_query() == {
        "source": "Kismet", "relation_1": "acted in", "relation_2": "acted in",
    }


def test_second_triple_is_accepted_in_either_orientation():
    forward = [["A", "r1", "UNKNOWN"], ["UNKNOWN", "r2", "B"]]
    reverse = [["A", "r1", "UNKNOWN"], ["B", "r2", "UNKNOWN"]]
    assert query_graph_to_hops(forward).relation_2 == "r2"
    # Traversed backwards, so the relation is inverted to match how the
    # adjacency materialises edges in both directions.
    assert query_graph_to_hops(reverse).relation_2 == "r2_inverse"


def test_webqsp_shapes_map_correctly():
    """WebQSP reverses the second hop, and sometimes anchors in the tail."""

    reversed_second = [
        ("Nick Clegg", "people.person.education", "UNKNOWN entity 1"),
        ("UNKNOWN answer 1", "education.field_of_study.students_majoring",
         "UNKNOWN entity 1"),
    ]
    hops = query_graph_to_hops(reversed_second)
    assert hops.source == "Nick Clegg"
    assert hops.relation_1 == "people.person.education"
    assert hops.relation_2 == "education.field_of_study.students_majoring_inverse"

    anchor_in_tail = [
        ("UNKNOWN entity 1", "award.award_honor.award", "Premier League Golden Boot"),
        ("UNKNOWN answer 1", "award.award_winner.awards_won", "UNKNOWN entity 1"),
    ]
    hops = query_graph_to_hops(anchor_in_tail)
    assert hops.source == "Premier League Golden Boot"
    assert hops.relation_1.endswith(INVERSE_SUFFIX)


def test_two_concrete_entities_prefer_the_uninverted_direction():
    """MetaQA graphs admit the path both ways; take the asked direction."""

    hops = query_graph_to_hops(
        [["Kismet", "acted in", "UNKNOWN"], ["UNKNOWN", "acted in", "A Foreign Affair"]]
    )
    assert hops.source == "Kismet"
    assert not hops.relation_1.endswith(INVERSE_SUFFIX)


@pytest.mark.parametrize("graph,reason", [
    ([["a", "r", "UNKNOWN"]], "two triples"),
    ([["a", "r", "UNKNOWN"]] * 3, "two triples"),
    # Two disconnected triples: no path from any concrete entity through a
    # variable and onward.
    ([["a", "r", "b"], ["c", "r2", "d"]], "two-hop path"),
    # All placeholders: nothing concrete to anchor on.
    ([["UNKNOWN", "r", "UNKNOWN x"], ["UNKNOWN x", "r2", "UNKNOWN y"]], "two-hop path"),
    ("not a graph", "two triples"),
])
def test_unrepresentable_graphs_are_refused(graph, reason: str):
    """Refusing is the point: the backend answers one fixed shape."""

    with pytest.raises(UnsupportedQueryGraph, match=reason):
        query_graph_to_hops(graph)


def test_malformed_triples_are_refused():
    with pytest.raises(UnsupportedQueryGraph, match="triple"):
        query_graph_to_hops([["a", "r"], ["UNKNOWN", "r2", "c"]])


def test_resolver_maps_handles_back_to_edges():
    edges = {
        owner: json.loads((FIXTURE / f"{owner}.json").read_text())
        for owner in ("owner_a", "owner_b", "owner_c")
    }
    resolver = build_handle_resolver(edges)
    total = sum(len(v) for v in edges.values())
    assert len(resolver) == total
    for owner, rows in edges.items():
        for edge in rows:
            found = resolver[edge["evidence"]]
            assert found["source"] == edge["source"]
            assert found["owner"] == owner


def test_invalid_padding_rows_are_dropped_not_reported_as_evidence():
    """The circuit pads its output to a fixed width; padding is not evidence."""

    resolver = {7: {"source": "A", "relation": "r", "target": "B"}}
    rows = [
        {"valid": 1, "left_evidence": 7, "right_evidence": 7, "score": 3},
        {"valid": 0, "left_evidence": 0, "right_evidence": 0, "score": 0},
    ]
    evidence = rows_to_evidence(rows, resolver)
    assert len(evidence) == 1
    assert evidence[0]["score"] == 3
    assert evidence[0]["edges"] == [["A", "r", "B"], ["A", "r", "B"]]


def test_unresolvable_handles_do_not_fabricate_edges():
    """A handle with no mapping must not become an empty or invented edge."""

    rows = [{"valid": 1, "left_evidence": 999, "right_evidence": 0, "score": 1}]
    assert rows_to_evidence(rows, {}) == []


def test_evidence_hit_matches_the_existing_runners_semantics():
    evidence = [{"score": 1, "edges": [["Kismet", "acted in", "Marlene Dietrich"]],
                 "reuse_nodes": []}]
    assert evidence_hit(evidence, ["Marlene Dietrich"]) is True
    assert evidence_hit(evidence, ["marlene dietrich"]) is True   # case-folded
    assert evidence_hit(evidence, ["Someone Else"]) is False
    assert evidence_hit(evidence, []) is False


def test_bridge_runs_on_the_real_metaqa_federation():
    """End to end on real data: query graph -> retrieval -> readable evidence."""

    from doram_t2_3pc.relation_pages import (
        RelationPageConfig, evaluate_paged_cleartext,
    )

    root = Path("/tmp/metaqa-ent")
    if not (root / "config_paged.json").is_file():
        pytest.skip("real MetaQA federation fixture not built in this environment")

    config = RelationPageConfig.load(root / "config_paged.json")
    edges = {
        f"owner_{i}": json.loads((root / f"owner_{i}.json").read_text())
        for i in range(3)
    }
    query = json.loads((root / "queries.json").read_text())[0]
    rows = evaluate_paged_cleartext(config, edges, query)
    evidence = rows_to_evidence(rows, build_handle_resolver(edges))

    assert evidence, "expected retrieval to return evidence"
    for item in evidence:
        assert item["edges"], "evidence must carry readable edges"
        for head, _, tail in item["edges"]:
            assert isinstance(head, str) and isinstance(tail, str)
