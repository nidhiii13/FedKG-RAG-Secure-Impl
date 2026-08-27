import json
import sys
from collections import defaultdict

import pytest

from scripts.run_cwq_eval import (
    build_fixed_union,
    inverse_relation,
    load_compatible,
    main,
    partition_statistics,
    partitioner,
)


def write_jsonl(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def compatible_row(qid, anchor="A", r1="d1.t.r1", r2="d2.t.r2", split="test",
                   groundtruths=("Target",)):
    return {
        "id": qid, "split": split, "question": f"question {qid}",
        "groundtruths": list(groundtruths),
        "query_graph": [[anchor, r1, "UNKNOWN"], ["UNKNOWN", r2, "ANSWER"]],
        "anchor_mapping": "anchor_mid_in_graph",
    }


def rog_row(qid, graph):
    return {"id": qid, "question": f"question {qid}", "answer": ["Target"],
            "q_entity": ["A"], "a_entity": ["Target"], "graph": graph}


TINY_GRAPH = [
    ["A", "d1.t.r1", "M1"],
    ["M1", "d2.t.r2", "Target"],
    ["A", "d1.t.r1", "M2"],
    ["M2", "d2.t.r2", "Other"],
    ["Noise", "d3.t.r3", "A"],
]


def test_load_compatible_rejects_duplicates(tmp_path):
    path = tmp_path / "compatible.jsonl"
    write_jsonl(path, [compatible_row("q1"), compatible_row("q1")])
    with pytest.raises(SystemExit):
        load_compatible(path, ["test"])


def test_load_compatible_filters_splits(tmp_path):
    path = tmp_path / "compatible.jsonl"
    write_jsonl(path, [compatible_row("q1", split="test"),
                       compatible_row("q2", split="validation")])
    assert [r["id"] for r in load_compatible(path, ["test"])] == ["q1"]
    both = load_compatible(path, ["test", "validation"])
    assert [r["id"] for r in both] == ["q1", "q2"]


def test_build_fixed_union_is_deduplicated_and_bidirectional(tmp_path):
    write_jsonl(tmp_path / "rog_cwq_test.jsonl", [
        rog_row("q1", TINY_GRAPH),
        rog_row("q2", TINY_GRAPH),  # duplicate edges must not double
        rog_row("q3", [["X", "d9.t.r9", "Y"]]),  # unselected: excluded
    ])
    adjacency, directed, forward = build_fixed_union(
        tmp_path, ["test"], {"q1", "q2"}
    )
    assert forward == len(TINY_GRAPH)
    assert directed == 2 * len(TINY_GRAPH)
    assert ("d1.t.r1", "M1") in adjacency["A"]
    assert ("d1.t.r1_inverse", "A") in adjacency["M1"]
    assert "X" not in adjacency


def test_build_fixed_union_fails_on_missing_id(tmp_path):
    write_jsonl(tmp_path / "rog_cwq_test.jsonl", [rog_row("q1", TINY_GRAPH)])
    with pytest.raises(SystemExit):
        build_fixed_union(tmp_path, ["test"], {"q1", "missing"})


def test_partitioner_deterministic_and_inverse_consistent():
    for method in ("subject-hash", "edge-hash", "relation-domain"):
        assign, count = partitioner(4, method)([])
        assign2, _ = partitioner(4, method)([])
        assert count == 4
        owner = assign("H", "d1.t.r1", "T")
        assert owner == assign2("H", "d1.t.r1", "T")
        assert 0 <= owner < 4
        if method != "subject-hash":
            assert assign("T", "d1.t.r1_inverse", "H") == owner


def test_relation_domain_groups_by_domain():
    assign, _ = partitioner(8, "relation-domain")([])
    assert assign("H1", "music.artist.origin", "T1") == \
        assign("H2", "music.album.artist", "T2")


def test_partition_statistics_counts_spanning_keys():
    owner_edges = {
        "owner_0": [{"source": "A", "relation": "r", "target": "T1"}],
        "owner_1": [{"source": "A", "relation": "r", "target": "T2"},
                    {"source": "B", "relation": "r", "target": "T3"}],
    }
    stats = partition_statistics({}, owner_edges)
    assert stats["adjacency_keys_total"] == 2
    assert stats["adjacency_keys_spanning_multiple_owners"] == 1
    assert stats["owner_edge_counts"] == {"owner_0": 1, "owner_1": 2}
    assert stats["edge_volume_skew"] == 2.0


def test_inverse_relation_roundtrip():
    assert inverse_relation("a.b.c") == "a.b.c_inverse"
    assert inverse_relation("a.b.c_inverse") == "a.b.c"


def run_runner(tmp_path, out, extra=()):
    compatible = tmp_path / "compatible.jsonl"
    write_jsonl(compatible, [
        compatible_row("q1"),
        compatible_row("q2", r1="d1.t.r1", r2="d2.t.r2", groundtruths=["Other"]),
    ])
    write_jsonl(tmp_path / "rog_cwq_test.jsonl",
                [rog_row("q1", TINY_GRAPH), rog_row("q2", TINY_GRAPH)])
    argv = ["run_cwq_eval.py", "--compatible", str(compatible),
            "--raw", str(tmp_path), "--splits", "test",
            "--owners", "2", "--bound", "3", "--topk", "4",
            "--neighbourhood-cap", "10", "--batch-size", "1",
            "--out", str(out), *extra]
    old = sys.argv
    sys.argv = argv
    try:
        assert main() == 0
    finally:
        sys.argv = old


def independent_oracle(graph, anchor, r1, r2, groundtruths):
    """Trivial re-implementation: bounded two-hop reachability with inverses."""
    adjacency = defaultdict(set)
    for h, r, t in graph:
        adjacency[h].add((r, t))
        adjacency[t].add((r + "_inverse", h))
    found = {
        tail
        for rel1, mid in adjacency[anchor] if rel1 == r1
        for rel2, tail in adjacency[mid] if rel2 == r2
    }
    return bool(found & set(groundtruths))


def test_runner_end_to_end_matches_independent_oracle(tmp_path):
    out = tmp_path / "run"
    run_runner(tmp_path, out)
    per_question = {
        json.loads(line)["id"]: json.loads(line)
        for line in (out / "per_question.jsonl").read_text().splitlines()
    }
    assert set(per_question) == {"q1", "q2"}
    for qid, row in per_question.items():
        expected = independent_oracle(
            TINY_GRAPH, "A", "d1.t.r1", "d2.t.r2", row["groundtruths"]
        )
        assert row["hit"] == expected, qid
    summary = json.loads((out / "summary.json").read_text())
    assert summary["questions_sampled"] == 2
    assert summary["duplicate_ids"] == 0
    assert summary["evidence_hits"] == 2
    assert summary["paged_vs_plaintext_same_bound_points"] == 0.0


def test_runner_resume_skips_completed_and_keeps_totals(tmp_path):
    out = tmp_path / "run"
    run_runner(tmp_path, out)
    first = (out / "per_question.jsonl").read_text()
    run_runner(tmp_path, out, extra=("--resume",))
    second = (out / "per_question.jsonl").read_text()
    assert first == second  # nothing re-run, nothing duplicated
    summary = json.loads((out / "summary.json").read_text())
    assert summary["evidence_hits"] == 2
    assert summary["questions_sampled"] == 2


def test_prepared_layouts_equal_unprepared(tmp_path):
    from doram_t2_3pc.rag_bridge import query_graph_to_hops
    from doram_t2_3pc.relation_pages import (
        RelationPageConfig,
        build_owner_page_layout,
        evaluate_paged_cleartext,
    )
    out = tmp_path / "run"
    run_runner(tmp_path, out)
    paged = RelationPageConfig.load(out / "fixture" / "config_paged.json")
    owner_edges = {
        f"owner_{i}": json.loads((out / "fixture" / f"owner_{i}.json").read_text())
        for i in range(2)
    }
    prepared = {
        owner: build_owner_page_layout(paged, owner, owner_edges[owner])
        for owner in paged.base.owners
    }
    hops = query_graph_to_hops(
        [["A", "d1.t.r1", "UNKNOWN"], ["UNKNOWN", "d2.t.r2", "ANSWER"]]
    )
    with_layouts = evaluate_paged_cleartext(
        paged, owner_edges, hops.as_query(), prepared_layouts=prepared
    )
    without = evaluate_paged_cleartext(paged, owner_edges, hops.as_query())
    assert with_layouts == without
