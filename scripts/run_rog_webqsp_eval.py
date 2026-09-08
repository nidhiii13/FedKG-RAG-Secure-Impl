#!/usr/bin/env python3
"""Evaluate the relation-paged retrieval core on RoG-WebQSP test subgraphs.

RoG-WebQSP does not ship the authoritative WebQSP semantic parse in each JSONL
record.  This runner therefore derives one deterministic two-hop relation pair
that reaches a gold answer.  It is an *oracle-path retrieval-core* evaluation,
not natural-language parsing accuracy.  All selected records are unioned before
one fixed fixture is built, so the servers do not receive a query-specific KG.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.evidence_handles import handles_leak_owner  # noqa: E402
from doram_t2_3pc.rag_bridge import (  # noqa: E402
    build_handle_resolver,
    evidence_hit,
    query_graph_to_hops,
    rows_to_evidence,
)
from doram_t2_3pc.relation_pages import (  # noqa: E402
    RelationPageConfig,
    build_owner_page_layout,
    check_global_frontier,
    evaluate_paged_cleartext,
)
from scripts.run_rag_eval import build_fixture, plaintext_rate, wilson  # noqa: E402


DEFAULT_INPUT = Path(
    ROOT.parent / "SimGRAG/data/raw/rog_webqsp/test.jsonl"
)


def inverse_relation(relation: str) -> str:
    return relation[:-8] if relation.endswith("_inverse") else relation + "_inverse"


def local_adjacency(graph: list[list[Any]]) -> dict[str, list[tuple[str, str]]]:
    adjacency: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for raw_head, raw_relation, raw_tail in graph:
        head, relation, tail = str(raw_head), str(raw_relation), str(raw_tail)
        adjacency[head].add((relation, tail))
        adjacency[tail].add((inverse_relation(relation), head))
    return {node: sorted(edges) for node, edges in adjacency.items()}


def select_two_hop(row: dict[str, Any], strict: bool) -> dict[str, Any] | None:
    """Return one stable gold-reaching chain, or None when unsupported."""
    adjacency = local_adjacency(row.get("graph", []))
    sources = sorted({str(value) for value in row.get("q_entity", [])})
    answers = sorted(
        {str(value) for value in row.get("a_entity", [])}
        | {str(value) for value in row.get("answer", [])}
    )
    answer_set = set(answers)
    direct = any(
        target in answer_set
        for source in sources
        for _, target in adjacency.get(source, [])
    )
    if strict and direct:
        return None
    paths = sorted({
        (source, relation_1, middle, relation_2, target)
        for source in sources
        for relation_1, middle in adjacency.get(source, [])
        for relation_2, target in adjacency.get(middle, [])
        if target in answer_set and target not in sources
    })
    if not paths:
        return None
    source, relation_1, middle, relation_2, target = paths[0]
    return {
        "id": str(row.get("id", "")),
        "query": str(row["question"]),
        "groundtruths": answers,
        "query_graph": [
            [source, relation_1, "UNKNOWN"],
            ["UNKNOWN", relation_2, "ANSWER"],
        ],
        "oracle_path": [source, relation_1, middle, relation_2, target],
    }


def scan_compatible(path: Path, strict: bool) -> tuple[list[dict[str, Any]], int]:
    selected: list[dict[str, Any]] = []
    total = 0
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            total += 1
            row = json.loads(line)
            chosen = select_two_hop(row, strict)
            if chosen is not None:
                selected.append(chosen)
            if total % 200 == 0:
                print(f"  profiled {total} records; compatible {len(selected)}")
    return selected, total


def build_fixed_union(
    path: Path, selected_ids: set[str]
) -> tuple[dict[str, list[tuple[str, str]]], int]:
    adjacency: dict[str, set[tuple[str, str]]] = defaultdict(set)
    records = 0
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            row = json.loads(line)
            if str(row.get("id", "")) not in selected_ids:
                continue
            records += 1
            for raw_head, raw_relation, raw_tail in row.get("graph", []):
                head, relation, tail = str(raw_head), str(raw_relation), str(raw_tail)
                adjacency[head].add((relation, tail))
                adjacency[tail].add((inverse_relation(relation), head))
            if records % 200 == 0:
                print(f"  unioned {records}/{len(selected_ids)} selected subgraphs")
    fixed = {node: sorted(edges) for node, edges in adjacency.items()}
    directed_edges = sum(len(edges) for edges in fixed.values())
    return fixed, directed_edges


def partitioner(
    owners: int, method: str
) -> Callable[[list[str]], tuple[Callable[[str, str, str], int], int]]:
    def digest(value: str) -> int:
        return int.from_bytes(hashlib.sha256(value.encode("utf-8")).digest()[:8], "big")

    def configure(_: list[str]):
        if method == "subject-hash":
            def assign(head: str, relation: str, tail: str) -> int:
                del relation, tail
                return digest(str(head)) % owners
        else:
            def assign(head: str, relation: str, tail: str) -> int:
                # Keep a forward edge and its generated inverse at one owner.
                if relation.endswith("_inverse"):
                    head, relation, tail = tail, relation[:-8], head
                encoded = json.dumps((str(head), str(relation), str(tail)))
                return digest(encoded) % owners
        return assign, owners

    return configure


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--mode", choices=("strict", "compatible"), default="strict")
    parser.add_argument(
        "--questions", type=int, default=0,
        help="number sampled after compatibility filtering; 0 means all",
    )
    parser.add_argument("--owners", type=int, default=3)
    parser.add_argument(
        "--partition", choices=("subject-hash", "edge-hash"), default="subject-hash"
    )
    parser.add_argument("--bound", type=int, default=3)
    parser.add_argument("--topk", type=int, default=4)
    parser.add_argument("--neighbourhood-cap", type=int, default=10)
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if (args.questions < 0 or args.owners < 1 or args.bound < 1
            or args.topk < 1 or args.batch_size < 1):
        parser.error("questions must be non-negative; owners, bound and topk must be positive")

    started = time.time()
    args.out.mkdir(parents=True, exist_ok=True)
    compatible, total = scan_compatible(args.input, args.mode == "strict")
    available = len(compatible)
    if args.questions and args.questions < available:
        compatible = random.Random(args.seed).sample(compatible, args.questions)
    questions = compatible
    if not questions:
        raise SystemExit("no compatible questions selected")
    print(f"selected {len(questions)} of {available} compatible questions ({total} total)")

    adjacency, union_directed_edges = build_fixed_union(
        args.input, {row["id"] for row in questions}
    )
    print(
        f"fixed union: {len(adjacency):,} entities, "
        f"{union_directed_edges:,} directed edge records (including generated inverses)"
    )

    config, budgets, edges_available, edges_kept = build_fixture(
        questions,
        adjacency,
        args.out / "fixture",
        args.bound,
        args.neighbourhood_cap,
        args.seed,
        partitioner(args.owners, args.partition),
        args.topk,
    )
    paged = RelationPageConfig.load(args.out / "fixture" / "config_paged.json")
    owner_edges = {
        f"owner_{index}": json.loads(
            (args.out / "fixture" / f"owner_{index}.json").read_text(encoding="utf-8")
        )
        for index in range(args.owners)
    }
    resolver = build_handle_resolver(owner_edges)
    layout_started = time.time()
    prepared_layouts = {
        owner: build_owner_page_layout(paged, owner, owner_edges[owner])
        for owner in paged.base.owners
    }
    layout_seconds = time.time() - layout_started
    print(f"prepared {len(prepared_layouts)} owner layouts once in {layout_seconds:.2f}s")
    bound_report = check_global_frontier(paged, owner_edges)
    leak = handles_leak_owner(owner_edges, evidence_bits=50)

    per_question_path = args.out / "per_question.jsonl"
    completed_rows: list[dict[str, Any]] = []
    if args.resume and per_question_path.exists():
        for line in per_question_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("id"):
                completed_rows.append(row)
        print(f"resume: reusing {len(completed_rows)} completed query records")
    completed_ids = {str(row["id"]) for row in completed_rows}
    hits = sum(bool(row.get("hit")) for row in completed_rows)
    empty = sum(not row.get("evidence") for row in completed_rows)
    pending = [row for row in questions if row["id"] not in completed_ids]
    retrieval_started = time.time()
    mode = "a" if args.resume and per_question_path.exists() else "w"
    with per_question_path.open(mode, encoding="utf-8") as log:
        for batch_start in range(0, len(pending), args.batch_size):
            batch = pending[batch_start:batch_start + args.batch_size]
            batch_started = time.time()
            for row in batch:
                hops = query_graph_to_hops(row["query_graph"])
                evidence = rows_to_evidence(
                    evaluate_paged_cleartext(
                        paged,
                        owner_edges,
                        hops.as_query(),
                        prepared_layouts=prepared_layouts,
                    ),
                    resolver,
                )
                hit = bool(evidence_hit(evidence, row["groundtruths"]))
                hits += hit
                empty += not evidence
                log.write(json.dumps({
                    "id": row["id"],
                    "query": row["query"],
                    "groundtruths": row["groundtruths"],
                    "hops": hops.as_query(),
                    "oracle_path": row["oracle_path"],
                    "evidence": evidence,
                    "hit": hit,
                    "evaluation_scope": "oracle-path retrieval core",
                }, ensure_ascii=False) + "\n")
            log.flush()
            completed = len(completed_rows) + batch_start + len(batch)
            seconds = time.time() - batch_started
            print(
                f"  batch {completed-len(batch)}:{completed} complete in {seconds:.2f}s; "
                f"overall hit rate {100*hits/completed:.2f}%"
            )

    retrieval_seconds = time.time() - retrieval_started
    low, high = wilson(hits, len(questions))
    federation_bound = paged.pages.global_frontier or args.bound
    same_bound = plaintext_rate(questions, adjacency, config, federation_bound, args.topk)
    ceiling = plaintext_rate(questions, adjacency, config, None, None)
    rows = len(config["entities"]) * len(config["relations"])
    summary = {
        "dataset": "RoG-WebQSP",
        "evaluation_scope": "oracle-path retrieval core over one fixed selected-subgraph union",
        "not_semantic_parsing_accuracy": True,
        "mode": args.mode,
        "records_total": total,
        "compatible_available": available,
        "questions_sampled": len(questions),
        "evidence_hits": hits,
        "evidence_hit_rate": hits / len(questions),
        "evidence_hit_ci95": [low, high],
        "empty_retrievals": empty,
        "retrieval_seconds": retrieval_seconds,
        "layout_preparation_seconds": layout_seconds,
        "batch_size": args.batch_size,
        "fixed_union_entities": len(adjacency),
        "fixed_union_directed_edges_including_generated_inverses": union_directed_edges,
        "fixture": {
            "entities": len(config["entities"]),
            "relations": len(config["relations"]),
            "directory_rows": rows,
            "edges_available": edges_available,
            "edges_kept": edges_kept,
            "owners": args.owners,
            "partition": args.partition,
            "owner_key_counts": budgets,
            "owner_key_skew": max(budgets) / min(budgets) if min(budgets) else None,
            "global_frontier": paged.pages.global_frontier,
            "max_federation_degree": bound_report["max_key_degree_federation_wide"],
        },
        "bound": args.bound,
        "top_k": args.topk,
        "neighbourhood_cap": args.neighbourhood_cap,
        "plaintext_same_bound": same_bound,
        "plaintext_ceiling_unclipped": ceiling,
        # These are capacity/layout losses, not consequences of cryptographic
        # privacy itself.  In particular, ``ceiling`` is still evaluated on the
        # fixed workload fixture produced with ``neighbourhood_cap``.
        "fixture_ceiling_unclipped": ceiling,
        "loss_before_fixture_ceiling_points": 100 * (1.0 - ceiling),
        "bound_and_topk_loss_points": 100 * (ceiling - same_bound),
        "paged_vs_plaintext_same_bound_points": 100 * (
            same_bound - hits / len(questions)
        ),
        "handles_owner_blind": not leak["leaks"],
        "total_wall_seconds": time.time() - started,
    }
    (args.out / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"retrieval: {hits}/{len(questions)} = {100*hits/len(questions):.2f}% "
        f"95% CI [{100*low:.2f}%, {100*high:.2f}%]"
    )
    print(f"wrote {args.out / 'summary.json'} and per_question.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
