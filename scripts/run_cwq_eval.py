#!/usr/bin/env python3
"""Evaluate the relation-paged retrieval core on ComplexWebQuestions 1.1.

Question paths come from **gold SPARQL** (see ``scripts/profile_cwq.py``), so
unlike the RoG-WebQSP oracle-path runner this evaluation never consults gold
answers to choose a relation pair.  The graph is one fixed deduplicated union
of the RoG-CWQ subgraphs of the selected questions, built once before any
query executes; owners are synthetic deterministic partitions of that union.

Cleartext-oracle evaluation; the MPC path is exercised separately.
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

DEFAULT_COMPATIBLE = ROOT / "data/cwq/twohop_compatible.jsonl"
DEFAULT_RAW = ROOT / "data/cwq/raw"
INVERSE = "_inverse"


def inverse_relation(relation: str) -> str:
    return relation[:-len(INVERSE)] if relation.endswith(INVERSE) else relation + INVERSE


def base_edge(head: str, relation: str, tail: str) -> tuple[str, str, str]:
    """Canonical forward form, so an edge and its inverse share one owner."""
    if relation.endswith(INVERSE):
        return tail, relation[:-len(INVERSE)], head
    return head, relation, tail


def load_compatible(path: Path, splits: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("split") not in splits:
                continue
            qid = str(row["id"])
            if qid in seen:
                raise SystemExit(f"duplicate question id in compatible file: {qid}")
            seen.add(qid)
            rows.append({
                "id": qid,
                "split": row["split"],
                "query": row["question"],
                "groundtruths": row["groundtruths"],
                "query_graph": row["query_graph"],
                "anchor_mapping": row.get("anchor_mapping"),
            })
    return rows


def build_fixed_union(
    raw: Path, splits: list[str], selected_ids: set[str]
) -> tuple[dict[str, list[tuple[str, str]]], int, int]:
    adjacency: dict[str, set[tuple[str, str]]] = defaultdict(set)
    forward: set[tuple[str, str, str]] = set()
    matched = 0
    for split in splits:
        source = raw / f"rog_cwq_{split}.jsonl"
        with source.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                row = json.loads(line)
                if str(row.get("id", "")) not in selected_ids:
                    continue
                matched += 1
                for raw_head, raw_relation, raw_tail in row.get("graph", []):
                    head, relation, tail = str(raw_head), str(raw_relation), str(raw_tail)
                    forward.add((head, relation, tail))
                    adjacency[head].add((relation, tail))
                    adjacency[tail].add((inverse_relation(relation), head))
                if matched % 200 == 0:
                    print(f"  unioned {matched}/{len(selected_ids)} selected subgraphs")
    if matched != len(selected_ids):
        raise SystemExit(
            f"only {matched} of {len(selected_ids)} selected ids found in RoG files"
        )
    fixed = {node: sorted(edges) for node, edges in adjacency.items()}
    directed = sum(len(edges) for edges in fixed.values())
    return fixed, directed, len(forward)


def partitioner(owners: int, method: str):
    """Deterministic owner assignment; inverse edges follow their forward edge."""

    def digest(value: str) -> int:
        return int.from_bytes(hashlib.sha256(value.encode("utf-8")).digest()[:8], "big")

    def configure(_: list[str]):
        if method == "subject-hash":
            def assign(head: str, relation: str, tail: str) -> int:
                del relation, tail
                return digest(str(head)) % owners
        elif method == "edge-hash":
            def assign(head: str, relation: str, tail: str) -> int:
                encoded = json.dumps(base_edge(head, relation, tail))
                return digest(encoded) % owners
        else:  # relation-domain: Freebase domain prefix owns the edge
            def assign(head: str, relation: str, tail: str) -> int:
                _, base, _ = base_edge(head, relation, tail)
                return digest(base.split(".", 1)[0]) % owners
        return assign, owners

    return configure


def partition_statistics(
    config: dict[str, Any], owner_edges: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    per_owner_edges = {owner: len(rows) for owner, rows in owner_edges.items()}
    per_owner_keys = {
        owner: len({(row["source"], row["relation"]) for row in rows})
        for owner, rows in owner_edges.items()
    }
    key_owners: dict[tuple[str, str], set[str]] = defaultdict(set)
    for owner, rows in owner_edges.items():
        for row in rows:
            key_owners[(row["source"], row["relation"])].add(owner)
    spanning = sum(1 for owners in key_owners.values() if len(owners) > 1)
    counts = sorted(per_owner_edges.values())
    return {
        "owner_edge_counts": per_owner_edges,
        "owner_distinct_key_counts": per_owner_keys,
        "edge_volume_skew": (counts[-1] / counts[0]) if counts and counts[0] else None,
        "adjacency_keys_total": len(key_owners),
        "adjacency_keys_spanning_multiple_owners": spanning,
    }


def evidence_owner_stats(raw_rows: list[dict[str, Any]], resolver) -> dict[str, Any]:
    owners: set[str] = set()
    cross_owner_chain = False
    for row in raw_rows:
        if not row.get("valid"):
            continue
        left = resolver.get(int(row.get("left_evidence") or 0))
        right = resolver.get(int(row.get("right_evidence") or 0))
        pair = [x["owner"] for x in (left, right) if x is not None]
        owners.update(pair)
        if len(pair) == 2 and pair[0] != pair[1]:
            cross_owner_chain = True
    return {"contributing_owners": sorted(owners), "cross_owner_chain": cross_owner_chain}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compatible", type=Path, default=DEFAULT_COMPATIBLE)
    parser.add_argument("--raw", type=Path, default=DEFAULT_RAW)
    parser.add_argument("--splits", default="test,validation",
                        help="comma-separated held-out splits to include")
    parser.add_argument("--questions", type=int, default=0,
                        help="deterministic sample size; 0 means all compatible")
    parser.add_argument("--owners", type=int, default=3)
    parser.add_argument("--partition",
                        choices=("subject-hash", "edge-hash", "relation-domain"),
                        default="subject-hash")
    parser.add_argument("--bound", type=int, default=8)
    parser.add_argument("--topk", type=int, default=32)
    parser.add_argument("--neighbourhood-cap", type=int, default=50)
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if (args.questions < 0 or args.owners < 1 or args.bound < 1
            or args.topk < 1 or args.batch_size < 1):
        parser.error("questions must be non-negative; owners, bound, topk positive")
    splits = [s.strip() for s in args.splits.split(",") if s.strip()]

    started = time.time()
    args.out.mkdir(parents=True, exist_ok=True)
    questions = load_compatible(args.compatible, splits)
    available = len(questions)
    if args.questions and args.questions < available:
        questions = random.Random(args.seed).sample(questions, args.questions)
    if not questions:
        raise SystemExit("no compatible questions selected")
    print(f"selected {len(questions)} of {available} compatible questions "
          f"from splits {splits}")

    adjacency, union_directed, union_forward = build_fixed_union(
        args.raw, splits, {row["id"] for row in questions}
    )
    print(f"fixed union: {len(adjacency):,} entities, {union_forward:,} unique "
          f"forward edges, {union_directed:,} directed records incl. inverses")

    config, budgets, edges_available, edges_kept = build_fixture(
        questions, adjacency, args.out / "fixture",
        args.bound, args.neighbourhood_cap, args.seed,
        partitioner(args.owners, args.partition), args.topk,
    )
    paged = RelationPageConfig.load(args.out / "fixture" / "config_paged.json")
    owner_edges = {
        f"owner_{index}": json.loads(
            (args.out / "fixture" / f"owner_{index}.json").read_text(encoding="utf-8")
        )
        for index in range(args.owners)
    }
    partition_stats = partition_statistics(config, owner_edges)
    print(f"fixture: {len(config['entities']):,} entities x "
          f"{len(config['relations']):,} relations; {edges_kept:,} rows kept "
          f"of {edges_available:,} available; owner edges "
          f"{partition_stats['owner_edge_counts']}")
    resolver = build_handle_resolver(owner_edges)
    layout_started = time.time()
    prepared_layouts = {
        owner: build_owner_page_layout(paged, owner, owner_edges[owner])
        for owner in paged.base.owners
    }
    layout_seconds = time.time() - layout_started
    print(f"prepared {len(prepared_layouts)} owner layouts once "
          f"in {layout_seconds:.2f}s")
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
    multi_owner = sum(
        len(row.get("contributing_owners", [])) > 1 for row in completed_rows
    )
    cross_chains = sum(bool(row.get("cross_owner_chain")) for row in completed_rows)
    pending = [row for row in questions if row["id"] not in completed_ids]
    retrieval_started = time.time()
    mode = "a" if args.resume and per_question_path.exists() else "w"
    with per_question_path.open(mode, encoding="utf-8") as log:
        for batch_start in range(0, len(pending), args.batch_size):
            batch = pending[batch_start:batch_start + args.batch_size]
            batch_started = time.time()
            for row in batch:
                hops = query_graph_to_hops(row["query_graph"])
                raw_rows = evaluate_paged_cleartext(
                    paged, owner_edges, hops.as_query(),
                    prepared_layouts=prepared_layouts,
                )
                evidence = rows_to_evidence(raw_rows, resolver)
                owner_stats = evidence_owner_stats(raw_rows, resolver)
                hit = bool(evidence_hit(evidence, row["groundtruths"]))
                hits += hit
                empty += not evidence
                multi_owner += len(owner_stats["contributing_owners"]) > 1
                cross_chains += owner_stats["cross_owner_chain"]
                log.write(json.dumps({
                    "id": row["id"],
                    "split": row["split"],
                    "query": row["query"],
                    "groundtruths": row["groundtruths"],
                    "hops": hops.as_query(),
                    "evidence": evidence,
                    "hit": hit,
                    **owner_stats,
                    "evaluation_scope":
                        "gold-SPARQL two-hop retrieval core, cleartext oracle",
                }, ensure_ascii=False) + "\n")
            log.flush()
            completed = len(completed_rows) + batch_start + len(batch)
            seconds = time.time() - batch_started
            print(f"  batch {completed - len(batch)}:{completed} in {seconds:.2f}s; "
                  f"running hit rate {100 * hits / completed:.2f}%")

    retrieval_seconds = time.time() - retrieval_started
    total = len(questions)
    low, high = wilson(hits, total)
    federation_bound = paged.pages.global_frontier or args.bound
    same_bound = plaintext_rate(questions, adjacency, config, federation_bound, args.topk)
    ceiling = plaintext_rate(questions, adjacency, config, None, None)
    rows = len(config["entities"]) * len(config["relations"])
    summary = {
        "dataset": "ComplexWebQuestions 1.1 (RoG-CWQ graph snapshot)",
        "evaluation_scope": ("gold-SPARQL dependent two-hop retrieval core over one "
                             "fixed selected-subgraph union; cleartext oracle"),
        "relation_paths_from": "gold SPARQL logical forms, never gold answers",
        "results_are_mpc": False,
        "splits": splits,
        "compatible_available": available,
        "questions_sampled": total,
        "unique_ids": len({row["id"] for row in questions}),
        "duplicate_ids": total - len({row["id"] for row in questions}),
        "evidence_hits": hits,
        "evidence_hit_rate": hits / total,
        "evidence_hit_ci95": [low, high],
        "empty_retrievals": empty,
        "questions_with_multi_owner_evidence": multi_owner,
        "questions_with_cross_owner_chain": cross_chains,
        "retrieval_seconds": retrieval_seconds,
        "retrieval_seconds_per_query": retrieval_seconds / max(1, len(pending)),
        "layout_preparation_seconds": layout_seconds,
        "batch_size": args.batch_size,
        "seed": args.seed,
        "fixed_union_entities": len(adjacency),
        "fixed_union_unique_forward_edges": union_forward,
        "fixed_union_directed_records_incl_inverses": union_directed,
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
            **partition_stats,
            "global_frontier": paged.pages.global_frontier,
            "max_federation_degree": bound_report["max_key_degree_federation_wide"],
        },
        "bound": args.bound,
        "top_k": args.topk,
        "neighbourhood_cap": args.neighbourhood_cap,
        "plaintext_same_bound": same_bound,
        "fixture_ceiling_unclipped": ceiling,
        "loss_before_fixture_ceiling_points": 100 * (1.0 - ceiling),
        "bound_and_topk_loss_points": 100 * (ceiling - same_bound),
        "paged_vs_plaintext_same_bound_points": 100 * (same_bound - hits / total),
        "handles_owner_blind": not leak["leaks"],
        "owners_are_synthetic_partitions": True,
        "total_wall_seconds": time.time() - started,
    }
    (args.out / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(f"retrieval: {hits}/{total} = {100 * hits / total:.2f}% "
          f"95% CI [{100 * low:.2f}%, {100 * high:.2f}%]")
    print(f"plaintext same bound {100 * same_bound:.2f}%; "
          f"fixture ceiling {100 * ceiling:.2f}%")
    print(f"wrote {args.out / 'summary.json'} and per_question.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
