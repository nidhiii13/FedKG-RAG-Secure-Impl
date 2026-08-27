#!/usr/bin/env python3
"""Build a small CWQ two-hop workload-closure fixture for MP-SPDZ validation.

Selects N diverse strict-two-hop CWQ questions (spread across first-relation
Freebase domains, deterministically), builds their bounded neighbourhood
closure over the fixed union of the selected questions' RoG-CWQ subgraphs with
``scripts.run_rag_eval.build_fixture`` -- the exact fixture builder the
cleartext evaluation uses -- and writes the layout
``scripts/run_kqapro_relation_mpc.py`` consumes:

    config.json                 relation-paged MPC config
    owner_<i>.json              per-owner plaintext edges (sharded later)
    queries.json                the N secret (source, relation_1, relation_2)
    cleartext_validation.json   independent oracle output for every field
    capacity_report.json        scope statement and cost estimate

This is a controlled correctness/cost fixture over a public-query workload
closure; it is not full-dataset MPC execution.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.config import HE_SCALABLE_FIELD_PRIME  # noqa: E402
from doram_t2_3pc.rag_bridge import query_graph_to_hops  # noqa: E402
from doram_t2_3pc.relation_pages import (  # noqa: E402
    RelationPageConfig,
    check_global_frontier,
    evaluate_paged_cleartext,
    paged_cost_estimate,
)
from scripts.run_cwq_eval import build_fixed_union, load_compatible, partitioner  # noqa: E402
from scripts.run_rag_eval import build_fixture  # noqa: E402


def select_diverse(rows, count: int, seed: int):
    """Deterministic domain-diverse selection: round-robin over the Freebase
    domain of relation_1, seeded order inside each domain."""

    by_domain = defaultdict(list)
    for row in sorted(rows, key=lambda r: r["id"]):
        hops = query_graph_to_hops(row["query_graph"])
        base = hops.relation_1
        base = base[:-len("_inverse")] if base.endswith("_inverse") else base
        by_domain[base.split(".", 1)[0]].append(row)
    generator = random.Random(seed)
    for domain in by_domain:
        generator.shuffle(by_domain[domain])
    picked = []
    domains = sorted(by_domain)
    while len(picked) < count and any(by_domain[d] for d in domains):
        for domain in domains:
            if by_domain[domain] and len(picked) < count:
                picked.append(by_domain[domain].pop())
    return picked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compatible", type=Path,
                        default=ROOT / "data/cwq/twohop_compatible.jsonl")
    parser.add_argument("--raw", type=Path, default=ROOT / "data/cwq/raw")
    parser.add_argument("--splits", default="test,validation")
    parser.add_argument("--queries", type=int, default=10)
    parser.add_argument("--bound", type=int, default=8)
    parser.add_argument("--topk", type=int, default=4)
    parser.add_argument("--neighbourhood-cap", type=int, default=10)
    parser.add_argument("--owners", type=int, default=3)
    parser.add_argument("--partition", default="subject-hash",
                        choices=("subject-hash", "edge-hash", "relation-domain"))
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    splits = [s.strip() for s in args.splits.split(",") if s.strip()]

    rows = load_compatible(args.compatible, splits)
    picked = select_diverse(rows, args.queries, args.seed)
    print(f"selected {len(picked)} diverse questions "
          f"({len({r['id'] for r in picked})} unique ids)")
    adjacency, _, forward = build_fixed_union(
        args.raw, splits, {row["id"] for row in picked}
    )
    print(f"union over selected subgraphs: {len(adjacency):,} entities, "
          f"{forward:,} forward edges")

    args.out.mkdir(parents=True, exist_ok=True)
    config_doc, budgets, edges_available, edges_kept = build_fixture(
        picked, adjacency, args.out, args.bound, args.neighbourhood_cap,
        args.seed, partitioner(args.owners, args.partition), args.topk,
    )
    (args.out / "config_paged.json").rename(args.out / "config.json")
    # Temi is an HE-based protocol and requires field_prime == 1 mod 32768;
    # swap the Mersenne prime build_fixture writes for the audited HE field.
    config_json = json.loads((args.out / "config.json").read_text(encoding="utf-8"))
    config_json["field_prime"] = HE_SCALABLE_FIELD_PRIME
    (args.out / "config.json").write_text(
        json.dumps(config_json, indent=1) + "\n", encoding="utf-8"
    )
    config = RelationPageConfig.load(args.out / "config.json")
    owner_edges = {
        f"owner_{index}": json.loads(
            (args.out / f"owner_{index}.json").read_text(encoding="utf-8")
        )
        for index in range(args.owners)
    }

    queries = []
    records = []
    for row in picked:
        hops = query_graph_to_hops(row["query_graph"])
        oracle = evaluate_paged_cleartext(config, owner_edges, hops.as_query())
        queries.append(hops.as_query())
        records.append({
            "uid": row["id"],
            "question": row["query"],
            "groundtruths": row["groundtruths"],
            "query": hops.as_query(),
            "oracle_output": oracle,
        })
    (args.out / "queries.json").write_text(
        json.dumps(queries, indent=2) + "\n", encoding="utf-8"
    )
    (args.out / "cleartext_validation.json").write_text(json.dumps({
        "evaluation_label": (
            "CWQ 1.1 strict two-hop gold-SPARQL subset, "
            f"{len(picked)}-query workload closure"
        ),
        "records": records,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    frontier = check_global_frontier(config, owner_edges)
    report = {
        "fixture_semantics": (
            "bounded two-hop neighbourhood closure of "
            f"{len(picked)} public CWQ query anchors and gold-SPARQL relation "
            "pairs; no answer-based edge selection; synthetic "
            f"{args.owners}-owner {args.partition} split"
        ),
        "entities": len(config_doc["entities"]),
        "relations": len(config_doc["relations"]),
        "edges_available": edges_available,
        "edges_kept": edges_kept,
        "owner_key_counts": budgets,
        "bound": args.bound,
        "top_k": args.topk,
        "neighbourhood_cap": args.neighbourhood_cap,
        "global_frontier_check": frontier,
        "cost_per_query": paged_cost_estimate(config, 1),
        "cost_all_queries": paged_cost_estimate(config, len(picked)),
    }
    (args.out / "capacity_report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(f"fixture: {report['entities']:,} entities x {report['relations']:,} "
          f"relations, {edges_kept:,} edge rows kept")
    print(json.dumps(report["cost_all_queries"], indent=2)[:600])
    print(f"wrote fixture to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
