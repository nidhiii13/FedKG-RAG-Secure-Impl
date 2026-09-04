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


def relation_domain(row) -> str:
    """Return the Freebase domain of a row's first-hop relation."""

    hops = query_graph_to_hops(row["query_graph"])
    relation = hops.relation_1
    if relation.endswith("_inverse"):
        relation = relation[:-len("_inverse")]
    return relation.split(".", 1)[0]


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
    parser.add_argument(
        "--first-relation-domain",
        default=None,
        help=(
            "restrict the fixed workload to one public Freebase first-relation "
            "domain (for example, location); omitted means domain-diverse selection"
        ),
    )
    parser.add_argument(
        "--query-ids",
        type=Path,
        help=(
            "optional JSON list of exact question IDs to include, in the given "
            "order; when supplied, --queries is ignored"
        ),
    )
    parser.add_argument(
        "--relation-allowlist",
        type=Path,
        help=(
            "optional JSON list of directed relation identifiers; graph records "
            "outside this public vocabulary are excluded before closure building"
        ),
    )
    parser.add_argument(
        "--full-filtered-union",
        action="store_true",
        help=(
            "retain the complete selected-subgraph union after any relation "
            "filter instead of reducing it to a bounded workload closure"
        ),
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    splits = [s.strip() for s in args.splits.split(",") if s.strip()]

    rows = load_compatible(args.compatible, splits)
    if args.first_relation_domain is not None:
        rows = [
            row for row in rows
            if relation_domain(row) == args.first_relation_domain
        ]
        if not rows:
            raise SystemExit(
                "no compatible questions found for first-relation domain "
                f"{args.first_relation_domain!r}"
            )
    if args.query_ids is not None:
        requested = json.loads(args.query_ids.read_text(encoding="utf-8"))
        if not isinstance(requested, list) or not all(
            isinstance(value, str) for value in requested
        ):
            raise SystemExit("--query-ids must contain a JSON list of strings")
        if len(requested) != len(set(requested)):
            raise SystemExit("--query-ids contains duplicate question IDs")
        by_id = {row["id"]: row for row in rows}
        missing = [qid for qid in requested if qid not in by_id]
        if missing:
            raise SystemExit(
                f"{len(missing)} requested IDs are unavailable after split/domain "
                f"filtering; first missing ID: {missing[0]}"
            )
        picked = [by_id[qid] for qid in requested]
        selection_method = "explicit-query-id-manifest"
    else:
        picked = select_diverse(rows, args.queries, args.seed)
        selection_method = "seeded-domain-diverse"
    print(f"selected {len(picked)} diverse questions "
          f"({len({r['id'] for r in picked})} unique ids)")
    adjacency, _, forward = build_fixed_union(
        args.raw, splits, {row["id"] for row in picked}
    )
    print(f"union over selected subgraphs: {len(adjacency):,} entities, "
          f"{forward:,} forward edges")
    relation_allowlist = None
    if args.relation_allowlist is not None:
        allowed = json.loads(args.relation_allowlist.read_text(encoding="utf-8"))
        if not isinstance(allowed, list) or not all(
            isinstance(value, str) for value in allowed
        ):
            raise SystemExit(
                "--relation-allowlist must contain a JSON list of strings"
            )
        if len(allowed) != len(set(allowed)):
            raise SystemExit("--relation-allowlist contains duplicate relations")
        relation_allowlist = set(allowed)
        asked = {
            relation
            for row in picked
            for hops in [query_graph_to_hops(row["query_graph"])]
            for relation in (hops.relation_1, hops.relation_2)
        }
        missing = sorted(asked - relation_allowlist)
        if missing:
            raise SystemExit(
                "relation allowlist excludes a selected query relation: " + missing[0]
            )
        filtered_adjacency = {
            source: [
                (relation, target)
                for relation, target in records
                if relation in relation_allowlist
            ]
            for source, records in adjacency.items()
        }
        adjacency = defaultdict(list, filtered_adjacency)
        retained = sum(len(records) for records in adjacency.values())
        print(
            f"public relation filter: {len(relation_allowlist)} relations, "
            f"{retained:,} directed records retained"
        )

    args.out.mkdir(parents=True, exist_ok=True)
    config_doc, budgets, edges_available, edges_kept = build_fixture(
        picked, adjacency, args.out, args.bound, args.neighbourhood_cap,
        args.seed, partitioner(args.owners, args.partition), args.topk,
        full_union=args.full_filtered_union,
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
    evaluation_shape = (
        "complete public relation-filtered selected-subgraph union"
        if args.full_filtered_union
        else "bounded workload closure"
    )
    (args.out / "cleartext_validation.json").write_text(json.dumps({
        "evaluation_label": (
            "CWQ 1.1 strict two-hop gold-SPARQL subset, "
            f"{len(picked)} queries over a {evaluation_shape}"
        ),
        "records": records,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    frontier = check_global_frontier(config, owner_edges)
    report = {
        "fixture_semantics": (
            (
                "complete public relation-filtered union of the selected "
                f"{len(picked)} CWQ subgraphs"
                if args.full_filtered_union
                else (
                    "bounded two-hop neighbourhood closure of "
                    f"{len(picked)} public CWQ query anchors and gold-SPARQL "
                    "relation pairs"
                )
            )
            + "; no answer-based edge selection; synthetic "
            + f"{args.owners}-owner {args.partition} split"
        ),
        "first_relation_domain": args.first_relation_domain,
        "selection_method": selection_method,
        "graph_scope": (
            "complete-selected-subgraph-filtered-union"
            if args.full_filtered_union
            else "bounded-workload-closure"
        ),
        "query_id_manifest": str(args.query_ids) if args.query_ids else None,
        "relation_allowlist": (
            str(args.relation_allowlist) if args.relation_allowlist else None
        ),
        "relation_allowlist_size": (
            len(relation_allowlist) if relation_allowlist is not None else None
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
