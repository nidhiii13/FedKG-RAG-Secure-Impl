#!/usr/bin/env python3
"""Materialise and evaluate LC-QuAD 2.0 strict two-hop rows.

This turns the compatibility export from ``profile_lcquad2.py`` into a real
retrieval-quality experiment:

1. take strict two-hop LC-QuAD rows;
2. ask Wikidata for the intermediate node and answer values;
3. build a small local KG fixture from those paths;
4. score the existing relation-paged retrieval oracle.

The result is a subset evaluation, not a full LC-QuAD result.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

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
    check_global_frontier,
    evaluate_paged_cleartext,
)
from scripts.run_rag_eval import build_fixture, entity_split, wilson  # noqa: E402


PREFIXES = """
PREFIX wd: <http://www.wikidata.org/entity/>
PREFIX wdt: <http://www.wikidata.org/prop/direct/>
PREFIX p: <http://www.wikidata.org/prop/>
PREFIX ps: <http://www.wikidata.org/prop/statement/>
PREFIX pq: <http://www.wikidata.org/prop/qualifier/>
PREFIX pr: <http://www.wikidata.org/prop/reference/>
"""


def as_prefixed(value: str) -> str:
    prefixes = {
        "http://www.wikidata.org/entity/": "wd:",
        "http://www.wikidata.org/prop/direct/": "wdt:",
        "http://www.wikidata.org/prop/": "p:",
        "http://www.wikidata.org/prop/statement/": "ps:",
        "http://www.wikidata.org/prop/qualifier/": "pq:",
        "http://www.wikidata.org/prop/reference/": "pr:",
    }
    for prefix, compact in prefixes.items():
        if value.startswith(prefix):
            return compact + value[len(prefix) :]
    return value


def binding_value(binding: dict[str, Any], name: str) -> str | None:
    found = binding.get(name)
    if not found:
        return None
    return as_prefixed(str(found.get("value", "")))


def triple_pattern(left: str, relation: str, right: str) -> str:
    if relation.endswith("_inverse"):
        return f"{right} {relation[:-8]} {left} ."
    return f"{left} {relation} {right} ."


def materialise_query(row: dict[str, Any], endpoint: str, limit: int, timeout: float) -> dict[str, Any]:
    hops = row["hops"]
    source = hops["source"]
    relation_1 = hops["relation_1"]
    relation_2 = hops["relation_2"]
    where = "\n".join([
        triple_pattern(source, relation_1, "?mid"),
        triple_pattern("?mid", relation_2, "?answer"),
    ])
    query = f"{PREFIXES}\nSELECT ?mid ?answer WHERE {{\n{where}\n}} LIMIT {limit}"
    payload = urllib.parse.urlencode({"query": query, "format": "json"}).encode()
    request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Accept": "application/sparql-results+json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "FedKG-RAG-Secure-Impl/LC-QuAD-eval",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        decoded = json.loads(response.read().decode("utf-8"))
    paths = []
    answers = []
    for binding in decoded.get("results", {}).get("bindings", []):
        mid = binding_value(binding, "mid")
        answer = binding_value(binding, "answer")
        if mid and answer:
            paths.append({"mid": mid, "answer": answer})
            answers.append(answer)
    return {
        "uid": row.get("uid"),
        "query": row.get("question") or row.get("paraphrased_question") or "",
        "query_graph": row["query_graph"],
        "hops": hops,
        "groundtruths": sorted(set(answers)),
        "paths": paths,
        "path_count": len(paths),
    }


def load_rows(path: Path, include_residual: bool) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("semantic_residual") and not include_residual:
            continue
        rows.append(row)
    return rows


def materialise_rows(
    rows: list[dict[str, Any]],
    out: Path,
    endpoint: str,
    sample: int,
    seed: int,
    per_query_limit: int,
    timeout: float,
    resume: bool,
    sleep: float,
) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    if sample <= 0 or sample >= len(rows):
        picked = list(rows)
        rng.shuffle(picked)
    else:
        picked = rng.sample(rows, sample)
    materialised = []
    seen: set[str] = set()
    if resume and out.exists():
        materialised = load_materialised(out)
        for record in materialised:
            seen.add(str(record.get("uid")))
        print(f"resuming from {out}: {len(materialised):,} existing rows")
    errors: Counter[str] = Counter()
    with out.open("a" if resume else "w", encoding="utf-8") as handle:
        for index, row in enumerate(picked, start=1):
            uid = str(row.get("uid"))
            if uid in seen:
                continue
            try:
                record = materialise_query(row, endpoint, per_query_limit, timeout)
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                errors[type(exc).__name__] += 1
                record = {
                    "uid": row.get("uid"),
                    "query": row.get("question"),
                    "query_graph": row.get("query_graph"),
                    "hops": row.get("hops"),
                    "groundtruths": [],
                    "paths": [],
                    "error": type(exc).__name__,
                }
            materialised.append(record)
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            seen.add(uid)
            if index % 25 == 0:
                answered = sum(1 for item in materialised if item.get("paths"))
                print(f"  materialised {index}/{len(picked)}  non-empty {answered}  errors {sum(errors.values())}")
            if sleep > 0:
                time.sleep(sleep)
    if errors:
        print(f"materialisation errors: {dict(errors.most_common())}")
    return materialised


def load_materialised(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def add_edge(adjacency: dict[str, list[tuple[str, str]]], head: str, relation: str, tail: str) -> None:
    adjacency[head].append((relation, tail))
    adjacency[tail].append((relation + "_inverse", head))


def build_adjacency(records: list[dict[str, Any]]) -> dict[str, list[tuple[str, str]]]:
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for record in records:
        hops = record["hops"]
        source = hops["source"]
        for path in record.get("paths", []):
            mid = path["mid"]
            answer = path["answer"]
            add_edge(adjacency, source, hops["relation_1"], mid)
            add_edge(adjacency, mid, hops["relation_2"], answer)
    for key in list(adjacency):
        adjacency[key] = sorted(set(adjacency[key]))
    return adjacency


def evaluate(records: list[dict[str, Any]], out: Path, args: argparse.Namespace) -> dict[str, Any]:
    questions = [
        {
            "query": row["query"],
            "groundtruths": row["groundtruths"],
            "query_graph": row["query_graph"],
        }
        for row in records
        if row.get("paths") and row.get("groundtruths")
    ]
    if not questions:
        raise SystemExit("no materialised LC-QuAD rows with answers; cannot evaluate")

    adjacency = build_adjacency(records)
    config, budgets, edges_available, edges_kept = build_fixture(
        questions,
        adjacency,
        out / "fixture",
        args.bound,
        args.neighbourhood_cap,
        args.seed,
        entity_split,
    )
    owner_count = len(budgets)
    rows = len(config["entities"]) * len(config["relations"])
    print(f"fixture: {len(config['entities']):,} entities, "
          f"{len(config['relations']):,} relations, {edges_available:,} edges "
          f"({edges_kept:,} kept at bound {args.bound})")
    print(f"directory: {rows:,} dense rows, {100*edges_available/rows:.2f}% occupied")
    print(f"federation: {owner_count} owners, B_i={budgets} "
          f"skew={max(budgets)/min(budgets):.2f}x")

    paged = RelationPageConfig.load(out / "fixture" / "config_paged.json")
    owner_edges = {
        f"owner_{i}": json.loads((out / "fixture" / f"owner_{i}.json").read_text())
        for i in range(owner_count)
    }
    leak = handles_leak_owner(owner_edges, evidence_bits=50)
    bound_report = check_global_frontier(paged, owner_edges)
    print(f"handles: {'LEAK' if leak['leaks'] else 'owner-blind'}   "
          f"global_frontier {paged.pages.global_frontier} verified "
          f"(max federation degree {bound_report['max_key_degree_federation_wide']})")

    resolver = build_handle_resolver(owner_edges)
    hits = empty = 0
    started = time.time()
    with (out / "per_question.jsonl").open("w", encoding="utf-8") as log:
        for index, row in enumerate(questions, start=1):
            hops = query_graph_to_hops(row["query_graph"])
            evidence = rows_to_evidence(
                evaluate_paged_cleartext(paged, owner_edges, hops.as_query()),
                resolver,
            )
            hit = evidence_hit(evidence, row["groundtruths"])
            hits += hit
            empty += not evidence
            log.write(json.dumps({
                "query": row["query"],
                "groundtruths": row["groundtruths"],
                "hops": hops.as_query(),
                "evidence": evidence,
                "hit": bool(hit),
            }, ensure_ascii=False) + "\n")
            if index % 25 == 0:
                print(f"  {index}/{len(questions)}  running hit rate {100*hits/index:.1f}%")

    low, high = wilson(hits, len(questions))
    summary = {
        "dataset": "lc_quad_2_0",
        "scope": "strict two-hop materialised Wikidata subset",
        "questions_materialised": len(records),
        "questions_scored": len(questions),
        "empty_retrievals": empty,
        "evidence_hits": hits,
        "evidence_hit_rate": round(hits / len(questions), 4),
        "evidence_hit_ci95": [round(low, 4), round(high, 4)],
        "retrieval_seconds": round(time.time() - started, 1),
        "bound": args.bound,
        "top_k": args.topk,
        "seed": args.seed,
        "fixture": {
            "entities": len(config["entities"]),
            "relations": len(config["relations"]),
            "directory_rows": rows,
            "directory_occupancy": round(edges_available / rows, 6) if rows else 0,
            "edges_available": edges_available,
            "edges_kept": edges_kept,
            "owners": owner_count,
            "B_i": budgets,
            "global_frontier": paged.pages.global_frontier,
            "volume_skew": round(max(budgets) / min(budgets), 2),
        },
        "handles_owner_blind": not leak["leaks"],
        "scored_with": "cleartext relation-paged oracle over materialised LC-QuAD subset",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(f"\nretrieval: {hits}/{len(questions)} = {100*hits/len(questions):.2f}%  "
          f"95% CI [{100*low:.2f}%, {100*high:.2f}%]")
    print(f"wrote {out / 'summary.json'} and per_question.jsonl")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query-graphs", type=Path,
                        default=Path("data/lc_quad2/lcquad2_twohop_query_graphs.jsonl"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--materialized", type=Path, default=None,
                        help="Reuse a previous materialized JSONL instead of querying Wikidata")
    parser.add_argument("--endpoint", default="https://query.wikidata.org/sparql")
    parser.add_argument("--questions", type=int, default=100,
                        help="number of compatible rows to materialise; use 0 for all")
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument("--per-query-limit", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--resume", action="store_true",
                        help="append to/reuse --out/materialized.jsonl if it already exists")
    parser.add_argument("--sleep", type=float, default=0.0,
                        help="seconds to sleep between SPARQL requests")
    parser.add_argument("--include-residual", action="store_true")
    parser.add_argument("--bound", type=int, default=3)
    parser.add_argument("--topk", type=int, default=4)
    parser.add_argument("--neighbourhood-cap", type=int, default=10)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    if args.materialized is None:
        rows = load_rows(args.query_graphs, args.include_residual)
        print(f"loaded {len(rows):,} LC-QuAD rows from {args.query_graphs}")
        materialized_path = args.out / "materialized.jsonl"
        records = materialise_rows(
            rows,
            materialized_path,
            args.endpoint,
            args.questions,
            args.seed,
            args.per_query_limit,
            args.timeout,
            args.resume,
            args.sleep,
        )
        print(f"wrote {materialized_path}")
    else:
        records = load_materialised(args.materialized)
        print(f"loaded {len(records):,} materialized rows from {args.materialized}")

    evaluate(records, args.out, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
