#!/usr/bin/env python3
"""Prepare the reproducible domain-scoped 1,000-query CWQ MPC suite.

The suite takes the 61 relation identifiers occurring most often across both
hops of the 1,267 held-out compatible questions.  It retains questions whose
two relations are both in that vocabulary (1,002 questions), sorts them by
question ID, and selects the first 1,000.  Questions are then grouped by the
public domain of the first-hop relation.  One relation-paged workload closure
is built per domain so that each compiled circuit has a smaller public
directory than a single 61-relation union.

The first-hop domain is intentionally public in this experiment.  Exact entity
and relation identifiers, intermediate results, candidates, and returned
fields remain secret inputs/values during MPC.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.rag_bridge import query_graph_to_hops  # noqa: E402
from scripts.build_cwq_mpc_fixture import relation_domain  # noqa: E402
from scripts.run_cwq_eval import load_compatible  # noqa: E402


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def digest_ids(ids: list[str]) -> str:
    payload = json.dumps(ids, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--compatible",
        type=Path,
        default=ROOT / "data/cwq/twohop_compatible.jsonl",
    )
    parser.add_argument("--raw", type=Path, default=ROOT / "data/cwq/raw")
    parser.add_argument("--relations", type=int, default=61)
    parser.add_argument("--queries", type=int, default=1000)
    parser.add_argument("--owners", type=int, default=3)
    parser.add_argument("--bound", type=int, default=8)
    parser.add_argument("--topk", type=int, default=4)
    parser.add_argument("--neighbourhood-cap", type=int, default=3)
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "data/cwq/mpc_fixture/cwq_1000_domain_suite_20260904",
    )
    args = parser.parse_args()
    if min(args.relations, args.queries, args.owners, args.bound, args.topk) < 1:
        parser.error("relations, queries, owners, bound and topk must be positive")

    rows = load_compatible(args.compatible, ["test", "validation"])
    relation_frequency: Counter[str] = Counter()
    annotated = []
    for row in rows:
        hops = query_graph_to_hops(row["query_graph"])
        relation_frequency.update((hops.relation_1, hops.relation_2))
        annotated.append((row, hops))
    ranked_relations = [
        relation for relation, _ in relation_frequency.most_common(args.relations)
    ]
    vocabulary = set(ranked_relations)
    eligible = sorted(
        (
            (row, hops)
            for row, hops in annotated
            if hops.relation_1 in vocabulary and hops.relation_2 in vocabulary
        ),
        key=lambda item: item[0]["id"],
    )
    if len(eligible) < args.queries:
        raise SystemExit(
            f"only {len(eligible)} questions are covered by the selected "
            f"{args.relations}-relation vocabulary"
        )
    selected = eligible[: args.queries]
    by_domain: dict[str, list[str]] = defaultdict(list)
    relations_by_domain: dict[str, set[str]] = defaultdict(set)
    for row, hops in selected:
        domain = relation_domain(row)
        by_domain[domain].append(row["id"])
        relations_by_domain[domain].update((hops.relation_1, hops.relation_2))

    args.out.mkdir(parents=True, exist_ok=True)
    relation_allowlist_path = args.out / "relation_allowlist.json"
    write_json(relation_allowlist_path, ranked_relations)
    relation_manifest = [
        {"relation": relation, "held_out_hop_frequency": relation_frequency[relation]}
        for relation in ranked_relations
    ]
    domain_manifest = []
    for domain in sorted(by_domain):
        ids = by_domain[domain]
        ids_path = args.out / "query_ids" / f"{domain}.json"
        domain_relations_path = args.out / "relation_allowlists" / f"{domain}.json"
        fixture_path = args.out / "fixtures" / domain
        write_json(ids_path, ids)
        write_json(domain_relations_path, sorted(relations_by_domain[domain]))
        command = [
            sys.executable,
            str(ROOT / "scripts/build_cwq_mpc_fixture.py"),
            "--compatible", str(args.compatible),
            "--raw", str(args.raw),
            "--splits", "test,validation",
            "--query-ids", str(ids_path),
            "--relation-allowlist", str(domain_relations_path),
            "--full-filtered-union",
            "--first-relation-domain", domain,
            "--owners", str(args.owners),
            "--partition", "subject-hash",
            "--bound", str(args.bound),
            "--topk", str(args.topk),
            "--neighbourhood-cap", str(args.neighbourhood_cap),
            "--seed", str(args.seed),
            "--out", str(fixture_path),
        ]
        print(f"building {domain}: {len(ids)} queries", flush=True)
        subprocess.run(command, check=True)
        capacity = json.loads(
            (fixture_path / "capacity_report.json").read_text(encoding="utf-8")
        )
        config = json.loads((fixture_path / "config.json").read_text(encoding="utf-8"))
        domain_manifest.append({
            "domain": domain,
            "queries": len(ids),
            "public_relations": len(relations_by_domain[domain]),
            "query_ids_sha256": digest_ids(ids),
            "entities": capacity["entities"],
            "relations": capacity["relations"],
            "edges_available": capacity["edges_available"],
            "edges_kept": capacity["edges_kept"],
            "directory_rows": (
                (len(config["entities"]) + 1) * len(config["relations"])
            ),
            "fixture": str(fixture_path),
        })

    selected_ids = [row["id"] for row, _ in selected]
    manifest = {
        "evaluation_label": "CWQ 1.1 domain-scoped native MPC breadth suite",
        "held_out_compatible_questions": len(rows),
        "relation_vocabulary_size": len(ranked_relations),
        "eligible_questions_before_limit": len(eligible),
        "selected_questions": len(selected_ids),
        "selection_rule": (
            "rank relations by frequency across both query hops; retain questions "
            "whose two relations are in the selected vocabulary; sort by question "
            "ID and take the requested prefix"
        ),
        "selected_query_ids_sha256": digest_ids(selected_ids),
        "public_leakage": (
            "first-hop Freebase domain and all circuit dimensions are public; exact "
            "entity and relation identifiers remain secret-shared"
        ),
        "security_scope": (
            "Temi protects private inputs and intermediate/output values against up "
            "to two passive corruptions among three non-colluding computation servers; "
            "the single-host evaluation does not instantiate operational separation"
        ),
        "parameters": {
            "owners": args.owners,
            "partition": "subject-hash",
            "bound": args.bound,
            "top_k": args.topk,
            "neighbourhood_cap": args.neighbourhood_cap,
            "seed": args.seed,
        },
        "relation_vocabulary": relation_manifest,
        "domains": domain_manifest,
    }
    write_json(args.out / "selected_query_ids.json", selected_ids)
    write_json(args.out / "manifest.json", manifest)
    print(f"wrote {args.out / 'manifest.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
