#!/usr/bin/env python3
"""Sweep top_k against retrieval quality on a built fixture.

Why
---
The decomposition in webqsp_smoke.json attributes most of the measured privacy
cost to the top_k budget rather than the fanout bound: 1.5 of MetaQA's 2.0 points
and 10.6 on WebQSP. And top_k selection is k passes over the candidate list,
which the cost estimate puts at 0.001-0.037% of a query. If the quality curve is
steep, the dominant privacy cost is nearly free to remove -- and the deployed
k=4 was simply set too low.

Scored with the cleartext oracle, verified equal to the circuit
(rag_quality_at_scale.json). top_k does not change the threat model: it is a
public parameter either way, so raising it reveals nothing new -- the servers
already emit exactly k rows and always did.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.rag_bridge import (  # noqa: E402
    build_handle_resolver,
    evidence_hit,
    rows_to_evidence,
)
from doram_t2_3pc.relation_pages import (  # noqa: E402
    RelationPageConfig,
    evaluate_paged_cleartext,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--questions", type=Path, required=True,
                        help="per_question.jsonl from a previous run")
    parser.add_argument("--values", type=int, nargs="+",
                        default=[1, 2, 4, 8, 16, 32, 64])
    args = parser.parse_args()

    rows = [
        json.loads(line) for line in
        args.questions.read_text(encoding="utf-8").splitlines()
        if '"hops"' in line
    ]
    raw = json.loads((args.fixture / "config_paged.json").read_text())
    owners = raw["owners"]
    owner_edges = {
        owner: json.loads((args.fixture / f"owner_{i}.json").read_text())
        for i, owner in enumerate(owners)
    }
    resolver = build_handle_resolver(owner_edges)

    base = RelationPageConfig.load(args.fixture / "config_paged.json")
    candidates = (
        base.pages.frontier_slots(len(owners))
        * len(owners)
        * base.pages.slots_per_key
    )
    print(f"{len(rows)} questions, {candidates} candidates per query\n")
    print(f"{'top_k':>7}{'hit rate':>11}{'hits':>8}{'delta vs k=4':>15}")

    baseline = None
    for k in args.values:
        if k > candidates:
            print(f"{k:>7}   skipped: exceeds the candidate count")
            continue
        raw["top_k"] = k
        scratch = args.fixture / "_topk_sweep.json"
        scratch.write_text(json.dumps(raw))
        config = RelationPageConfig.load(scratch)
        hits = 0
        for row in rows:
            evidence = rows_to_evidence(
                evaluate_paged_cleartext(config, owner_edges, row["hops"]),
                resolver,
            )
            hits += bool(evidence_hit(evidence, row["groundtruths"]))
        rate = hits / len(rows)
        if k == 4:
            baseline = rate
        delta = "" if baseline is None else f"{100 * (rate - baseline):+.2f} pts"
        print(f"{k:>7}{100 * rate:>10.2f}%{hits:>8}{delta:>15}")
        scratch.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
