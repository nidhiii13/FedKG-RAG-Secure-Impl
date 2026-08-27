#!/usr/bin/env python3
"""Answer-independent scoring study over a completed CWQ run's fixture.

The deployed fixture score (``1 + position % 9``) is synthetic.  This study
asks how much any ranking can matter, and whether public KG-aware scores beat
the synthetic one, by re-ranking the *same* bounded candidate chains under
different answer-independent scores and clipping to top-k:

    synthetic-position    what the fixture ships today (proxy)
    inverse-target-degree rarer target entities first
    relation-selectivity  rarer second-hop relations first
    random                seeded lower bound
    unclipped             no top-k clip = ranking-headroom ceiling

Scores never look at gold answers; ground truth is used only to grade the
final hit, exactly as in the main evaluation.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.rag_bridge import evidence_hit  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--topk", type=int, default=4)
    parser.add_argument("--seed", type=int, default=4242)
    args = parser.parse_args()

    config = json.loads((args.run / "fixture" / "config_paged.json").read_text())
    owners = config["owners"]
    edges = []
    for owner in owners:
        edges.extend(json.loads((args.run / "fixture" / f"{owner}.json").read_text()))
    adjacency = defaultdict(list)
    out_degree: Counter[str] = Counter()
    relation_freq: Counter[str] = Counter()
    for edge in edges:
        adjacency[(edge["source"], edge["relation"])].append(edge["target"])
        out_degree[edge["source"]] += 1
        relation_freq[edge["relation"]] += 1

    questions = [json.loads(line)
                 for line in (args.run / "per_question.jsonl").read_text().splitlines()]
    rng = random.Random(args.seed)

    def chains(hops):
        result = []
        for position, mid in enumerate(sorted(adjacency[(hops["source"], hops["relation_1"])])):
            for position2, tail in enumerate(sorted(adjacency[(mid, hops["relation_2"])])):
                result.append((mid, tail, position * 31 + position2))
        return result

    scorers = {
        "synthetic-position": lambda mid, tail, pos: -(1 + pos % 9),
        "inverse-target-degree": lambda mid, tail, pos: out_degree[tail],
        "relation-selectivity": lambda mid, tail, pos: 0,  # handled per-hops below
        "random": lambda mid, tail, pos: rng.random(),
    }
    hits = {name: 0 for name in scorers}
    hits["unclipped"] = 0
    for row in questions:
        hops = row["hops"]
        candidates = chains(hops)
        selectivity = relation_freq[hops["relation_2"]]
        for name, scorer in scorers.items():
            if name == "relation-selectivity":
                ranked = sorted(candidates, key=lambda c: (selectivity, out_degree[c[1]]))
            else:
                ranked = sorted(candidates, key=lambda c: scorer(*c))
            top = ranked[:args.topk]
            evidence = [{"score": 1, "reuse_nodes": [], "edges": [
                [hops["source"], hops["relation_1"], mid],
                [mid, hops["relation_2"], tail]]} for mid, tail, _ in top]
            hits[name] += evidence_hit(evidence, row["groundtruths"])
        evidence = [{"score": 1, "reuse_nodes": [], "edges": [
            [hops["source"], hops["relation_1"], mid],
            [mid, hops["relation_2"], tail]]} for mid, tail, _ in candidates]
        hits["unclipped"] += evidence_hit(evidence, row["groundtruths"])

    total = len(questions)
    report = {
        "run": str(args.run),
        "questions": total,
        "top_k": args.topk,
        "bound_from_fixture": config["fanout_per_owner"],
        "hit_rates": {name: round(count / total, 4)
                      for name, count in sorted(hits.items())},
        "ranking_headroom_points": round(
            100 * (hits["unclipped"] - min(hits[n] for n in scorers)) / total, 2),
        "note": ("candidates are the fixture's bounded chains; scores are "
                 "answer-independent; unclipped is the no-top-k ceiling at the "
                 "same bound"),
    }
    out = args.run / f"scoring_study_k{args.topk}.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
