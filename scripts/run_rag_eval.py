#!/usr/bin/env python3
"""Evaluate oblivious retrieval on MetaQA or WebQSP, with a plaintext baseline.

Builds a federated fixture covering a sample of questions, scores retrieval
through the relation-paged path, optionally answers through Ollama, and writes
both a per-question JSONL and a summary JSON so runs are comparable over time.

Retrieval is scored with the cleartext oracle, which is verified equal to the
MPC circuit (benchmarks/rag_quality_at_scale.json, metaqa_federated_execution.json).
Scoring in MPC costs ~5.7 GB per query on the MetaQA fixture, so the sweep uses
the oracle and the circuit is used for spot verification.

Two datasets, and they are not equivalent
-----------------------------------------
MetaQA supplies 2-hop questions whose chain is read out of the graph, and the
federation is synthesised by an entity split. Every sampled question is
representable.

WebQSP supplies its own query graphs and a real 5-party split, which is the
better federation. But only **66 of its 203** questions are two-hop; the other
137 are one-hop and this backend answers two-hop chains. WebQSP numbers
therefore describe a 33% subset, and the summary records that as
``representable_fraction`` so it cannot be quoted as a WebQSP-wide result.

WebQSP also has 3,800 relations against MetaQA's 18, so the dense
``entity x relation`` directory is far emptier -- see the printed occupancy.

Example
-------
    python3 scripts/run_rag_eval.py --dataset metaqa \\
        --questions 1000 --answers 300 --out results/rag_eval_1000

Every number it prints is also written to ``<out>/summary.json``.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.evidence_handles import (  # noqa: E402
    allocate_owner_blind_handles,
    handles_leak_owner,
)
from doram_t2_3pc.rag_bridge import (  # noqa: E402
    UnsupportedQueryGraph,
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

SIMGRAG = ROOT.parent / "SimGRAG"
DEFAULT_KB = SIMGRAG / "data/raw/metaQA/kb.txt"
DEFAULT_QA = SIMGRAG / "data/raw/metaQA/2-hop/vanilla/qa_test.txt"
WEBQSP = SIMGRAG / "data/webqsp"
LLM_CONFIG = {
    "metaqa": SIMGRAG / "configs/federated/metaqa_party_0.json",
    "webqsp": SIMGRAG / "configs/federated/webqsp_party_0.json",
}


def wilson(hits: int, total: int) -> tuple[float, float]:
    """Wilson score interval: behaves near p=1 where the normal one does not."""

    if not total:
        return (0.0, 0.0)
    z, p, n = 1.96, hits / total, total
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def load_graph(kb: Path):
    triples = [
        tuple(part.strip() for part in line.split("|"))
        for line in kb.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    adjacency = defaultdict(list)
    for head, relation, tail in triples:
        adjacency[head].append((relation, tail))
        adjacency[tail].append((relation + "_inverse", head))
    return adjacency


def sample_questions(qa: Path, adjacency, count: int, seed: int):
    """Take questions whose answer is reachable, and derive their query graph.

    The chain is read out of the knowledge graph rather than produced by the
    LLM rewrite, which isolates RETRIEVAL quality from rewrite quality. Rewrite
    is a separate stage with its own error rate and should be measured
    separately, not folded into this number.
    """

    rows = []
    for line in qa.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        question, answers = line.split("\t")
        match = re.search(r"\[(.+?)\]", question)
        if match:
            rows.append({
                "query": question.replace("[", "").replace("]", ""),
                "entity": match.group(1),
                "groundtruths": answers.split("|"),
            })

    generator = random.Random(seed)
    picked, skipped = [], 0
    for row in generator.sample(rows, len(rows)):
        truths = set(row["groundtruths"])
        chain = None
        for r1, mid in adjacency.get(row["entity"], []):
            for r2, tail in adjacency.get(mid, []):
                if tail in truths:
                    chain = (r1, r2)
                    break
            if chain:
                break
        if chain is None:
            skipped += 1
            continue
        row["query_graph"] = [
            [row["entity"], chain[0], "UNKNOWN"], ["UNKNOWN", chain[1], "ANSWER"]
        ]
        picked.append(row)
        if len(picked) >= count:
            break
    return picked, skipped, len(rows)


def load_webqsp(root: Path, count: int, seed: int):
    """Load WebQSP's graph, its own query graphs, and its real 5-party split.

    Unlike MetaQA, nothing here is synthesised: the query graphs ship with the
    dataset and the federation is the one SimGRAG built. The cost is coverage --
    the query graphs that are not two-hop chains are dropped, and the caller is
    told how many so the fraction can be reported.
    """

    import pickle

    graph = pickle.loads((root / "WebQSP.graph").read_bytes())
    query_graphs = pickle.loads((root / "WebQSP.query_graphs").read_bytes())
    queries, groundtruths = pickle.loads((root / "WebQSP.queries_gt").read_bytes())

    adjacency = defaultdict(list)
    for head, relations in graph.items():
        for relation, tails in relations.items():
            for tail in tails:
                adjacency[head].append((relation, tail))
                adjacency[tail].append((relation + "_inverse", head))

    # The real federation: every forward edge belongs to exactly one party. An
    # inverse edge is the same edge read backwards, so it inherits that owner --
    # otherwise the split would be inconsistent with itself.
    edge_owner: dict[tuple[str, str, str], int] = {}
    federated = root / "federated"
    owner_count = len([p for p in federated.iterdir() if p.is_dir()])
    for owner in range(owner_count):
        party = pickle.loads((federated / f"party_{owner}" / "party.pkl").read_bytes())
        for head, relations in party["graph"].items():
            for relation, tails in relations.items():
                for tail in tails:
                    edge_owner[(head, relation, tail)] = owner

    rows, unrepresentable = [], 0
    for position, graph_spec in enumerate(query_graphs):
        try:
            query_graph_to_hops(graph_spec)
        except UnsupportedQueryGraph:
            unrepresentable += 1
            continue
        rows.append({
            "query": queries[position],
            "groundtruths": list(groundtruths[position]),
            "query_graph": [list(triple) for triple in graph_spec],
        })

    generator = random.Random(seed)
    picked = generator.sample(rows, len(rows))[:count]
    return adjacency, picked, unrepresentable, len(query_graphs), edge_owner, owner_count


def entity_split(nodes: list[str]):
    """Synthesised 3-owner split: each owner holds complete records about its
    own subjects.

    That keeps relation diversity per owner (which a relation-type split
    destroys) and gives realistic volume skew. Used for MetaQA, which ships no
    federation of its own.
    """

    index = {entity: position for position, entity in enumerate(nodes)}

    def assign(head: str, relation: str, tail: str) -> int:
        return 0 if index[head] < len(nodes) * 0.6 else 1 + (index[head] % 2)

    return assign, 3


def recorded_split(edge_owner: dict, owner_count: int):
    """WebQSP's real split, with inverse edges following their forward edge."""

    def assign(head: str, relation: str, tail: str) -> int:
        if relation.endswith("_inverse"):
            head, relation, tail = tail, relation[: -len("_inverse")], head
        return edge_owner.get((head, relation, tail), 0)

    return lambda nodes: (assign, owner_count)


def build_fixture(questions, adjacency, out: Path, bound: int, cap: int, seed: int,
                  split, top_k: int = 4, full_union: bool = False):
    """Cover each question's two-hop neighbourhood and split it across owners."""

    keep = set()
    for row in questions:
        hops = query_graph_to_hops(row["query_graph"])
        keep.add(hops.source)
        # Walk the queried chain explicitly. The generic expansion below takes
        # an arbitrary `cap` neighbours, which on a graph with a large relation
        # vocabulary can drop the very relation the query asks for -- the
        # question would then score zero for a fixture-construction reason
        # rather than a retrieval one. Same cap, so this adds no extra reach.
        mids = [t for r, t in adjacency[hops.source] if r == hops.relation_1][:cap]
        for mid in mids:
            keep.add(mid)
            keep.update(
                [t for r, t in adjacency[mid] if r == hops.relation_2][:cap]
            )
        # Distractors: the neighbourhood the backend must scan past.
        for _, mid in adjacency[hops.source][:cap]:
            keep.add(mid)
            for _, tail in adjacency[mid][:cap]:
                keep.add(tail)
    if full_union:
        edges = sorted({
            (head, relation, target)
            for head, records in adjacency.items()
            for relation, target in records
        })
    else:
        edges = sorted(
            {(h, r, t) for h in keep for r, t in adjacency[h] if t in keep}
        )
    query_sources = {
        query_graph_to_hops(row["query_graph"]).source for row in questions
    }
    nodes = sorted(
        {h for h, _, _ in edges} | {t for _, _, t in edges} | query_sources
    )
    # Restricting the vocabulary to relations actually present in the subgraph
    # is load-bearing, not tidiness: the directory is dense in
    # entities x relations, and WebQSP's full 3,800-relation vocabulary would
    # make it 771 million rows.
    #
    # The relations the queries ask about are added even when the subgraph
    # retains no edge for them. The ontology is a *public* parameter, so a query
    # naming a relation with no matching edges must return nothing -- an honest
    # miss -- rather than being unanswerable. Excluding them would instead
    # silently drop those questions from the denominator.
    asked = set()
    for row in questions:
        hops = query_graph_to_hops(row["query_graph"])
        asked.update((hops.relation_1, hops.relation_2))
    relations = sorted({r for _, r, _ in edges} | asked)

    assign, owner_count = split(nodes)
    grouped = [defaultdict(list) for _ in range(owner_count)]
    for head, relation, tail in edges:
        grouped[assign(head, relation, tail)][(head, relation)].append(tail)

    owners = []
    for owner in range(owner_count):
        rows = [
            {"source": h, "relation": r, "target": t,
             "evidence": 1, "score": 1 + position % 9}
            for position, ((h, r), tails) in enumerate(sorted(grouped[owner].items()))
            for t in sorted(tails)[:bound]
        ]
        owners.append(
            allocate_owner_blind_handles(rows, 50, rng=random.Random(seed + owner))
        )

    budgets = [len(grouped[owner]) for owner in range(owner_count)]
    # The federation-wide bound is a public parameter, so it must be measured
    # rather than assumed. Under an entity split every key lives with one owner
    # and this comes out equal to `bound`; under WebQSP's recorded edge split a
    # key can span parties, and then it is genuinely larger.
    federation_degree = defaultdict(int)
    for owner in range(owner_count):
        for key, tails in grouped[owner].items():
            federation_degree[key] += min(len(tails), bound)
    global_frontier = max(federation_degree.values(), default=bound)

    out.mkdir(parents=True, exist_ok=True)
    config = {
        "owners": [f"owner_{i}" for i in range(owner_count)],
        "entities": {e: i + 1 for i, e in enumerate(nodes)},
        "relations": {r: i + 1 for i, r in enumerate(relations)},
        "fanout_per_owner": bound,
        "top_k": top_k,
        "field_prime": 170141183460469231731687303715884105727,
        "relation_page_layout": {
            "page_size": bound, "pages_per_key": 1,
            "page_budget": max(budgets) + 1,
            "frontier_per_owner": bound, "global_frontier": global_frontier,
        },
    }
    (out / "config_paged.json").write_text(json.dumps(config, indent=1))
    for position, rows in enumerate(owners):
        (out / f"owner_{position}.json").write_text(json.dumps(rows, indent=1))
    return config, budgets, len(edges), sum(len(r) for r in owners)


def plaintext_rate(questions, adjacency, config, bound, topk) -> float:
    """Baseline on the same graph: what non-private retrieval would score."""

    nodes = set(config["entities"])
    full = defaultdict(list)
    for head in nodes:
        for relation, tail in adjacency[head]:
            if tail in nodes:
                full[(head, relation)].append(tail)
    hits = 0
    for row in questions:
        hops = query_graph_to_hops(row["query_graph"])
        chains = []
        firsts = sorted(full.get((hops.source, hops.relation_1), []))
        for mid in (firsts[:bound] if bound else firsts):
            seconds = sorted(full.get((mid, hops.relation_2), []))
            for tail in (seconds[:bound] if bound else seconds):
                chains.append({"score": 1, "reuse_nodes": [], "edges": [
                    [hops.source, hops.relation_1, mid],
                    [mid, hops.relation_2, tail]]})
        hits += evidence_hit(chains[:topk] if topk else chains, row["groundtruths"])
    return hits / len(questions) if questions else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", choices=("metaqa", "webqsp"), default="metaqa")
    parser.add_argument("--questions", type=int, default=400,
                        help="questions to score for retrieval (default 400); "
                             "WebQSP has at most 66 representable ones")
    parser.add_argument("--answers", type=int, default=0,
                        help="how many of those to also answer through the LLM")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--bound", type=int, default=3,
                        help="edges retained per (source, relation); quality "
                             "saturates at 3 on MetaQA, collapses below 2")
    parser.add_argument("--topk", type=int, default=4)
    parser.add_argument("--neighbourhood-cap", type=int, default=10,
                        help="per-node expansion cap when building the fixture")
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument("--kb", type=Path, default=DEFAULT_KB)
    parser.add_argument("--qa", type=Path, default=DEFAULT_QA)
    parser.add_argument("--webqsp-root", type=Path, default=WEBQSP)
    parser.add_argument("--llm-config", type=Path, default=None)
    parser.add_argument("--llm-timeout", type=float, default=60.0,
                        help="per-answer LLM timeout in seconds")
    parser.add_argument("--llm-max-tokens", type=int, default=80)
    parser.add_argument("--skip-baseline", action="store_true")
    args = parser.parse_args()
    if args.llm_config is None:
        args.llm_config = LLM_CONFIG[args.dataset]

    started = time.time()
    args.out.mkdir(parents=True, exist_ok=True)
    coverage: dict[str, object] = {"dataset": args.dataset}

    if args.dataset == "webqsp":
        (adjacency, questions, unrepresentable, total,
         edge_owner, owner_count) = load_webqsp(
            args.webqsp_root, args.questions, args.seed
        )
        split = recorded_split(edge_owner, owner_count)
        representable = total - unrepresentable
        coverage.update({
            "query_graphs_available": total,
            "query_graphs_representable": representable,
            "representable_fraction": round(representable / total, 4),
            "federation": f"recorded {owner_count}-party split",
        })
        print(f"WebQSP: {representable}/{total} query graphs are two-hop chains "
              f"({100*representable/total:.0f}%); {unrepresentable} are not "
              f"representable by this backend and are excluded")
        print(f"sampled {len(questions)} of those {representable}")
    else:
        adjacency = load_graph(args.kb)
        questions, skipped, available = sample_questions(
            args.qa, adjacency, args.questions, args.seed
        )
        split = entity_split
        coverage.update({
            "query_graphs_available": available,
            "answer_unreachable_skipped": skipped,
            "federation": "synthesised 3-owner entity split",
        })
        print(f"sampled {len(questions)} of {available:,} questions "
              f"({skipped} skipped: answer not reachable in the KB)")

    if not questions:
        print("no representable questions; nothing to score")
        return 1

    config, budgets, edges_available, edges_kept = build_fixture(
        questions, adjacency, args.out / "fixture",
        args.bound, args.neighbourhood_cap, args.seed, split
    )
    owner_count = len(budgets)
    rows = len(config["entities"]) * len(config["relations"])
    print(f"fixture: {len(config['entities']):,} entities, "
          f"{len(config['relations']):,} relations, {edges_available:,} edges "
          f"({edges_kept:,} kept at bound {args.bound})")
    print(f"directory: {rows:,} dense rows, "
          f"{100*edges_available/rows:.2f}% occupied "
          f"-- the rest is padding, and the padding is the privacy")
    print(f"federation: {owner_count} owners, B_i={budgets} "
          f"skew={max(budgets)/min(budgets):.2f}x")

    paged = RelationPageConfig.load(args.out / "fixture" / "config_paged.json")
    owner_edges = {
        f"owner_{i}": json.loads(
            (args.out / "fixture" / f"owner_{i}.json").read_text()
        ) for i in range(owner_count)
    }
    leak = handles_leak_owner(owner_edges, evidence_bits=50)
    bound_report = check_global_frontier(paged, owner_edges)
    print(f"handles: {'LEAK' if leak['leaks'] else 'owner-blind'}   "
          f"global_frontier {paged.pages.global_frontier} verified "
          f"(max federation degree {bound_report['max_key_degree_federation_wide']})")

    resolver = build_handle_resolver(owner_edges)
    hits = empty = unsupported = 0
    retrieval_started = time.time()
    with (args.out / "per_question.jsonl").open("w", encoding="utf-8") as log:
        for position, row in enumerate(questions, start=1):
            try:
                hops = query_graph_to_hops(row["query_graph"])
            except UnsupportedQueryGraph as exc:
                unsupported += 1
                log.write(json.dumps({"query": row["query"],
                                      "error": str(exc)}) + "\n")
                continue
            evidence = rows_to_evidence(
                evaluate_paged_cleartext(paged, owner_edges, hops.as_query()),
                resolver,
            )
            hit = bool(evidence_hit(evidence, row["groundtruths"]))
            hits += hit
            empty += not evidence
            log.write(json.dumps({
                "query": row["query"], "groundtruths": row["groundtruths"],
                "hops": hops.as_query(), "evidence": evidence, "hit": hit,
            }, ensure_ascii=False) + "\n")
            if position % 200 == 0:
                print(f"  {position}/{len(questions)}  running hit rate "
                      f"{100*hits/position:.1f}%")
    scored = len(questions) - unsupported
    retrieval_seconds = time.time() - retrieval_started
    low, high = wilson(hits, scored)
    print(f"\nretrieval: {hits}/{scored} = {100*hits/scored:.2f}%  "
          f"95% CI [{100*low:.2f}%, {100*high:.2f}%]  ({retrieval_seconds:.0f}s)")

    summary = {
        **coverage,
        "questions_sampled": len(questions),
        "questions_scored": scored,
        "unsupported_query_graphs": unsupported,
        "empty_retrievals": empty,
        "evidence_hits": hits,
        "evidence_hit_rate": round(hits / scored, 4) if scored else None,
        "evidence_hit_ci95": [round(low, 4), round(high, 4)],
        "retrieval_seconds": round(retrieval_seconds, 1),
        "bound": args.bound, "top_k": args.topk, "seed": args.seed,
        "fixture": {"entities": len(config["entities"]),
                    "relations": len(config["relations"]),
                    "directory_rows": rows,
                    "directory_occupancy": round(edges_available / rows, 6),
                    "edges_available": edges_available, "edges_kept": edges_kept,
                    "owners": owner_count, "B_i": budgets,
                    "global_frontier": paged.pages.global_frontier,
                    "volume_skew": round(max(budgets) / min(budgets), 2)},
        "handles_owner_blind": not leak["leaks"],
        "scored_with": "cleartext oracle, verified equal to the MPC circuit; "
                       "see benchmarks/rag_quality_at_scale.json",
    }

    if not args.skip_baseline:
        # Compare like with like. The oblivious path truncates per owner, so its
        # federation-wide retention is `global_frontier`, not `bound`; under an
        # entity split those coincide, but under WebQSP's recorded edge split a
        # key spans parties and `bound` would understate the baseline -- making
        # privacy look free, or better than free.
        federation_bound = paged.pages.global_frontier or args.bound
        base = plaintext_rate(questions, adjacency, config, federation_bound, args.topk)
        # The true ceiling clips neither the fanout nor the result list. The
        # top-k-clipped figure is kept because the recorded MetaQA benchmarks
        # quote it, but it is not an upper bound and must not be used as one.
        ceiling = plaintext_rate(questions, adjacency, config, None, None)
        clipped = plaintext_rate(questions, adjacency, config, None, args.topk)
        rate = hits / scored
        summary["plaintext_same_bound"] = round(base, 4)
        summary["plaintext_federation_bound"] = federation_bound
        summary["plaintext_unbounded"] = round(clipped, 4)
        summary["plaintext_ceiling_unclipped"] = round(ceiling, 4)
        summary["privacy_cost_points"] = round(100 * (ceiling - rate), 2)
        print(f"baseline : plaintext at federation bound {federation_bound} = "
              f"{100*base:.2f}%   top-{args.topk}-clipped unbounded = {100*clipped:.2f}%")
        print(f"ceiling  : {100*ceiling:.2f}% (no fanout bound, no top-k clip)")
        print(f"           privacy costs {summary['privacy_cost_points']:.2f} points "
              f"of retrieval quality")

    if args.answers:
        from openai import OpenAI

        conf = json.loads(args.llm_config.read_text())
        llm = conf.get("llm", conf)
        client = OpenAI(
            base_url=llm["base_url"],
            api_key=llm.get("api_key", "ollama"),
            max_retries=0,
        )
        picked = random.Random(args.seed).sample(
            [json.loads(line) for line in
             (args.out / "per_question.jsonl").read_text().splitlines()
             if '"hit"' in line],
            min(args.answers, scored),
        )
        correct = answered = 0
        errors: Counter[str] = Counter()
        answer_started = time.time()
        with (args.out / "answers.jsonl").open("w", encoding="utf-8") as log:
            for position, row in enumerate(picked, start=1):
                facts = "\n".join(
                    " ; ".join(f"{h} -{r}-> {t}" for h, r, t in item["edges"])
                    for item in row["evidence"]
                )
                prompt = (f"Answer using ONLY these retrieved facts.\n\nFacts:\n"
                          f"{facts}\n\nQuestion: {row['query']}\n"
                          "Answer with names only, comma separated.")
                try:
                    out = client.chat.completions.create(
                        model=llm["model"],
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.0,
                        max_tokens=args.llm_max_tokens,
                        timeout=args.llm_timeout,
                    ).choices[0].message.content.strip()
                except Exception as exc:  # noqa: BLE001
                    errors[type(exc).__name__] += 1
                    log.write(json.dumps({"query": row["query"],
                                          "error": type(exc).__name__}) + "\n")
                    if position % 10 == 0:
                        print(f"  answered {position}/{len(picked)}  "
                              f"successful {answered}, errors {sum(errors.values())}")
                    continue
                ok = any(str(g).casefold() in out.casefold()
                         for g in row["groundtruths"])
                correct += ok
                answered += 1
                log.write(json.dumps({"query": row["query"],
                                      "groundtruths": row["groundtruths"],
                                      "answer": out, "correct": ok},
                                     ensure_ascii=False) + "\n")
                if position % 50 == 0:
                    print(f"  answered {position}/{len(picked)}  "
                          f"running accuracy {100*correct/answered:.1f}%")
        summary.update({
            "answers_attempted": len(picked),
            "answers_scored": answered,
            "answers_errors": sum(errors.values()),
            "answer_error_types": dict(errors.most_common()),
            "answer_seconds": round(time.time() - answer_started, 1),
            "llm_model": llm["model"],
            "llm_timeout": args.llm_timeout,
            "llm_max_tokens": args.llm_max_tokens,
        })
        if answered:
            alow, ahigh = wilson(correct, answered)
            summary.update({
                "answers_correct": correct,
                "answer_accuracy": round(correct / answered, 4),
                "answer_accuracy_ci95": [round(alow, 4), round(ahigh, 4)],
            })
            print(f"answers  : {correct}/{answered} = {100*correct/answered:.2f}%  "
                  f"95% CI [{100*alow:.2f}%, {100*ahigh:.2f}%]")
        else:
            print(f"answers  : 0/{len(picked)} scored; "
                  f"errors {dict(errors.most_common())}")

    summary["total_seconds"] = round(time.time() - started, 1)
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(f"\nwrote {args.out}/summary.json and per_question.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
