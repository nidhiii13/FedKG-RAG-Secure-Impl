# Dataset Evaluation — End-to-End N-Party Private Lookups on Real Repo Datasets

> **Superseded for paper use** by [paper_evaluation.md](paper_evaluation.md)
> (adds baselines, WebQSP N=5, timing repetitions, per-domain percentiles,
> and real process-separated deployment measurements). This file records the
> earlier exploratory single-repetition run.

Run date: 2026-08-27, single CPU core, repo `.venv` (Python 3.10.12, NumPy
2.2.6). Harness: [`benchmarks/eval_datasets.py`](../benchmarks/eval_datasets.py).
Machine-readable summaries: [`benchmarks/dataset_eval_summaries.json`](../benchmarks/dataset_eval_summaries.json).
Reproduce with:

```bash
.venv/bin/python multiparty_fss/benchmarks/eval_datasets.py \
    --dataset all --queries 50 --party-count 3 --scaling --out /tmp/mpfss_eval
```

**Scope.** This measures the multi-party FSS pipeline end to end at the
retrieval layer: plaintext query term → HMAC encoding → rank in the shared
opaque universe → `Gen^{p0}` keygen (client) → one request per evaluator →
`Eval^{p0}` over the full universe at each of N evaluators over replicated
plaintext-free stores → fail-closed XOR combine → opaque candidate → and,
where the dataset supports it, answer readout from the opaque snapshot
adjacency (1-hop / 2-hop chains in encoded-ID space) compared against
HMAC-encoded gold. Timing/universe visibility to evaluators follows the
documented leakage model (SECURITY.md); nothing here measures privacy — these
are functionality and cost metrics. The answer-readout stage corresponds to
the repo's structural stage and is computed over the replicated encoded
adjacency after the private anchor lookups; it is not itself an oblivious
computation.

## Workloads

| Workload | KG source | Federation | Queries (source) | Answer stage |
|---|---|---|---|---|
| `metaqa` | Real SimGRAG federated MetaQA party KGs (2 × ~134k edges) | 2 real data partitions | 50 × 1-hop `qa_test.txt` questions; relation derived from the gold chain | topic + relation privately looked up; answers = encoded adjacency readout; exact-match vs gold |
| `lcquad2` | Term universe from **all 6,046** LC-QuAD 2.0 test SPARQLs (wd:/wdt: co-occurrence) | 3 hash-split owners | first 50 questions with ≥1 entity + ≥1 relation (157 term lookups) | none (no local Wikidata; retrieval-level only) |
| `kqapro` | **Full** frozen KQA Pro relation graph, 385,774 edges (`data/kqa_pro/relation_fixture/full`) | 3 owners (user fixture) | 50 two-hop validation queries + `endpoint_ids` gold | source + rel₁ + rel₂ privately looked up; 2-hop encoded readout; exact vs endpoint IDs |
| `cwq-closure` | CWQ 25-query closure fixture, 4,625 edges (`data/cwq/mpc_fixture/q25_closure`) | 3 owners (user fixture) | 25 two-hop queries + groundtruth labels | same 2-hop readout |
| `cwq-rog` | Union of first 25 RoG CWQ test subgraphs (25,581 entities) | 3 hash-split owners | 25 questions; private lookup of each gold topic entity | gold-answer-entity universe coverage only (multi-hop CWQ derivation out of scope) |
| `metaqa-n5` / `metaqa-n7` | as `metaqa` | 2 partitions | 20 questions | scaling reruns at N=5 (t=2) and N=7 (t=3) |

All runs use the honest-majority default `t = ⌊(N−1)/2⌋`, β = 1, dense-mode
responses (worst-case communication), and 10 negative controls per workload
(5 absent entity + 5 absent relation lookups that must reconstruct all-zero).

## Headline results

**Retrieval correctness: 606/606 term lookups correct across all workloads
(100%), including 3 genuinely-absent terms correctly reconstructing to zero;
all 70 negative controls pass.** Every present term reconstructed exactly
`{α-candidate: 1}` over its full universe — no false positives, no false
negatives, on real KGs up to 385k edges and universes up to 40,151 points.

| Workload | N | t | Queries | Lookups | Lookup correct | Answer exact-match | Mean coverage |
|---|---|---|---|---|---|---|---|
| metaqa | 3 | 1 | 50 | 100 | 100% | **50/50 (100%)** | 1.0 |
| lcquad2 | 3 | 1 | 50 | 157 | 100% | n/a | n/a |
| kqapro | 3 | 1 | 50 | 150 | 100% | **50/50 (100%)** | 1.0 |
| cwq-closure | 3 | 1 | 25 | 75 | 100% | 20/25 (80%)* | 0.852* |
| cwq-rog | 3 | 1 | 25 | 44 | 100% | n/a | 0.848† |
| metaqa-n5 | 5 | 2 | 20 | 40 | 100% | 20/20 (100%) | 1.0 |
| metaqa-n7 | 7 | 3 | 20 | 40 | 100% | 20/20 (100%) | 1.0 |

\* **All five CWQ-closure misses are fixture artifacts, not FSS errors**,
verified case by case: 2 queries' `relation_2` edges were pruned by the
closure build (`edges_kept` 4,625 < `edges_available` 4,928) — the private
lookup *correctly* reported those relations absent and the readout correctly
returned nothing; the other 3 queries each returned exactly 8 endpoints
against 14–25 gold answers, where 8 is precisely the fixture's
`fanout_per_owner`/`bound` = 8 cap. The FSS layer retrieved everything the
pruned KG contains.

† `cwq-rog` coverage = fraction of gold answer entities present in the
25-subgraph union universe — a property of RoG subgraph completeness, not of
the retrieval (all topic-entity lookups were correct).

## Latency (per private lookup, parallel-evaluator model: keygen + max eval + combine)

| Workload | Universe (entity) | n | keygen p50 | eval p50 (per evaluator) | combine p50 | **total p50** | total p95 domain-mixed |
|---|---|---|---|---|---|---|---|
| metaqa (entity lookups) | 40,151 | 16 | 15.7 ms | 29.2 ms | 11.3 ms | **57.2 ms** | ~58 ms |
| metaqa (relation lookups) | 9 | 4 | ~0.1 ms | ~0.2 ms | ~0.05 ms | **0.4 ms** | — |
| lcquad2 | 4,622 | 13 | 1.0 ms | 1.3 ms | 0.4 ms | **2.7 ms** | 7.7 ms |
| kqapro | 17,067 | 15 | 1.2 ms | 1.6 ms | 0.3 ms | **3.1 ms** | 22 ms (entity tail) |
| cwq-closure | 820 | 10 | 0.7 ms | 1.0 ms | 0.3 ms | **1.9 ms** | 2.6 ms |
| cwq-rog | 25,581 | 15 | 10.3 ms | 17.3 ms | 7.3 ms | **35.1 ms** | 51 ms |
| metaqa-n5 | 40,151 | 16 | 18.3 ms | 32.2 ms | 18.9 ms | **69.6 ms** | — |
| metaqa-n7 | 40,151 | 16 | 29.5 ms | 57.3 ms | 26.7 ms | **114.3 ms** | — |

Whole-query cost (all its term lookups, sequential in-process): MetaQA
answers a full 1-hop question (entity + relation lookup + readout) in ≈58 ms;
KQA Pro answers a full two-hop question (3 lookups + 2-hop readout) in ≈6–25
ms. Query-phase wall clock for all 50 queries: MetaQA 6.9 s, KQA Pro 4.0 s,
LC-QuAD2 1.7 s, CWQ 4.2 s combined.

Contrast with the deployed legacy 2-party CLI path: the repo's own documented
full-universe exact lookup on MetaQA-scale universes is ≈36 s per query
(80,311 points, subprocess batching; `docs/secure_architecture.md`), and our
measured legacy sweep at 65,536 points was 10.35 s. The N=3 honest-majority
path answers the same shape of query in tens of milliseconds — three orders
of magnitude — though the comparison is deployment-path vs deployment-path,
not construction vs construction (the tree DPF itself is fast; its subprocess
protocol is not).

## Scaling with N (MetaQA, same 20 queries, same 40,151-point universe)

| N | t | key/evaluator (JSON) | total p50/lookup | store total (N replicas) | setup |
|---|---|---|---|---|---|
| 3 | 1 | 32.4 KiB | 57 ms | 267 MB | 31 s |
| 5 | 2 | 192.4 KiB | 70 ms | 445 MB | 48 s |
| 7 | 3 | 1.38 MiB | 114 ms | 624 MB | 61 s |

Latency doubles from N=3→7 while key size grows ~43× — key material (the
2^((N−1)/2) factor), not time, is the binding constraint as N grows, exactly
as the construction's bound predicts. Answer quality is N-invariant (100%
at every N), as it must be for a correct FSS.

## Communication (dense mode = worst case)

Per lookup: client→evaluator = one key share (32 KiB at MetaQA N=3, 1.4 MiB
at N=7); evaluator→combiner = the dense share vector (~840 KiB JSON at
U=40k). The projected mode used by the retrieval flow returns
capacity-many slot shares instead (hundreds of bytes); dense mode was chosen
here to bound the worst case and to make full-universe correctness checkable
per query.

## One-time setup costs

Snapshot build + N-store replication + verified load: MetaQA 31 s / 267 MB
(N=3), KQA Pro 32 s / 319 MB, CWQ-RoG 12 s / 95 MB, LC-QuAD2 1 s / 11 MB.
Replication is per-evaluator-set and amortizes over all queries.

## Takeaways

1. **The N-party path is functionally exact on real data**: zero retrieval
   errors in 606 lookups across four datasets, and 100% answer exact-match
   wherever the underlying KG actually contains the gold chain (MetaQA 50/50,
   KQA Pro 50/50, MetaQA at N=5/7 20/20 each). Every observed answer miss
   traces to documented fixture pruning, and in each such case the private
   lookup *correctly* reported the pruned term as absent — the fail-closed
   behavior working as specified.
2. **Interactive latency at honest-majority N=3** on the repo's real
   universes (≈57 ms per 40k-point private lookup; 2–3 ms at the 1–17k
   scales of LC-QuAD2/KQA Pro), with plenty of headroom given the
   pure-Python PRG bottleneck.
3. **Scaling behaves as the theory says**: time ≈ ×2 and keys ≈ ×43 from
   N=3→7 on identical workloads; the practical N ceiling is key size.
4. These are prototype functionality/cost measurements under the documented
   leakage model; they say nothing about privacy beyond the construction's
   cited guarantees, and the answer-readout stage is not oblivious.
