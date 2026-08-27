# ComplexWebQuestions 1.1 evaluation of the relation-paged oblivious retrieval core

Date: 2026-08-27.  All numbers below were produced by the commands in
§R and are stored at the paths in §S.

## A. Dataset selection verdict

**Selected: ComplexWebQuestions 1.1 (official release, gold SPARQL) joined by
question ID with the RoG-CWQ graph snapshot (HuggingFace `rmanluo/RoG-cwq`).**
Both held-out splits are used (test 3,531 + validation 3,519 = 7,050
questions; the 27,639-question train split is not used).  1,267 held-out
questions are strict dependent two-hop compatible, with the relation pair
parsed from the **gold SPARQL** — gold answers are never consulted for path
selection.  The ID join between the official v1.1 files and RoG-CWQ is exact:
3,531/3,531 and 3,519/3,519.

## B. Candidate comparison

| Candidate | Held-out qs | Gold logical form | Graph snapshot | Two-hop ≥1,000 held-out | Blocking issue |
|---|---|---|---|---|---|
| **CWQ 1.1 + RoG-CWQ (chosen)** | 7,050 | SPARQL (all splits) | RoG-CWQ subgraphs, fixed download | **yes: 1,267 (measured)** | answers for test come from RoG-CWQ, not the official leaderboard |
| GrailQA | dev 6,763 usable (test labels hidden) | s-expr + SPARQL | none shipped; requires own Virtuoso Freebase server | unmeasured | no downloadable working graph; test answers hidden |
| WebQSP official parses | 1,639 test | InferentialChain | RoG-WebQSP union (local) | no (~500 two-hop test qs) | too few strict two-hop |
| SIB federated bio collection | >1,000 pairs total | SPARQL | 11 live endpoints, no frozen snapshot | no (avg ~6 triple patterns; ~100 federated) | answers not frozen; complexity mismatch — best provenance-native candidate, kept as future work |
| WikiWebQuestions | WebQuestions-scale (~4.9k total) | SPARQL (Wikidata) | requires full Wikidata | no | no fixed snapshot; smaller than CWQ |
| LC-QuAD 2.0 | 30,226 | SPARQL | live DBpedia/Wikidata | 3,714 candidates | remote-endpoint materialization failures (prior experience) |

## C. Why CWQ is the strongest match

1. Only candidate with ≥1,000 *measured* held-out strict two-hop questions
   plus a fixed downloadable graph snapshot plus gold executable SPARQL.
2. It directly removes the biggest methodological weakness of the existing
   RoG-WebQSP result (oracle paths derived from gold answers).
3. Heterogeneous vocabulary: 5,689 relations across the full held-out union.
4. Licensing: CWQ is a free research benchmark (Talmor & Berant, NAACL'18);
   RoG-CWQ is a public HF dataset (no explicit license tag — flagged in §Q);
   GrailQA would have been CC BY-SA 4.0 but is infeasible here.

## D. Compatibility counts and rejection reasons (Stage 1)

`data/cwq/compatibility_summary.json`; parser = `scripts/profile_cwq.py`
(parses gold SPARQL; boilerplate filters whitelisted; EXISTS blocks tracked
by brace balance).

Combined held-out: **1,267 / 7,050 strict two-hop** (test 664/3,531,
validation 603/3,519; all `composition` type).  Rejection classes (test /
validation): multi-anchor joins incl. grounded type constraints 1,033/1,068;
3+ triple chains/trees 691/674; ORDER BY/LIMIT/temporal-EXISTS 388/454;
two triples not a dependent chain 387/418; non-boilerplate FILTER 225/194;
manual/unparsed SPARQL 126/49; UNION/OPTIONAL/MINUS 17/61.
Anchor mapping (answer-independent, via `q_entity` + relation_1 orientation):
1,172 unique-topic-entity matches, 91 single-topic-entity fallbacks,
10 literal MIDs; 0 unmapped.

## E. Graph and fixture statistics

- Full held-out union (capacity analysis only, `data/cwq/full_union_capacity.json`):
  **1,055,994 entities, 3,447,420 unique forward edges, 5,689 relations**,
  2,019,811 distinct (source, relation) keys, max key fanout 429, p99 = 14.
- Fixed evaluation union (1,267 selected subgraphs, deduplicated, built once
  before any query): 293,028 entities, 854,421 unique forward edges,
  1,708,842 directed records incl. generated inverses.
- Primary workload fixture (b=8, cap=50): 75,611 entities x 5,203 relations
  (393.4M dense directory rows), 472,793 edge rows kept of 634,946 available,
  global frontier 8.

## F. Owner-partition methodology

Owners are **synthetic deterministic partitions** (not a real federation),
generated once before query execution; three MPC computation servers are held
fixed while external owner count N varies over 1, 2, 4, 8.
- subject-hash: SHA256(source) mod N; inverse edges follow the forward edge.
- edge-hash: SHA256(canonical forward triple) mod N.
- relation-domain: SHA256(Freebase domain prefix of the base relation) mod N.
Recorded per partition: per-owner edge and key counts, volume skew, keys
spanning multiple owners, per-question contributing owners and cross-owner
chains (all in each run's `summary.json`).

## G. Retrieval accuracy (Stage 4, cleartext oracle, held-out, gold-SPARQL paths)

Primary (b=8, k=32, cap=50, 3 owners subject-hash):
**1,184/1,267 = 93.45%**, Wilson 95% CI [91.95%, 94.68%]; empty retrievals 83
misses of which 79 empty; test split 613/664 = 92.32%, validation 571/603 =
94.69%; plaintext at identical bound = 93.45% (**gap 0.00 points**);
unclipped fixture ceiling = 93.61%.

## H. Accuracy-loss decomposition (primary run)

1. Loss before fixture ceiling: **6.39 points** (81 questions whose gold
   answer is not two-hop-reachable in the RoG subgraph union — snapshot
   coverage, not privacy).
2. Fanout/top-k capacity loss: **0.16 points**.
3. Relation-paged vs same-bound plaintext: **0.00 points**.
4. LLM generation loss after successful retrieval: 13.7 points conditional
   (§I).
None of these is a cryptographic privacy cost; §N states what is.

## I. Ollama generation (Stage 6)

300 distinct sampled questions, evidence-only prompting, llama3:70b-q2-4k,
0 errors, 3,636 s.  **Overall 233/300 = 77.67%** [72.62, 82.01].
Retrieval hits in sample: 270/300 (90.0%).  **Generation accuracy given
retrieval hit: 233/270 = 86.30%.**  Retrieval misses are included in the
denominator, not silently dropped (all 30 generated wrong/empty answers).

## J. Cleartext performance (primary run)

Layout preparation once: 164.9 s; retrieval 1.14 s for 1,267 queries =
**0.90 ms/query** (batched, prepared layouts); total wall 262 s
(4:25 including union build and baselines); peak RSS 10.35 GB.

## K. MP-SPDZ performance (Stage 7, Temi, semi-honest dishonest-majority, 3 parties on localhost)

10-query diverse gold-SPARQL closure (91 entities x 224 relations, 396 edge
rows, bound 8, top-k 4, frontier 5): **all 10 queries reconstructed exactly**
(160 fields = 2 batches x 5 queries x top-4 x 4 fields) against the
independent cleartext oracle.
- MPC time incl. Temi preprocessing: 20.45 s total (10.41 + 10.03 per
  5-query batch) = **2.04 s/query amortized**.
- Communication: 1,986 MB global (993.0 MB/batch, party0 468.6 MB/batch) =
  **198.6 MB/query**.
- Reported rounds (multithreaded, double-counted by MP-SPDZ): 40,058/batch.
- One-time compilation ~19.4 min (reused across batches); peak RSS 20.0 GB.
- 25-query closure (235 entities x 458 relations, 1,148 edge rows):
  **all 25 queries exact** (400 fields; 5 batches of 5).  MPC incl.
  preprocessing 84.44 s total (16.1–17.6 s/batch) = **3.38 s/query**;
  communication 15,665.7 MB (3,133.1 MB/batch) = **626.6 MB/query**;
  64,044 reported rounds/batch; one ~48-min compile reused across all five
  batches; peak RSS 50.3 GB (compile phase); total wall 50:37.
- Compile-size limit found: a 10-query batch over a 106k-row dense directory
  exceeded 30-min compile (10M+ instructions, 51 GB); mitigated by 5-query
  batches and cap-3 closures.  Cleartext lookup time was never extrapolated
  to MPC time.

## L. Owner-count and partition ablations (Stage 5, all 1,267 questions each)

| config | hit rate | notes |
|---|---|---|
| bound 3 / 8 / 16 (k=32,c=50,subj3) | 93.05 / 93.45 / 93.61% | bound is the only quality lever; b=16 reaches the ceiling |
| top-k 4 / 16 / 32 (b=8) | 93.37 / 93.45 / 93.45% | ranking nearly irrelevant (§ scoring study) |
| cap 10 / 50 / 100 (b=8,k=32) | 93.45% each | cap moves only distractor mass (ceiling 93.53 vs 93.61) |
| owners 1 / 2 / 4 / 8 subject-hash | 93.45% each | retention invariant; skew ≤ 1.09; cross-owner-chain questions 0/604/882/1031 (0–81%) |
| edge-hash 3 / 8 owners | 93.61% each | 47.8k/54.7k keys span owners → federation-wide retention rises to 24/64 (global frontier), reaching the ceiling; cross-owner questions 985/1099 |
| relation-domain 4 owners | 93.45% | volume skew 4.89 — realistic thematic split is heavily imbalanced; 287 cross-owner questions |

Scoring study (`scoring_study_k{4,32}.json`): ranking headroom 0.00 points at
k=32 and 0.55 at k=4; answer-independent KG-aware scores (inverse target
degree, relation selectivity) recover 0.31 of those 0.55 points over the
synthetic positional score.  The shipped `1 + position % 9` score is
irrelevant to hit-rate at k>=16 and must not be described as semantic
ranking.

## M. Memory and scalability limitations

- Cleartext path: 10.35 GB peak at 1,267 questions / 393M-row dense
  directory; layout preparation is the wall-clock bottleneck (165 s).
- MPC path: dense-directory program size, not runtime, is the binding
  constraint (compile blow-up above ~0.5M directory-row-x-query products);
  the KQA-style type-blocked/bucketed directory is the known fix and is not
  yet wired into the CWQ fixture builder.
- Full-graph (1.06M entities) MPC execution was **not** attempted and is not
  claimed.

## N. Security / leakage statement

Public: entity and relation vocabularies (ontology), owner count, per-owner
key counts and page budgets, fanout bound, global frontier, top-k, question
count and batch size.  Owner edge volumes are public by construction of the
layout.  Secret: query source entity, both relations, all intermediate
frontiers, result contents, owner contributions to a result (evidence handles
verified owner-blind: `handles_owner_blind: true`).  Result cardinality is
fixed-shape (top-k padded rows, valid flags secret-shared); per-query MPC
work is query-independent (fixed access pattern), so timing does not depend
on the secret query within a fixture.  Repeated identical queries produce
fresh reshared outputs but identical public shapes — linkage across queries
is not hidden at the workload level (batch membership is public).  Malformed
client inputs are not validated beyond field-membership; malicious inputs
are out of scope for Temi (semi-honest).  The localhost harness centralizes
shares operationally; it is not a three-host deployment.

## O. Comparison with previous datasets

| dataset | held-out two-hop qs | graph (entities/edges) | path source | retrieval | MPC validated |
|---|---|---|---|---|---|
| MetaQA (2-hop) | 1,000 sampled | 12.7k / 86.2k | read from KB with answers | 96.70% (b=3) | earlier runs |
| LC-QuAD 2.0 | 3,714 candidates | live DBpedia | gold SPARQL | batch-dependent, endpoint-limited | no |
| KQA Pro | 21 val (199 total) | 17.8k / 385.8k | gold programs | 21/21 exact | 21/21 Temi, 38.45 s, 6,794 MB |
| RoG-WebQSP | 473 strict | 781k / 2.28M | **oracle (answer-derived)** | 71.88% (b=8) | no |
| **CWQ 1.1 (this work)** | **1,267** | **1.06M / 3.45M (full union)** | **gold SPARQL, answer-free** | **93.45% (b=8)** | **10/10 exact Temi** |

CWQ is now the largest, most defensible evaluation in the project: more
held-out two-hop questions than any prior dataset here, a bigger graph than
RoG-WebQSP, and answer-independent paths (which RoG-WebQSP lacks).  The
93.45% (CWQ) vs 71.88% (RoG-WebQSP) difference is a fixture-coverage
difference (CWQ ceiling 93.61 vs WebQSP ceiling 91.54 with much heavier
truncation loss there), not an algorithmic improvement claim.

## P. Defensible paper wording

"On the 1,267 held-out ComplexWebQuestions 1.1 questions whose gold SPARQL is
a pure dependent two-hop chain (664 test, 603 validation, of 7,050 held-out
questions profiled), relation-paged oblivious retrieval over one fixed union
of the RoG-CWQ subgraphs (293k entities, 854k unique edges) attains 93.45%
evidence hit rate (Wilson 95% CI [92.0%, 94.7%]) at public fanout bound 8 and
top-32 — identical to a non-private baseline truncated at the same public
bound; the unclipped fixture ceiling is 93.61%.  Relation pairs are parsed
from gold SPARQL and never from answers.  End-to-end with evidence-only
llama3-70B generation, 300 sampled questions answer at 77.7% (86.3%
conditional on retrieval success).  A 10-query workload closure executes
exactly under MP-SPDZ Temi (semi-honest, dishonest-majority, three localhost
parties) in 2.04 s and 199 MB communication per query amortized, and a
25-query closure in 3.38 s and 627 MB per query, matching the cleartext
oracle on every reconstructed field (560 fields total).  Owners are synthetic
deterministic partitions; under an 8-owner edge split, 87% of answered
questions combine evidence from multiple owners."

## Q. Claims that must NOT be made

- Not sublinear ORAM (linear relation-paged scan).
- Not malicious security (Temi/Semi are semi-honest).
- Not a real federation (synthetic owner splits; RoG-CWQ has no provenance).
- Not full-CWQ accuracy (strict two-hop subset: 18.0% of held-out questions).
- Not full-dataset MPC (10-query closure; cleartext oracle for the 1,267).
- Not official CWQ leaderboard accuracy (test answers come from RoG-CWQ).
- The 6.39-point ceiling loss is snapshot coverage, not privacy cost.
- The RoG-CWQ subgraphs were originally retrieved for GNN training; the
  union is a fixed benchmark snapshot, not canonical Freebase.
- RoG-CWQ carries no explicit dataset license tag; verify before
  redistribution.
- No claim of production readiness.

## R. Reproduction commands

```bash
# data (downloads: official CWQ 1.1 Dropbox JSON, HF rmanluo/RoG-cwq parquet)
# see scripts/README.md "ComplexWebQuestions 1.1" section
.venv/bin/python scripts/profile_cwq.py
.venv/bin/python -m pytest tests/unit/test_profile_cwq.py tests/unit/test_run_cwq_eval.py
PYTHONUNBUFFERED=1 /usr/bin/time -v .venv/bin/python -u scripts/run_cwq_eval.py \
  --questions 0 --seed 4242 --bound 8 --topk 32 --neighbourhood-cap 50 \
  --batch-size 100 --out results/cwq_cleartext_full1267_b8_k32_c50_<ts> \
  2>&1 | tee .../terminal.log
bash scripts/run_cwq_ablations.sh
.venv/bin/python scripts/study_cwq_scoring.py --run <primary_run> --topk 4
.venv/bin/python scripts/run_cwq_answers.py --run <primary_run> --answers 300
.venv/bin/python scripts/build_cwq_mpc_fixture.py --queries 10 --neighbourhood-cap 3 \
  --out data/cwq/mpc_fixture/q10_closure_c3
.venv/bin/python scripts/run_kqapro_relation_mpc.py \
  --fixture data/cwq/mpc_fixture/q10_closure_c3 \
  --output results/cwq_mpc_temi_q10c3_<ts> --protocol temi --batch-size 5 \
  --compile-timeout 7200 --runtime-timeout 7200
```

## S. Result and log paths

- Profiling: `data/cwq/{compatibility_summary.json,twohop_compatible.jsonl,rejected_examples.jsonl}`
- Capacity: `data/cwq/full_union_capacity.json`
- Primary run: `results/cwq_cleartext_full1267_b8_k32_c50_20260827T093228Z/`
  (`summary.json`, `per_question.jsonl`, `terminal.log`,
  `answers_a300.{jsonl,summary.json,terminal.log}`, `scoring_study_k{4,32}.json`)
- Smoke/pilot: `results/cwq_cleartext_smoke10_20260827T093007Z/`,
  `results/cwq_cleartext_pilot100_20260827T093043Z/`
- Ablations: `results/cwq_cleartext_full1267_*` (14 runs) +
  `results/cwq_runs_table.json` + `results/cwq_ablations_*.log`
- MPC: `results/cwq_mpc_temi_q10c3_20260827T100757Z/` (exact, per-batch logs);
  `results/cwq_mpc_temi_q25c3_*/`; failed oversized compile kept at
  `results/cwq_mpc_temi_q10_20260827T09{3550,3649}Z/`
- Pointer files: `results/latest_cwq_run.txt`, `results/latest_cwq_mpc_run.txt`

## T. Prioritized next improvements

1. Wire the type-blocked/bucketed compact directory (already used for KQA
   Pro) into the CWQ MPC fixture builder to lift the compile-size ceiling and
   scale MPC validation to 50+ queries and larger closures.
2. Two-hop-with-constraint class (~1,000 additional held-out questions with a
   grounded type filter on ?x): support a public type post-filter inside the
   circuit to roughly double compatible coverage.
3. Provenance-native evaluation on the SIB federated collection (small-N,
   genuinely federated) as a companion experiment.
4. Snapshot-coverage recovery: the 79 empty retrievals stem from anchors
   missing the queried relation in RoG subgraphs; re-materialize those
   questions' first hop from a full Freebase dump to close part of the
   6.4-point ceiling gap.
5. Score field: replace the synthetic score with public relation-selectivity
   (measurable, answer-independent), mattering only for k<=8 and LLM context
   ordering.
