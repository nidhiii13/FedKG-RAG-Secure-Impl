# What each recorded benchmark still claims

Thirty-seven benchmarks accumulated here, and some **contradict each other** —
because later measurements corrected earlier ones. Read cold, this directory
would let someone quote a number that has since been invalidated. That is the
failure mode this file exists to prevent.

Every benchmark is classified below. `tests/unit/test_terminology_guard.py`
asserts the list is complete, so a new benchmark cannot be added without saying
where it stands.

Statuses: **stands** (unchallenged), **superseded** (a later, better measurement
replaced its numbers), **invalidated** (a load-bearing input was measured and
found wrong), **scoped** (correct, but only under conditions that must be quoted
with it).

---

## Invalidated — do not quote

| Benchmark | Why |
| --- | --- |
| `relation_page_cost_model.json` | Assumes maximum `(source, relation)` degree of **16**. Measured on the real graph: **4,176** — understated 261×. Every MetaQA projection in it rests on the wrong input. See `metaqa_real_degree_profile.json`. |

## Scoped — correct, but the condition must be quoted alongside

| Benchmark | The condition |
| --- | --- |
| `relation_paged_crossover.json` | The 17.5× advantage is at **synthetic narrowing factor 8**. Real MetaQA is **1.00** (1.97 forward-only). This number does **not** transfer to MetaQA and must never be presented as a MetaQA result. |
| `relation_paged_backend_ab.json` | The negative result (paged 1.15× *slower*) is on an unskewed fixture — that is the honest half of the crossover pair and should travel with it. |
| `volume_hiding_on_real_federation.json` | Break-even spans 1.6–214 queries depending on `page_size`. The favourable end is driven by `page_size = 2,089`, itself a consequence of the narrowing premise failing. Pooling looks best where the paged layout looks worst. |
| `committee_size_versus_threshold.json` | The 5-party option preserves *absolute* 2-collusion tolerance but needs 3-of-5 honest (60%) versus 1-of-3 (33%). Not a free win. The *t*-private PIR claim in it is **unverified**. |
| `malicious_protocol_overhead.json` | MASCOT runs correctly at 31×/155× cost. This does **not** make the system maliciously secure — both I/O boundaries stay unauthenticated. |
| `hybrid_directory_planning.json` | **Model-only, no circuit.** The best layout found: type-blocked partition for the 54.1% of edges matching each entity's primary type + hashed compact for the 45.9% residual. **92×** against the dense folded circuit at full edge coverage, 1.80× better than hashed-alone sized the same safe way. The primary-type map is edge-derived here, so the split ratio is a sizing estimate, not a deployable one. |
| `compact_directory_planning.json` | **Negative result, and model-only — no circuit exists.** Sizing the directory to the key count instead of the keyspace is *not* a general win: it trades padding for a per-slot tag comparison, and below ~40× sparsity that is a loss. Modelled **slower** on every fixture small enough to run in MPC (0.31–0.73×); wins only at 67.7× sparsity (2.39×) and at full WebQSP scale (100×, a projection). MetaQA can never benefit — 18 relations means no padding to remove. |
| `relation_folded_directory.json` | **5.68x less communication on the largest WebQSP fixture measured, byte-identical output** (verified by reconstructing every output value under both circuits on 5 arms). Hop two was resolving the same relation once per frontier address. The ratio is layout-dependent — it grows with relation count and frontier width, so it is 5.68x on WebQSP and 1.42x on MetaQA — and the eval-fixture figures in it are extrapolations, not runs. Removes a *factor*, not the dense-keyspace *term*. |
| `rag_quality_at_scale.json` | The measured **97.2%** evidence-hit over **400** real MetaQA questions (CI [95.6, 98.9]) and **86%** answer accuracy **stand** — re-measured 2026-08-16 at 97.25%. But its headline **"privacy costs ~0.3 points" is CORRECTED to 2.00 points**: the 97.5% it called a ceiling was still clipped to top_k=4, and the true unclipped ceiling is 99.25%. Quote 2.0, never 0.3. |
| `webqsp_smoke.json` | A **smoke test on 32.5% of WebQSP**, not a WebQSP evaluation — 137 of 203 questions are one-hop and outside the circuit's shape. Oracle only; the circuit was not run. Its value is what it *scopes*: on a real 5-party federation, skew collapses to 1.07×, `global_frontier` degrades to owners × bound, and the privacy cost rises to 9.09 points. |
| `metaqa_federated_split_reality_check.json` | Carries an in-place `CORRECTION`: premise 2 (volume skew) fails only under the *bundled* random split, and is restored by any realistic federation model. Premise 1 fails structurally. |

## Superseded — later numbers replace these

| Benchmark | Superseded by |
| --- | --- |
| `volume_hiding_shuffle_cost.json` | `sort_join_growth.json`. Its "amortises after 0.2 queries" used shuffle cost alone; the descriptor remap is 99.5% of the true cost. Corrected total is 15.1% per query at a 250-query epoch, not 6.9%. |
| `rag_privacy_quality_price.json` | `rag_quality_at_scale.json`, which measures the same thing over 400 questions with confidence intervals instead of 40. |
| `rag_retrieval_quality.json` | `rag_quality_at_scale.json`, which measures the same thing over 400 questions with confidence intervals instead of 40. |
| `frontier_compaction_microbenchmark.json` | `relation_paged_ablation.json`, which ablates compaction against a true counterfactual rather than a no-op arm. |

## Stands

| Benchmark | Claim |
| --- | --- |
| `rag_fixture_optimisation.json` | **3.47× less communication, 3.12× faster, identical answers** — bound 4→3 (past the quality plateau) plus global frontier (worth 3× here because an entity split keeps each key with one owner). Remaining cost is 55% directory, which is 88% padding — and that padding is the privacy. **Scoped by `webqsp_smoke.json`:** the 3× depends on the entity split; under WebQSP's recorded edge split the federation bound is owners × bound and the saving does not transfer. |
| `rag_end_to_end.json` | **First RAG run through the oblivious backend.** Query graph → paged retrieval → readable evidence → Ollama answer, reusing SimGRAG's prompts and model unchanged. Closes the largest claim/evidence gap. One query, not an evaluation. |
| `federation_split_comparison.json` | The federation split decides whether **both** claims pay. An entity split keeps relation diversity (1.353× retention gain vs 1.052×) **and** gives larger volume skew (3.19× vs 1.78×). A relation split flatters the packed-scan baseline by separating relations at the owner boundary. |
| `metaqa_federated_execution.json` | **First real-MetaQA execution** of the paged backend, over a relation-type federation (skew 1.78×, owner-blind handles). Correct against the oracle. Also records that relation-type splitting and relation-keying **interact**: the split suppresses most of the keying benefit. |
| `threat_model_cost_fork.json` | **261×** premium for 2-of-3 over 1-of-3 on the growing term. The session's strongest single result. |
| `relation_paged_multiaxis.json` | Cost model validated out-of-sample: 5.25% mean held-out error. Owner count is near-quadratic (exponent **1.80**). |
| `relation_paged_scaling.json` | Cost is linear in `entities × relations`; batching does **not** amortise. |
| `relation_paged_ablation.json` | Layout ≈8× versus micro-optimisations ≈2.1× — resists over-attribution. |
| `doram_viability_under_dishonest_majority.json` | DORAM `batch_init` is 56 billion triples at MetaQA scale; access itself is 2.65× *cheaper* than scanning. |
| `owner_side_oram_construction.json` | Owner-side construction removes in-circuit init. Recursion tuned χ=256 for 2.16×. Cleartext-verified, circuit not run. |
| `global_frontier_compaction.json` | Quadratic-in-owners → linear. 1.79× at 4 owners, executed and result-identical. The *mechanism* stands; how much it saves depends on the split — see `webqsp_smoke.json`, where an edge split leaves the federation bound at owners × bound. |
| `global_frontier_bound_check.json` | The federation bound is MPC-verified, not trusted. Accepts a sound bound, rejects an understated one. |
| `efficiency_stack.json` | 2.51× cumulative, threat model untouched. |
| `pooling_circuit_verification.json` | Pooling executed in MPC; all 8 blocks remap correctly under a secret non-identity permutation. |
| `sort_join_growth.json` | `n·log₂(n)` law, 4.2% spread. Corrected the remap estimate upward 2.2×. |
| `metaqa_real_degree_profile.json` | **Narrowing factor 1.00** on real MetaQA — but carries `CORRECTION_aggregate_retention`: that worst-case ratio understates the layout. At bound 2 relation keying retains **66.9%** against source keying's **43.2%** (1.55×). The speed claim does not transfer; the **retention** claim does. |
| `metaqa_narrowing_fixes.json` | Hub filtering does **not** restore narrowing at any threshold. Forward-only gives 1.97 at a semantic cost. |
| `metaqa_real_lossiness.json` | The supported scan discards **56.8%** of MetaQA at fanout 2. Real, unsolved. |
| `relation_paged_regression.json` | 10/10 distinct queries, both backends agreeing against independent oracles. |
| `relation_paged_overflow_validation.json` | Multi-page overflow executed losslessly. |
| `candidate_level_ranking_probe.json` | Candidate-level ranking is graph-size-independent — but requires revealing the query to owners. |

---

## If you quote one number from this directory

**261×** — the threat-model premium (`threat_model_cost_fork.json`). It is measured,
out-of-sample validated, reproduced across two independent workloads, and
unaffected by every dataset finding above.

## If you are writing the paper

The two claims with real-data standing are the **measurement study** and
**volume hiding under a modelled federation**. The relation-paged layout — the
most-optimised component here — is the one the real data does not support.
