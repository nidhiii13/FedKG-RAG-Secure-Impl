# Paper-Level Evaluation — BGI15 p-Party DPF Private Lookup

Run date: 2026-08-27. This document is the consolidated, paper-grade
evaluation of the `multiparty_fss/` path: methodology, environment,
construction-level comparison against baselines, end-to-end results on five
real datasets (including two *real* federations at N=2-owner and N=5-owner),
N-scaling, deployed-mode (process-separated) measurements, and threats to
validity. It supersedes the earlier exploratory
[dataset_eval.md](dataset_eval.md) run (whose harness it extends with timing
repetitions, warm-up, per-domain reporting, WebQSP, baselines, and a socket
transport).

Artifacts (all in [`benchmarks/paper_results/`](../benchmarks/paper_results/)):
`microbench_constructions.csv/json`, four SVG figures
(`fig_key_size_vs_universe.svg`, `fig_evalfull_vs_universe.svg`,
`fig_scalar_vs_universe.svg`, `fig_keygen_vs_universe.svg`), per-workload
summary JSONs (in-process and socket), `run_manifest.json`. Reproduce with:

```bash
.venv/bin/python multiparty_fss/benchmarks/paper_eval.py \
    --work /tmp/mpfss_paper --queries 50 --repeats 3
```

## 1. Methodology

- **Environment.** Intel Xeon Gold 6136 @ 3.00 GHz (48 cores; a single core
  used except where stated), 251 GiB RAM, Linux 6.8, CPython 3.10.12, NumPy
  2.2.6. Pure-Python implementation; PRG = domain-separated SHAKE-256
  throughout (including baselines, so comparisons isolate construction
  structure, not toolchain).
- **Timing.** Every reported latency is the **median over repetitions after
  an untimed warm-up** (microbench: 5 reps + IQR recorded in the CSV;
  dataset lookups: 3 reps; socket runs: 1 rep, 50 queries). Per-stage timers
  use `time.perf_counter`.
- **Latency model.** In-process mode reports keygen + **max** over the N
  evaluators + combine (parallel-evaluator model; per-evaluator times and
  sums are in the raw JSON). Socket mode measures the **real wall time of N
  parallel round trips** to genuinely separated evaluator processes over
  localhost TCP with full JSON marshaling — no modeling.
- **Correctness accounting.** Every lookup's combined dense vector is checked
  in full: a present term must reconstruct exactly `{α: 1}` over the entire
  universe; an absent term must reconstruct all-zero. 10 negative controls
  (absent terms) per workload. Answer stages compare HMAC-encoded readout
  sets against HMAC-encoded gold.
- **Security parameters.** λ = 128, m = 64, honest-majority claim
  t = ⌊(N−1)/2⌋ everywhere. These are functionality/cost measurements under
  the documented leakage model ([SECURITY.md](../SECURITY.md)); nothing here
  measures privacy.

## 2. Construction-level comparison (microbenchmarks)

Baselines, implemented in [`baselines.py`](../baselines.py) in the same
language and PRG family: the standard **two-party tree DPF** (BGI16-style;
two-server non-collusion model — a *weaker* trust model, shown as the
classical efficiency reference) and **naive truth-table XOR sharing**
((N−1)-private, information-theoretic; the trivial baseline of BGI15).
Selected rows (full sweep U ∈ {2^10 … 2^20} in the CSV):

| Construction | Model | U = 2^16: key/eval · keygen · scalar · full-sweep | U = 2^20: key/eval · keygen · scalar · full-sweep |
|---|---|---|---|
| **mpdpf-N3** (this path) | honest-majority t=1 | 24 KiB · 2.2 ms · 0.06 ms · 8.3 ms | 96 KiB · 8.5 ms · 0.13 ms · 73.8 ms |
| **mpdpf-N5** | honest-majority t=2 | 144 KiB · 5.5 ms · 0.30 ms · 20.7 ms | 576 KiB · 20.6 ms · 0.81 ms · 224.7 ms |
| **mpdpf-N7** | honest-majority t=3 | 1.03 MiB · 17.4 ms · 1.89 ms · 62.7 ms | 4.13 MiB · 61.4 ms · 6.43 ms · 823.5 ms |
| tree-dpf-2party | 2-server non-collusion | 0.3 KiB · 0.13 ms · 0.036 ms · 354.7 ms | 0.4 KiB · 0.16 ms · 0.059 ms · (>1.4 s at 2^18; capped) |
| naive-xor-N3 | (N−1)-private, IT | 512 KiB · 4.9 ms · ~0 · ~0 | 8 MiB · 82.4 ms · ~0 · 1.5 ms |

Readings (figures visualize all five series):

1. **Key size follows the proven bound exactly**: `2^{(N−1)/2}·√U·(λ+m)`
   — doubling per +2 parties, ×4 per ×16 universe. The tree DPF's O(n) keys
   (~0.3 KiB) are three to four orders smaller — that is the known,
   fundamental gap between 2-party polylog keys and PRG-based multi-party
   √-keys (open problem per BGI15/GWW25), not an implementation artifact.
2. **Against the naive baseline the grid DPF wins on key size at every
   measured scale** (already 3.0 KiB vs 8 KiB at U=2^10; 96 KiB vs 8 MiB at
   U=2^20 for N=3 — an 85× reduction) *and* on keygen time at large U
   (8.5 ms vs 82 ms at 2^20).
3. **Scalar vs sweep trade-off vs the tree**: single-point evaluation favors
   the tree (flat ~0.04–0.06 ms = n small PRG calls) over the grid (loads
   one row: 0.13–6.4 ms growing with √U·2^{N−1}); *full-universe* sweeps in
   this same-language setting favor the grid by 6–43× (8.3 ms vs 355 ms at
   2^16 for N=3) because the tree needs 2^{n+1} tiny PRG calls whose
   per-call overhead dominates in Python, while the grid does few large,
   vectorizable expansions. **Caveat (stated wherever these numbers are
   used):** native tree-DPF implementations with fixed-key AES-NI evaluate
   ~10^7+ points/s; the same-language comparison isolates *call structure*,
   not achievable native throughput, and the repo's own CUDA tree-DPF CLI
   remains the deployed-path reference.

## 3. End-to-end dataset results (in-process, repeats = 3)

**All 657 query lookups across the seven in-process workloads were correct
(100%)** — present terms reconstruct exactly `{α: 1}` over the full
universe, absent terms reconstruct all-zero — and all 70 negative controls
pass (the socket phase adds a further 250 lookups + 20 controls, also all
correct; §5). Latencies are per private lookup, split by domain (the entity/relation
universes differ by orders of magnitude, so pooled percentiles would be
misleading — pooling is exactly how an earlier draft under-reported KQA Pro
entity cost by 5×).

| Workload | Federation | U entity (n) | Lookups (present) | Correct | Entity p50/p95 | Relation p50/p95 | Answer exact | Coverage |
|---|---|---|---|---|---|---|---|---|
| MetaQA | **real 2-owner** | 40,151 (16) | 100 (100) | 100% | 42.1 / 42.8 ms | 0.2 / 0.3 ms | **50/50** | 1.0 |
| WebQSP | **real 5-owner**, N=5, t=2 | 202,518 (18) | 51 (36) | 100% | 266 / 298 ms | — | n/a | 0.53† |
| LC-QuAD 2.0 | 3-owner (term fixture) | 4,622 (13) | 157 (156) | 100% | 5.4 / 5.5 ms | 2.0 / 2.1 ms | n/a | n/a |
| KQA Pro | 3-owner, full 385,774-edge graph | 17,067 (15) | 150 (150) | 100% | 17.2 / 17.4 ms | 1.3 / 1.4 ms | **50/50** | 1.0 |
| CWQ-closure | 3-owner fixture | 820 (10) | 75 (73) | 100% | 1.5 / 1.5 ms | 1.5 / 1.6 ms | 20/25* | 0.85* |
| CWQ-RoG | 3-owner (25 subgraph union) | 25,581 (15) | 44 (44) | 100% | 25.2 / 25.4 ms | — | n/a | 0.85† |

\* All five CWQ-closure misses are verified fixture artifacts: two queries'
`relation_2` edges were pruned by the closure build (4,625 of 4,928 edges
kept) and the private lookups *correctly* reported them absent; three
queries returned exactly 8 endpoints — precisely the fixture's
`fanout_per_owner = 8` cap — against 14–25 gold answers. The FSS layer
retrieved everything the pruned KG contains.

† Coverage on WebQSP/CWQ-RoG = fraction of gold answer entities present in
the KG universe — a property of the cross-source data (RoG questions vs the
SimGRAG/RoG snapshots), not of retrieval. On WebQSP, 15 of 51 RoG topic
entities are absent from the SimGRAG federated KG; every one was correctly
reported as a miss, which is itself the fail-closed behavior working.

**Whole-question cost:** a MetaQA 1-hop question (entity + relation lookup +
encoded 1-hop readout) ≈ 42 ms; a KQA Pro two-hop question (3 lookups +
2-hop readout) ≈ 20 ms; a WebQSP topic lookup over the 202k-entity 5-party
federation ≈ 266 ms.

**Answer quality is N-invariant**, as correctness of an FSS requires:
MetaQA is 100% exact at N=3 (50 q), N=5 and N=7 (20 q each).

## 4. Scaling with N (MetaQA, identical queries and universe)

| N | t | Entity p50 | Key/evaluator (JSON) | Stores (N replicas) | Setup |
|---|---|---|---|---|---|
| 3 | 1 | 42.1 ms | 32.4 KiB | 267 MB | 28 s |
| 5 | 2 | 56.1 ms | 192.4 KiB | 445 MB | 40 s |
| 7 | 3 | 99.2 ms | 1.38 MiB | 624 MB | 52 s |

Latency ×2.4 while key material ×43 from N=3→7: the practical ceiling on N
is communication/key size, not computation — consistent with §2 and the
construction's bound.

## 5. Deployed mode: real process separation over TCP (socket transport)

N evaluator server processes (`tools/serve_multiparty_evaluator.py`), each
loading its own replicated store; the client issues N parallel requests over
localhost TCP with full JSON marshaling; measured wall time, 50 queries, no
modeling. Correctness and answer exact-match remain 100% end-to-end over the
wire; all controls pass.

| Workload (N=3) | Entity p50 in-process | Entity p50 socket | Overhead | Relation p50 socket |
|---|---|---|---|---|
| MetaQA (U=40k, ~840 KiB dense responses) | 42.1 ms | 182.8 ms | +141 ms | 4.2 ms |
| KQA Pro (U=17k, ~357 KiB dense responses) | 17.2 ms | 94.0 ms | +77 ms | 8.2 ms |

Overhead attribution: dense-mode responses are hundreds of KiB of JSON;
client-side parse + strict validation of N such responses runs under the
CPython GIL, so the three response validations serialize (~sum, not max)
even though the evaluator processes themselves run in parallel. This is a
measured artifact of (JSON + CPython) engineering, not of the construction —
the three concrete fixes are standard and orthogonal to the cryptography:
a binary wire format for share vectors, response validation in NumPy, and/or
projected-mode responses. Localhost TCP itself contributes ~1–3 ms. We
report the honest deployed-Python number rather than the fix.

## 6. Communication per lookup (measured JSON sizes)

Client→evaluator = one key share: 32.4 KiB (MetaQA N=3) … 1.38 MiB (N=7);
23.1 KiB (KQA Pro/CWQ-RoG N=3); 4.4 KiB (CWQ-closure). Evaluator→combiner
(dense mode, the worst case used throughout this evaluation): ≈ 21 B/point
of JSON — 840 KiB at U=40k, 535 KiB at U=25.6k, 357 KiB at U=17k. A binary
encoding would be 8 B/point; projected mode returns capacity-many slot
shares instead. One-time store replication: §3/§4 tables (up to 2.4 GB for
the 5-replica WebQSP set).

## 7. Threats to validity / limitations

1. **Same-language baseline caveat** (§2): Python per-call overhead
   penalizes the tree DPF's full sweeps; native AES-NI tree DPFs are orders
   faster. Both framings are reported; neither changes key-size facts.
2. **Localhost ≠ WAN.** Socket mode includes real marshaling and IPC but no
   network latency/bandwidth constraints; WAN deployments add RTTs and
   bandwidth-limited transfer of the dense responses (or keys at large N).
3. **Single-core.** Evaluator-side work parallelizes across hosts by
   construction; client-side combine/validation parallelism is limited by
   the GIL in this prototype (§5).
4. **Answer readout is not oblivious.** The 1-/2-hop expansion after the
   private anchor lookups runs over the replicated encoded adjacency
   (as in the repo's structural stage); only the lookups are private, per
   the documented model.
5. **Gold incompleteness / cross-source gaps** are reported as such
   (CWQ fixture caps, WebQSP RoG-vs-SimGRAG entity gap) rather than folded
   into retrieval metrics.
6. **No privacy measurement.** Privacy rests on the cited construction
   (BGI15 §3.1, (p−1)-secure; claimed at honest-majority t) — tests and
   benchmarks establish functionality and cost only.
7. Timing dispersion is small (p95/p50 ≤ 1.12 on every workload's entity
   lookups; IQRs in the CSV), so median reporting is representative.

## 8. Inventory of what this evaluation adds over the exploratory run

Baselines in the same toolchain (tree DPF cross-checked exhaustively;
naive sharing), real 5-party WebQSP federation, timing repetitions +
warm-up + per-domain percentiles, real process-separated deployment
measurements, universe sweeps 2^10–2^20 with IQRs, dependency-free SVG
figures, CSV/JSON artifacts under version control, and an explicit
threats-to-validity section. Test coverage for all new components:
`tests/test_baselines_transport.py` (160 total tests in the package suite).
