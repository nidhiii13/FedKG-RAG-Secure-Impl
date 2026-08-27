# `multiparty_fss/` — Configurable N-Party FSS Private Lookup

A genuine, paper-backed **N-party distributed point function** path for this
repository's private-lookup pipeline, implemented from:

> Elette Boyle, Niv Gilboa, Yuval Ishai. **Function Secret Sharing.**
> EUROCRYPT 2015 (Part II), LNCS 9057, pp. 337–367 — Section 3.1,
> *"A p-party protocol"*, Algorithms 3–4 (`Gen^{p0}`, `Eval^{p0}`).
> Official PDF: <https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf>

- **Construction ID:** `bgi15-mpdpf-p0` (used in every wire artifact).
- **Parties:** configurable `N ∈ [3, 10]` (`N = 2` remains the legacy path).
- **Claimed threat model:** semi-honest, honest majority —
  `t = ⌊(N−1)/2⌋` colluding evaluators (the construction itself is proven
  against up to `N−1`; see [SECURITY.md](SECURITY.md)).
- **Output group:** `GF(2)^64` — shares combine by **XOR**, not mod-2^64
  addition. This is a deliberate, documented difference from the two-party
  path, forced by the construction's parity-based cancellation.
- **Availability:** all `N` output shares are required; none may be missing.
- **Status:** research prototype. Passing tests establish functional
  correctness only, **not** cryptographic privacy.

Design and research record: [docs/multiparty_fss/research_and_design.md](../docs/multiparty_fss/research_and_design.md)
(construction selection, threat model, trust boundaries, full specification)
and [docs/multiparty_fss/two_party_audit.md](../docs/multiparty_fss/two_party_audit.md)
(the audit that motivated a separate implementation).

## Relationship to the existing two-party path

The two-party path (`src/crypto`, `src/runtime`, `src/orchestration`,
`tools/fss_cli`, `third_party/myl7-fss`) is **unchanged** — same code, same
wire formats, same tests, same CLI. It remains available as an explicit
compatibility mode and is documented as a **two-server non-collusion model**,
not an honest-majority deployment (with two evaluators, one corruption is not
a strict minority). Nothing in this package reinterprets two-party keys as
multi-party keys or vice versa: every artifact is version- and
construction-tagged, and each path rejects the other's material
(`tests/test_two_party_separation.py`).

Reused from the existing tree (neutral, party-count-free infrastructure
only): `OpaqueIndexSnapshot` / `ReplicatedEvaluatorIndex`, the HMAC ID layer,
the universe-digest algorithm, the candidate-handle provider, and the
candidate-slot layout builder. The cryptographic core here shares **no** code
with the myl7/fss tree DPF.

## Layout

```
multiparty_fss/
  params.py        parameter set (N, t, n), grid dimensions, params digest
  prg.py           G = SHAKE-256 with domain separation
  parity.py        E_p / O_p parity-array sampling (Notation 2)
  keygen.py        Algorithm 3, Gen^{p0}
  evaluate.py      Algorithm 4, Eval^{p0} (scalar / batch / universe sweep)
  combine.py       XOR output decoder (all N shares required)
  keyshare.py      key-share container + strict (de)serialization
  domain.py        rank encoding over the shared opaque universe
  projection.py    XOR candidate projection (+ conversion from legacy layout)
  requests.py      request/response envelopes + fail-closed N-party coordinator
  replication.py   N-store snapshot replication with versioned manifests
  service.py       evaluator store + evaluation service (one per evaluator)
  orchestrator.py  client-side keygen -> dispatch -> combine
  tools/           CLI: export stores, run evaluator, combine, run query
  tests/           correctness / negative / wire / separation / CLI suites
  benchmarks/      bench_multiparty_fss.py
  docs/            paper_to_code_mapping.md, wire_format.md, benchmarks.md
```

## API

```python
from multiparty_fss import (
    MpDpfParams, generate, evaluate, evaluate_many, combine,
    serialize_key_share, deserialize_key_share,
)

params = MpDpfParams.create(domain_bits=12, party_count=5)   # t defaults to 2
shares = generate(alpha=173, beta=1, party_count=5, threshold=2, params=params)
y = {s.party_index: evaluate(s, 173) for s in shares}
assert combine(y, party_count=5) == 1          # XOR reconstruction
payload = serialize_key_share(shares[0])       # versioned JSON dict
restored = deserialize_key_share(payload)      # strict, fail-closed
```

`generate(...)` refuses `N < 3`, `N > 10`, `t < 1`, `t > N−1`, out-of-domain
`alpha`, out-of-group `beta`. `threshold` defaults to `⌊(N−1)/2⌋`.

## Running the role-separated flow

No build step is required (pure Python + NumPy; uses the repo's `.venv`).

```bash
# 1. Replicate opaque snapshots (from the existing export pipeline) to N stores:
.venv/bin/python multiparty_fss/tools/export_multiparty_snapshots.py \
  --snapshot /path/partition-a.json --snapshot /path/partition-b.json \
  --evaluator mp_fss_0 --evaluator mp_fss_1 --evaluator mp_fss_2 \
  --output-dir /tmp/fedkg-mpfss

# 2a. One-process demo (client + N in-process evaluators):
FEDKG_SETUP_KEY=... FEDKG_PRIO_HANDLE_KEY=0123456789abcdef \
.venv/bin/python multiparty_fss/tools/run_multiparty_fss_query.py \
  --store /tmp/fedkg-mpfss/mp_fss_0 --store /tmp/fedkg-mpfss/mp_fss_1 \
  --store /tmp/fedkg-mpfss/mp_fss_2 \
  --party-count 3 --threshold 1 --domain entity --label "Alice" \
  --request-id req-1 --query-nonce nonce-0123456789 --capacity 16

# 2b. Process-per-evaluator: pipe one request JSON into each worker...
.venv/bin/python multiparty_fss/tools/run_multiparty_evaluator.py \
  --store /tmp/fedkg-mpfss/mp_fss_1 --evaluator-id mp_fss_1 < request_1.json

# ...then combine exactly N responses (N is explicit, never inferred):
.venv/bin/python multiparty_fss/tools/combine_multiparty_shares.py \
  --party-count 3 --request-id req-1 < responses.json
```

The combined result maps opaque candidate IDs to reconstructed values
(`beta` at the matched candidate, nothing else) — the same
candidate-ID/value shape the legacy flow hands to downstream Prio3
aggregation, which is evaluator-agnostic
(`src/aggregation/prio3_candidates.py` accepts any topology; the
FSS-evaluator count restriction of the legacy pipeline lives in
`src/orchestration/prio_candidate_pipeline.py`, which this path does not
use).

## Tests

```bash
.venv/bin/python -m pytest multiparty_fss/tests -q         # 148 tests
.venv/bin/python -m pytest tests/unit tests/integration -q # legacy suites, unchanged
```

Covered: correctness for `(N, t) ∈ {(3,1), (4,1), (5,2), (7,3)}` plus `N=8`
(hit reconstructs `beta` for `beta ∈ {0, 1, 2^64−1, random}`; **every** other
domain point reconstructs 0; boundary and random alphas; scalar = batch =
universe-sweep equivalence; repeated randomized trials; an independent
brute-force re-implementation of Eval as a cross-check oracle), the complete
negative-validation matrix (missing/duplicate/extra shares, wrong index/count/
threshold, mixed keygens/constructions/versions/parameter sets, mismatched
request IDs and digests, truncated/corrupted/malformed keys, unsupported N and
t, out-of-group values, bool-as-int), wire-format round trips, cross-path
rejection in both directions, N-store replication with tamper detection,
role-separated CLI end-to-end runs, and fail-closed behavior when an
evaluator is missing or duplicated.

**No official test vectors exist** for this construction (no other public
implementation as of 2026-08-27 — see research_and_design.md §1.3), so
cross-validation is against an in-repo independent model, and this is
recorded as a limitation.

## Benchmarks

```bash
.venv/bin/python multiparty_fss/benchmarks/bench_multiparty_fss.py \
  --universe 4096 --universe 65536 --repeat 5
```

Methodology and measured results: [docs/benchmarks.md](docs/benchmarks.md).

**Paper-level evaluation** (baselines incl. a same-toolchain two-party tree
DPF and naive sharing; MetaQA, WebQSP *real 5-party federation*, LC-QuAD 2.0,
KQA Pro, CWQ; timing repetitions; real process-separated socket deployment;
figures + CSV artifacts): [docs/paper_evaluation.md](docs/paper_evaluation.md),
driver [benchmarks/paper_eval.py](benchmarks/paper_eval.py), dataset harness
[benchmarks/eval_datasets.py](benchmarks/eval_datasets.py), artifacts in
[benchmarks/paper_results/](benchmarks/paper_results/). Earlier exploratory
run: [docs/dataset_eval.md](docs/dataset_eval.md).
Headline (U = 65,536 points, n = 16, single CPU core): keygen 3–36 ms,
per-evaluator keys 24 KiB (N=3) to 2.9 MiB (N=8), full-universe evaluation
8–119 ms, scalar evaluation 0.06–5.3 ms. Prototype numbers, not production
claims.
