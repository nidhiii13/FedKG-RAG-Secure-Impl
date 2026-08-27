# Paper-to-Code Mapping — BGI15 `Gen^{p0}` / `Eval^{p0}`

Source of truth: Boyle, Gilboa, Ishai, *Function Secret Sharing*, EUROCRYPT
2015, official proceedings PDF
(<https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf>),
Section 3.1 "A p-party protocol": Notation 2, Algorithm 3 (`Gen^{p0}`),
Algorithm 4 (`Eval^{p0}`), plus the in-text correctness and secrecy
arguments on the two pages following Algorithm 4. This mapping was produced
by re-reading those algorithms line by line against the code after
implementation (task Phase 11); the checklist results are at the end.

Index convention: the paper is 1-based (`γ ∈ [ν]`, `j ∈ [2^{p−1}]`,
parties `1..p`); the code is 0-based everywhere (`row ∈ [0, ν)`,
`j ∈ [0, S)`, `party_index ∈ [0, N)`). `S` below abbreviates `2^{p−1}`.

## Definitions

| Paper | Code |
|---|---|
| Definition 3: point function `P_{a,b} : {0,1}^n → {0,1}^m`, `P(a)=b`, else `0^m` | `f_{α,β} : [2^n] → GF(2)^64`; `m = 64` fixed (`params.OUTPUT_BITS`), `β` a 64-bit word |
| Definition 1: p-party **additive output decoder** over Abelian `G`; `{0,1}^m` under `⊕` | `combine.combine` / `combine.combine_vectors`: XOR of exactly N shares |
| Definition 2: T-secure FSS (adversary sees `(k_i)_{i∈T}`) + Remark 2.1 (t-security) | Claim recorded in metadata (`threshold`); no code counterpart — the definition governs what the tests may and may not claim (see SECURITY.md) |
| Key size accounting `\|σ_i\| = νλ2^{p−1}`, `\|cw's\| = μm2^{p−1}` | `MpDpfParams.sigma_bytes = ν·S·16`, `MpDpfParams.cw_bytes = S·μ·8` (λ=128, m=64 in bytes) |

## Notation 2 (parity arrays)

| Paper | Code |
|---|---|
| `E_p` = p×S binary arrays whose columns are **all** even-parity p-bit strings; `O_p` likewise odd | `parity.parity_columns(p, odd)` enumerates the `2^{p−1}` column integers; column `c` encodes `A[i,j]=bit i of c` (`parity.party_holds`) |
| `A ∈_R E_p` / `A ∈_R O_p` (uniform) | `parity.sample_parity_array`: Fisher–Yates shuffle of the full column set with `secrets.SystemRandom` — a uniform permutation of the enumerated columns, which is exactly the uniform distribution over `E_p`/`O_p` |
| `e_δ·b`: length-`μ` block vector, `b` at block δ | `keygen.generate`: `target = np.zeros(mu); target[delta] = beta` |

## Algorithm 3 — `Gen^{p0}(1^λ, a, b)` → `keygen.generate`

| Line | Paper | Code |
|---|---|---|
| 1 | `G : {0,1}^λ → {0,1}^{mμ}` a PRG | `prg.expand_seed`: SHAKE-256(`params.prg_context()` ‖ seed) squeezed to `8·μ` bytes, viewed as `μ` little-endian uint64 words. λ = 128 (`SEED_BYTES = 16`). The PRG identifier and context are bound into `params_id`/wire (see deviations D3) |
| 2 | `μ ← ⌈2^{n/2}·2^{(p−1)/2}⌉`, `ν ← ⌈2^n/μ⌉` | `MpDpfParams.mu = ceil(isqrt-exact sqrt(2^{n+p−1}))`, `MpDpfParams.nu = ceil(2^n/μ)` — exact integer arithmetic, no floats (`params._ceil_sqrt`) |
| 3 | regard `a` as `(γ, δ)`, `γ ∈ [ν]`, `δ ∈ [μ]` | `MpDpfParams.cell(alpha) = divmod(alpha, mu)` — documented **row-major** convention (the paper fixes no explicit pairing); `Eval` uses the identical mapping, which is the only consistency requirement |
| 4 | `A_γ ∈_R O_p`; `A_{γ'} ∈_R E_p` for `γ' ≠ γ` | `arrays = [sample_parity_array(p, odd=(row == gamma)) for row in range(nu)]` |
| 5 | `ν·2^{p−1}` independent seeds `∈ {0,1}^λ` | `seeds[row][j] = _random_seed()` — `secrets.token_bytes(16)`, resampled if all-zero (deviation D1) |
| 6 | `cw_1..cw_S ∈ {0,1}^{mμ}` random s.t. `⊕_j (cw_j ⊕ G(s_{γ,j})) = e_δ·b` | first `S−1` words uniform (`secrets.token_bytes(8μ)`); `cw_S = e_δ·b ⊕ (⊕_j G(s_{γ,j})) ⊕ (⊕_{j<S} cw_j)` — the uniform distribution on the constraint's affine subspace, sampled by solving for the last word |
| 7 | `σ_{i,γ'} = (s_{γ',1}·A_{γ'}[i,1]) ‖ … ‖ (s_{γ',S}·A_{γ'}[i,S])` | per party, per row: 16-byte block = seed if `party_holds(columns[j], i)` else `0^16` |
| 8 | `σ_i = σ_{i,1} ‖ … ‖ σ_{i,ν}` | `b"".join(blocks)` with rows outer, `j` inner — matches `keyshare.seed_blocks()`'s `(ν, S, 16)` reshape |
| 9 | `k_i = (σ_i ‖ cw_1 ‖ … ‖ cw_S)` | `MpDpfKeyShare(sigma=…, correction_words=cw.tobytes())`; the CW block is **identical in every `k_i` by construction** (the paper concatenates the same `cw` list into each key); metadata fields (N, t, party index, keygen ID, params digest, universe binding) are wire-format additions, not construction changes |
| 10 | return `(k_1..k_p)` | list ordered by `party_index` 0..N−1 |

## Algorithm 4 — `Eval^{p0}(i, k_i, x)` → `evaluate.evaluate` / `evaluate_many` / `evaluate_universe`

| Line | Paper | Code |
|---|---|---|
| 1–2 | same `G`, `μ`, `ν` | same `MpDpfParams` — parameters travel inside the key share and are digest-checked, so Gen/Eval can never disagree on `μ, ν` |
| 3 | `x = (γ', δ')` | `params.cell(point)` (identical row-major mapping as Gen line 3) |
| 4–5 | parse `k_i` into `σ_i`, `cw_1..cw_S`; `σ_i` into per-row λ-bit blocks | `keyshare.seed_blocks()` `(ν, S, 16)` view; `keyshare.cw_matrix()` `(S, μ)` uint64 view; lengths re-validated against the parameter set at parse time |
| 6 | `y_i ← ⊕_{1≤j≤S, s_{γ',j}≠0} (cw_j ⊕ G(s_{γ',j}))` | `evaluate._row_vector`: for each `j` with a non-zero seed block, `acc ^= cw[j]; acc ^= expand_seed(seed)` — the `s ≠ 0` sentinel is exactly the paper's held test (made unambiguous by deviation D1) |
| 7 | return `y_i[δ']` | `int(row_vector[delta])` — block δ' of the `μ`-block vector = word δ' of the uint64 vector (m = 64 = one word) |
| — | (batching, not in paper) | `evaluate_many` groups points by row and computes each `_row_vector` once; `evaluate_universe` sweeps rows `0..⌈U/μ⌉−1` and slices. Both are algebraically identical to per-point Line 6–7 and are tested equal to the scalar path |

## Correctness / secrecy arguments (paper §3.1 text) → tests

| Paper claim | Where verified functionally |
|---|---|
| `γ' ≠ γ`: every `cw_j ⊕ G(s_{γ',j})` occurs an even number of times across parties ⇒ XOR 0 | `tests/test_correctness.py`: every non-α point of the **full domain** reconstructs 0 for (3,1), (4,1), (5,2), (7,3), N=8 |
| `γ' = γ`: odd multiplicities ⇒ `⊕_i y_i = ⊕_j (cw_j ⊕ G(s_{γ,j})) = e_δ·b` | α reconstructs β incl. β ∈ {0, 1, 2^64−1, random} |
| independent restatement of the algebra | `tests/test_correctness.py::_model_combined` — a second, cache-free implementation of Line 6 used as a cross-check oracle |
| secrecy: any p−1 rows of `A_{γ'}` identically distributed for `E_p` vs `O_p`; `cw`'s masked by an exclusive honest seed | **not testable by execution** — this is the cryptographic claim, carried by the paper's argument (see SECURITY.md). Tests only pin the *sampling* (uniform over the full column enumerations) that the argument requires |

## Documented deviations from the paper text

- **D1 (zero-seed sentinel).** Eval line 6 uses `s ≠ 0` as "held". A held
  seed drawn as `0^λ` (probability `2^{−128}`) would be skipped, which the
  paper carries as a negligible correctness error. `Gen` resamples zero
  seeds; statistical distance ≤ `ν·S·2^{−128}` per generation, and the
  correctness error becomes 0. (`keygen._random_seed`.)
- **D2 (pair mapping).** The paper says "regard a as a pair (γ, δ)" without
  fixing the bijection; with the adjusted `μ` of line 2 a bit-split is not
  possible, so a div/mod row-major mapping is used, identically in Gen and
  Eval. Any fixed bijection yields the same functionality and security (the
  grid cell of α is what matters; the distribution of (γ, δ) is a public
  deterministic function of α either way).
- **D3 (PRG instantiation).** The paper assumes an abstract PRG. Instantiated
  as SHAKE-256 with a domain-separation context binding construction ID,
  scheme version, and the parameter set (n, p, μ, ν, m, λ). The context
  contains nothing party- or session-specific (all holders of a seed must
  expand identically). Assumption documented in SECURITY.md.
- **D4 (metadata).** Key shares/requests/responses carry binding metadata
  (versions, construction, params digest, N, t, party index, keygen ID,
  universe digest) that the paper does not discuss. These fields are outside
  the construction; they only ever cause *rejection*, never a change to the
  computed values.
- **D5 (output group size).** `m` is fixed to 64 and `β` is an unsigned
  64-bit word; the paper allows any `m`. `μ` blocks of `m` bits map to one
  NumPy uint64 word per block.

## Threshold-specific review (task Phase 9)

`t_claimed = ⌊(N−1)/2⌋` is enforced as the default everywhere
(`params.honest_majority_threshold`); the construction supports and the
paper argues the stricter `t ≤ N−1` (Remark 2.1 + §3.1), which the library
accepts only as an explicit opt-in and every shipped tool leaves at the
default. A coalition of `t+1` is **never** claimed private under the
deployment model (even where the theorem would still cover it, the system
claim stays at honest majority — the weakest-link rule of the surrounding
repo). Party indices are bound into keys, manifests, requests, and responses
and cross-checked at every hop, so shares/metadata cannot be confused across
configurations (tested). Reconstruction requirements are stated separately
from the privacy threshold and are **not** derived from it.

| N | Required honest parties (claimed model) | Max corrupted t (claimed) | Max t (paper theorem) | Shares needed to reconstruct | Missing-party tolerance |
|---|---|---|---|---|---|
| 3 | 2 | 1 | 2 | 3 | 0 |
| 4 | 3 | 1 | 3 | 4 | 0 |
| 5 | 3 | 2 | 4 | 5 | 0 |
| 7 | 4 | 3 | 6 | 7 | 0 |
| 8 | 5 | 3 | 7 | 8 | 0 |
| 10 | 6 | 4 | 9 | 10 | 0 |

## Phase 11 checklist (executed after implementation)

1. Algorithms re-read line by line against code — this document is the record.
2. Group operations: XOR only, on `uint64` vectors / Python ints validated to
   `[0, 2^64)`; no modular addition anywhere on this path; no signed types
   (`dtype '<u8'` everywhere; `int(np.uint64)` is non-negative). ✔
3. Bit/byte order: PRG output and CWs are little-endian uint64 words
   (`'<u8'`, explicit); serialization is raw-bytes base64 with lengths
   recomputed from parameters. Party-membership bit order is the documented
   `bit i of column ↔ party i` convention, used by Gen only (Eval never
   inspects columns). ✔
4. Domain encoding: identical `cell()` in Gen and Eval; rank domain bound to
   the universe digest; `n = ⌈log₂ max(U,2)⌉` recomputed and cross-checked by
   the evaluator service. ✔
5. PRG expansion: one context for all parties within a parameter set; no
   party/session data in the context; seed length enforced. ✔
6. Correction words: single CW block shared across keys (per Algorithm 3);
   constraint solved for the last word; verified by the full-domain
   correctness tests and the independent model. ✔
7. Party-index handling: coordinator keys by `party_index` field (never list
   position); duplicates/out-of-range/missing rejected; store manifests bind
   index ↔ ordered ID list. ✔
8. Threshold calculations: `⌊(N−1)/2⌋` in one place
   (`honest_majority_threshold`), tested for N = 3..10. ✔
9. Reconstruction coefficients: trivial (XOR of all N — coefficient 1 each);
   no Lagrange machinery to get wrong; `combine` requires the exact index
   set. ✔
10. Serialization/parsing: strict field sets, types, lengths; no regex on
    security-relevant input anywhere in the package (`json` + schema walks). ✔
11. Context/domain separation: PRG context (construction‖version‖params);
    digest labels all version-disjoint from legacy
    (`fedkg-mpfss-*` vs `fedkg-fss-*`). ✔
12. RNG: `secrets` everywhere key material or permutations are drawn; no
    `random`, no fixed seeds outside tests; grep-verified. ✔
13. Key/nonce reuse: fresh keygen ID per generation; mixing across
    generations rejected at parse/combine; PRG seeds drawn fresh per
    generation. ✔
14. No fixed production keys: the only fixed constants are public labels
    (context strings, version tags). ✔
15. Accidental collusion: evaluator stores refuse other evaluators' shares
    (identity + index binding); orchestrator sends share i to evaluator i
    only; tested misrouting is rejected. ✔
16. Coordinator sees reconstructed outputs by design (it is the authorized
    recipient) — stated in SECURITY.md; evaluators never see each other's
    outputs. ✔
17. Dealer/setup leakage: none beyond the client's own inputs (client is the
    dealer). ✔
18. Error paths: all validation raises typed exceptions; no partial
    combine, no default-allow branch; CLI tools exit nonzero on any
    validation error (tested). ✔
19. Sanitizers/static analysis: `.venv/bin/python -m compileall multiparty_fss`
    clean; an AST-level unused-import scan clean (pyflakes is not installed in
    the repo venv and no dependency was added for it); insecure-RNG grep
    (`random`, `mt19937`, `np.random`) clean; C/CUDA sanitizers n/a (no
    native code on this path). ✔
20. Full test suites re-run after review — commands and results in
    README.md / benchmarks.md. ✔
