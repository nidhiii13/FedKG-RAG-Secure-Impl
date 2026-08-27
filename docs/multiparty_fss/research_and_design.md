# Multi-Party FSS: Research, Selection, and Design

Research date: 2026-08-27. All bibliographic facts below were re-verified
against primary sources on this date (official proceedings PDFs, the IACR
ePrint archive, arXiv, and publisher pages); nothing is cited from memory.
Where a source could not be fully verified, that is stated explicitly.

This document covers Phases 2–5 of the multi-party FSS task: primary-source
research (§1–§3), the mandated threat model (§4), trust boundaries (§5), and
the full security/correctness specification of the implemented construction
(§6). The implementation lives in [`multiparty_fss/`](../../multiparty_fss/);
the paper-to-code mapping is in
[`multiparty_fss/docs/paper_to_code_mapping.md`](../../multiparty_fss/docs/paper_to_code_mapping.md).

---

## 1. Primary sources examined

### 1.1 Selected construction

**[BGI15]** Elette Boyle, Niv Gilboa, Yuval Ishai. *Function Secret Sharing.*
EUROCRYPT 2015 (Part II), LNCS 9057, Springer, pp. 337–367.
DOI [10.1007/978-3-662-46803-6_12](https://doi.org/10.1007/978-3-662-46803-6_12).
Official proceedings PDF (IACR archive, used for this work):
<https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf>.

Verified content (read directly from the proceedings PDF):

- **Definition 2 (Function Secret Sharing)** — p-party, `T`-secure FSS with
  respect to an output decoder `DEC` and function class `F`:
  `Gen(1^λ, f) → (k_1,…,k_p)`; `Eval(i, k_i, x) → y_i`; **correctness**
  `Dec(Eval(1,k_1,x),…,Eval(p,k_p,x)) = f(x)`; **security** as an
  indistinguishability experiment in which the adversary chooses `f_0, f_1`
  with equal domains, receives `(k_i)_{i∈T}` for `f_b`, and must guess `b`
  with at most negligible advantage (non-uniform PPT adversaries).
- **Definition 1 / p-party additive output decoder** — decoding is the sum of
  the p output shares in an Abelian group `G`; `{0,1}^m` is interpreted as an
  Abelian group under XOR (paper, end of Section 2: "in particular, {0,1}^n is
  interpreted as an Abelian group with respect to the xor group operator ⊕").
- **Remark 2, item 1 (Adversary Structure)** — "We say an FSS scheme is
  *t-secure* for threshold t < p if it is T-secure for all T ⊂ [p] of size
  |T| ≤ t. By default … 'secure FSS' will refer to (p−1)-security, in which
  any strict subset of parties may be corrupted."
- **Section 3.1, "A p-party protocol", Notation 2, Algorithms 3 and 4
  (`Gen^{p0}`, `Eval^{p0}`)** — the multi-party DPF construction implemented
  here, transcribed in full in §6.2 below.
- **Claimed security and key size** (paper §1.1 and §3.1): the scheme shares a
  DPF `P_{a,b}: {0,1}^n → {0,1}^m` "secure against any coalition of at most
  p−1 key holders", with key length `O(2^{n/2}·2^{(p−1)/2}·m)`; the in-text
  accounting at the end of §3.1 gives `|σ_i| = νλ·2^{p−1}` plus correction
  words `μm·2^{p−1}`, i.e. key size `O(2^{n/2}·2^{(p−1)/2}(λ+m))`. §1.1 states
  the same bound as `O(λ·2^{p/2}·N^{1/2})` for domain size `N = 2^n`.
- **Proof status**: the proceedings gives the complete construction, a full
  correctness argument, and an explicit secrecy argument (any p−1 rows of the
  parity arrays are identically distributed for `E_p` vs `O_p` sampling; the
  correction words are random subject to one constraint that is masked by the
  PRG output of at least one seed excluded from every (p−1)-subset of keys).
  It is a proof sketch, not a numbered theorem; the two-party algorithms in
  the same section defer full proofs to the full version. The (p−1)-security
  of this construction is independently restated as established prior art by
  [BKO22] and [GWW25] below.

### 1.2 Corroborating and competing sources

**[BKO22]** Paul Bunn, Eyal Kushilevitz, Rafail Ostrovsky. *CNF-FSS and its
Applications.* PKC 2022 (Part I), LNCS 13177/13178, Springer,
DOI [10.1007/978-3-030-97121-2_11](https://doi.org/10.1007/978-3-030-97121-2_11).
ePrint: <https://eprint.iacr.org/2021/163> (received 2021-02-17, last revised
2021-12-23; PDF read directly). Verified content:

- Confirms the BGI15 multi-party scheme and its threshold: "the only known
  result in the FSS setting, based on OWF alone, is a (p−1, p)-DPF scheme of
  communication proportional to √N from [BGI15]" and "A more efficient
  (p−1)-out-of-p DPF solution is given by [BGI15] and has communication of
  essentially O(√N) (more precisely O(√(N·2^p)·(λ+m)))" — which equals
  `2^{n/2}·2^{p/2}(λ+m)`, matching §1.1 of BGI15.
- Their own results: a (2,5)-DPF with communication `O(N^{1/4})`; in general,
  with `p > dt` parties, a (t,p)-DPF with communication
  `O(N^{1/2d}·√(2^{p'})·p^t·d·(λ+m))` (their §1.1; also an information-theoretic
  variant `O(N^{1/d}·p^t·d·m)`); and a 1-out-of-3 CNF-DPF with polylogarithmic
  keys. Output range concretized as "the field GF[2^m], represented by m-bit
  strings" (their footnote 8).
- Keys in their (t,p) schemes are in **CNF/replicated format** (each key given
  to several parties), and the constructions route through a d-dimensional
  product of point functions with non-interactive share multiplication.

**[GWW25]** Aarushi Goel, Mingyuan Wang, Zhiheng Wang. *Multiparty Distributed
Point Functions.* CRYPTO 2025, Springer
(chapter DOI [10.1007/978-3-032-01884-7_5](https://doi.org/10.1007/978-3-032-01884-7_5)).
ePrint: <https://eprint.iacr.org/2025/1074> (PDF read directly; latest
revision 2025-06-09). Verified content:

- Informal Theorem 1: for n parties and point functions `D → Z_{p^q}`
  (constant prime p), assuming OWFs, "there exists an (n−1)-private multiparty
  DPF where the size of each party's function share is O(|D|^{1/2+ε}·n^3)".
- Confirms BGI15 as the state of the art it improves on: "the only other known
  construction of multiparty DPFs [BGI15] produces shares of size
  O(√|D|·2^{n−1})", and (their footnote 2) "The only other construction in
  Minicrypt that we are aware of is limited to at most four parties [BGIK22a]
  and allows only a single corrupt party."
- Their construction replaces BGI15's deterministic seed-assignment
  combinatorics with a *randomized combinatorial design*; they also prove any
  deterministic-design multiparty DPF must have exponential-in-n share size,
  and derive (t,n)-threshold DPFs via share conversion [CDI05].

**[CBM15]** Henry Corrigan-Gibbs, Dan Boneh, David Mazières. *Riposte: An
Anonymous Messaging System Handling Millions of Users.* IEEE S&P 2015,
pp. 321–338, DOI [10.1109/SP.2015.27](https://doi.org/10.1109/SP.2015.27);
arXiv: <https://arxiv.org/abs/1503.06115>. Multi-server DPF-like scheme with
`s` servers tolerating `s−1` collusions, built from *seed-homomorphic PRGs*
under DDH-type assumptions; communication `O(√N)`. Characterization
cross-confirmed by [BKO22] ("using PK assumptions and operations, specifically
seed-homomorphic PRG, [CBM15] also achieve a scheme with communication that
depends on √N, but has better dependency on p").

**[DHRW16]** Yevgeniy Dodis, Shai Halevi, Ron Rothblum, Daniel Wichs. *Spooky
Encryption and its Applications.* CRYPTO 2016. Under LWE, a (p−1, p)-FSS for
all functions exists (as characterized by [BKO22] §1.1: "under the LWE
assumption, a (p−1, p)-FSS scheme for all functions can be constructed
[DHRW16]"). Not examined beyond this; listed for completeness.

**[DHPR25a]** Marc Damie, Florian Hahn, Andreas Peter, Jan Ramon. *DDH-based
schemes for multi-party Function Secret Sharing.* NordSec 2025, Springer
(chapter DOI [10.1007/978-3-032-14782-0_1](https://doi.org/10.1007/978-3-032-14782-0_1));
ePrint: <https://eprint.iacr.org/2025/1805>. Honest-majority multi-party DPF
with `O(∛N)` key size from DDH; reports key sizes "up to 10× smaller (on
realistic problem sizes) than state-of-the-art schemes".

**[DHPR25b]** Same authors. *Eliminating Exponential Key Growth in PRG-Based
Distributed Point Functions.* DPM 2025 (ESORICS workshop);
arXiv: <https://arxiv.org/abs/2509.22022>. PRG-based optimization of the
BGI15-style multi-party DPF **under an honest-majority assumption**, "keys up
to 3× smaller than the best known multi-party DPF".

**[KP25]** Toomas Krips, Pille Pullonen-Raudvere. *Multi-Party Distributed
Point Functions with Polylogarithmic Key Size from Invariants of Matrices.*
ePrint: <https://eprint.iacr.org/2025/978> (preprint, last revised
2026-01-16; **not** verified as published at a peer-reviewed venue as of the
research date). Polylogarithmic keys for any party count, from *novel*
assumptions (generic-group-flavored, linear code equivalence, factoring).

**[BKO-ITC22]** Bunn, Kushilevitz, Ostrovsky. *Information-Theoretic
Distributed Point Functions.* ITC 2022
(author-hosted PDF: <https://ntt-research.com/wp-content/uploads/2023/08/Information-Theoretic-Distributed-Point-Functions.pdf>).
Information-theoretic DPF variants; listed as related work only — no claims
from it are load-bearing here.

**Two-party baseline (already in the repo):**
**[GI14]** Niv Gilboa, Yuval Ishai. *Distributed Point Functions and Their
Applications.* EUROCRYPT 2014, LNCS 8441,
DOI [10.1007/978-3-642-55220-5_35](https://doi.org/10.1007/978-3-642-55220-5_35).
**[BGI16]** Boyle, Gilboa, Ishai. *Function Secret Sharing: Improvements and
Extensions.* ACM CCS 2016, DOI
[10.1145/2976749.2978429](https://doi.org/10.1145/2976749.2978429); ePrint
<https://eprint.iacr.org/2018/707>. The tree DPF with 65 correction words
implemented by the vendored `third_party/myl7-fss` and driven by
`tools/fss_cli/main.cu` is this two-party line of work. It is **inherently
two-party** (one seed pair, complementary control bits, sign-bit evaluation);
no loop generalizes it to p ≥ 3.

### 1.3 Public implementation availability (as of 2026-08-27)

Searched: GitHub, ePrint artifact links, author pages. Found — all
**two-party**: `myl7/fss` (vendored here; CUDA/C++), Google
`distributed_point_functions` (C++), `facebookresearch/GPU-DPF`,
`weikengchen/libdpf`, `MatanHamilis/DPF` (Rust), `MatanHamilis/dmpf`
(multi-**point**, still 2-party; IEEE S&P 2025), sycret, funshade.
**No public implementation of any ≥3-party DPF/FSS construction was found**
— not for BGI15's p-party scheme, not for BKO22, not for GWW25, and no
artifact was located for DHPR25a/b (their papers report benchmarks but the
searches surfaced no repository). The claim "an N-party FSS implementation is
not publicly available" is, to the best of a diligent search on the research
date, **true**. Consequently no official test vectors exist either;
cross-validation in this repo is against an independent brute-force model of
the construction plus the paper's correctness equation (see Phase 8 notes in
`multiparty_fss/README.md`).

License note: `third_party/myl7-fss` is Apache-2.0 (per its repository
metadata); it is neither modified nor reused by the new path. The new
implementation is original code written from the BGI15 paper text.

---

## 2. Candidate comparison

Answers to the task's evaluation questions, per candidate. "HM" = the mandated
honest-majority threshold `t = ⌊(N−1)/2⌋`.

| Question | **BGI15 p-party (`Gen^{p0}`/`Eval^{p0}`)** — SELECTED | BGI16 tree DPF (current 2-party) | BKO22 CNF-FSS | GWW25 | CBM15 (Riposte s-server) | DHPR25a (DDH) / DHPR25b (PRG) | KP25 |
|---|---|---|---|---|---|---|---|
| Venue / year | EUROCRYPT 2015 | CCS 2016 | PKC 2022 | CRYPTO 2025 | IEEE S&P 2015 | NordSec 2025 / DPM 2025 | preprint only |
| >2 parties? | Yes, any p ≥ 2 (used here for p ≥ 3) | No | Yes, p ≥ 3 | Yes | Yes | Yes | Yes |
| One key share per evaluator? | Yes — `k_i` distinct per party (distinct seed subsets; CWs common to all keys by construction) | Yes (2) | **No** for (t,p) t>1 — CNF/replicated keys, each key held by several parties | Yes | Yes | Yes (per paper abstracts) | Yes |
| N fixed or runtime-configurable? | Runtime-configurable (p is a `Gen` parameter) | Fixed 2 | Configurable but parameter-regime-bound (needs p > dt) | Configurable | Configurable | Configurable | Configurable |
| Corruption threshold | **p−1** (any strict coalition) | 1 (the other party) | t with p > dt (also 1-out-of-3 CNF) | n−1 | s−1 | honest majority (t < N/2) | unclear (preprint) |
| Supports t < N/2 semi-honest? | **Yes — a fortiori**: T-security for all \|T\| ≤ p−1 ⊇ all \|T\| ≤ ⌊(N−1)/2⌋ (BGI15 Remark 2.1 makes t-security monotone in t by definition) | Only N=2 non-collusion (t=1 of 2 is *not* strict honest majority) | Yes in supported (t,p) regimes | Yes (a fortiori) | Yes (a fortiori) | Yes (natively) | unclear |
| Static or adaptive adversary? | Static (Definition 2 experiment fixes T) | Static | Static | Static | Static | Static | — |
| Computational or IT? | Computational (PRG) | Computational (PRG) | Both variants exist | Computational (OWF) | Computational (DDH) | Computational (DDH / PRG) | Computational, novel assumptions |
| Tolerates evaluator collusion? | Yes, any ≤ p−1 | No (any collusion of the 2 is total) | Yes, ≤ t | Yes, ≤ n−1 | Yes, ≤ s−1 | Yes, ≤ ⌊(N−1)/2⌋ | — |
| All N output shares needed to reconstruct? | **Yes** (additive/XOR decoder over all p shares) | Yes (both) | Reconstruction from the ℓ = C(p,t) key evaluations, each recoverable from any holder — some missing-party tolerance in CNF format | Yes for the additive DPF; their threshold variant allows qualified subsets | Yes | Yes (per abstract; additive decoders) | — |
| Qualified-subset reconstruction? | No | No | Partially (CNF replication) | Only in their (t,n)-threshold extension | No | No | — |
| Threshold availability or only threshold privacy? | **Privacy only.** Availability requires all N | Privacy only | CNF gives some availability | Threshold variant only | Privacy only | Privacy only | — |
| Trusted dealer required? | A key generator that knows (α, β) — the **query client** takes this role; no third-party dealer | Same | Same | Same | Same | Same | — |
| Client can act as dealer? | Yes (implemented that way) | Yes | Yes | Yes | Yes | Yes | — |
| Preprocessing / correlated randomness? | None | None | None | None | None | None | — |
| Interaction during Eval? | **None** (local evaluation; one-shot response) | None | None (non-interactive by FSS definition; their DORAM applications add protocol rounds) | None | None | None | — |
| Assumptions | PRG (⇔ OWF) | PRG | PRG / none (IT variant) | OWF | DDH (seed-homomorphic PRG) | DDH / PRG + honest majority | GGM-flavored + code equivalence + factoring |
| 64-bit input domain? | **No** — key size Θ(2^{n/2}); usable up to n ≈ 30. The repo's evaluated universes are ranks in a shared point list (n = ⌈log₂ U⌉ ≈ 14–20), so this fits; the 64-bit projected-HMAC domain is retained only as the *point namespace*, not the DPF domain (§6.4) | Yes (65 CWs) | No (same √-type scaling per dimension) | No (\|D\|^{1/2+ε}) | No (√N) | No (∛N / √N-type) | Plausibly yes (polylog) |
| Output in Z/(2^64)? | **No — output group changes to GF(2)^64 (XOR).** The construction's cancellation argument is parity-based; BGI15 states ranges as `{0,1}^m` under ⊕, and BKO22 concretizes GF[2^m]. The additive-mod-2^64 decoder of the two-party path does not apply (see §6.3) | Yes (Z_{2^64}) | GF[2^m] (their footnote 8) | Z_{p^q}, constant prime p — also **not** Z_{2^64} | Group generated by the seed-homomorphic PRG range (e.g., elliptic-curve or Z_q vectors) — not Z_{2^64} | additive groups per paper | — |
| Key size (per evaluator) | `ν·2^{p−1}·λ + 2^{p−1}·μ·m` bits with μ = ⌈2^{(n+p−1)/2}⌉, ν = ⌈2^n/μ⌉; i.e. O(2^{n/2}·2^{(p−1)/2}(λ+m)). Concretely (n=17, λ=128, m=64): ~35 KiB at p=3, ~208 KiB at p=5, ~1.5 MiB at p=7 | O(λn): ~1 KiB | O(N^{1/2d}·√(2^p)·p^t·d·(λ+m)) — asymptotically better in N, large p,t-dependent constants (p^t = 343 at (3,7)) | O(\|D\|^{1/2+ε}·n^3) — asymptotically better in p (poly), worse exponent in \|D\|; concrete constants unanalyzed in the paper | O(√N) group elements + exponentiations per Eval column | O(∛N) / BGI15-with-smaller-constants | polylog |
| Eval cost | 2^{p−1} PRG expansions of mμ bits per fresh row (rows amortize across a batch) | n AES calls per point | higher (d-dim product + share multiplications) | polynomial, unanalyzed concretely | exponentiations (public-key ops) per column | comparable to / better than BGI15 | — |
| Reference implementation? | **None public** (implemented here from the paper) | Yes (myl7/fss, vendored; Apache-2.0) | None found | None found | Riposte prototype existed for the *system*; none found for a reusable s-server DPF library | None found | None found |
| Interoperable with this repo's CUDA/C++ + Python split? | Yes — pure-Python + NumPy reference is adequate at prototype scale (§6.7); nothing in the construction requires GPU; the CUDA two-party CLI is untouched | Already integrated | Harder (CNF key routing changes the evaluator topology) | Unknown | Requires a group/exponentiation library not present in the repo | Unknown (no artifact) | Unknown |

### 2.1 Selection rationale

**Selected: the BGI15 p-party DPF (`Gen^{p0}`, `Eval^{p0}`, Algorithms 3–4).**

1. **It provably meets the mandated threat model with margin.** The
   construction is (p−1)-secure under BGI15's Definition 2 + Remark 2.1 —
   security against *every strict coalition*. The mandated threshold
   `t = ⌊(N−1)/2⌋ ≤ N−1` is therefore covered by direct instantiation of the
   same definition (T-security for all |T| ≤ p−1 trivially implies T-security
   for all |T| ≤ t; no reduction is needed, only monotonicity of the
   quantifier). This is *not* an N-out-of-N-reconstruction scheme whose privacy
   holds only against single parties: privacy holds against any p−1 of p.
2. **It is completely specified in the proceedings of a leading venue.**
   Algorithms 3–4 plus Notation 2 are a full, implementable specification
   (10 + 7 lines); no parameter is left to invention. Competing multi-party
   schemes at leading venues (BKO22, GWW25) are asymptotic results whose
   faithful implementation requires substantially more derivation (spread
   matrices / d-dimensional products with share multiplication; randomized
   combinatorial designs with amplification), have worse concrete constants at
   this repo's problem sizes (universe ranks n ≈ 14–20, p ∈ {3,4,5,7}), and
   have no artifacts to validate against.
3. **It is corroborated.** Two later leading-venue papers (BKO22 at PKC,
   GWW25 at CRYPTO) restate the construction, its (p−1) threshold, and its
   key size as the baseline they improve — a strong independent check on this
   implementation's reading of the paper.
4. **Concrete costs are acceptable at this repo's scale** (§2 table; measured
   numbers in `multiparty_fss/docs/benchmarks.md`).
5. **Uniformity.** One algorithm covers every required N (3, 4, 5, 7, …) with
   one wire format; the alternatives change shape per (t, p) regime.

**Why the honest-majority-native papers (DHPR25a/b) were not selected despite
matching the threat model exactly:** NordSec and DPM are reputable but not
among the mandated leading venues; the papers are months old with no located
artifacts and no third-party corroboration yet; and their gain over BGI15 is a
constant factor (≤10×/3× on key size) that is immaterial at this repo's
universe sizes. Choosing the stronger-threshold, better-corroborated
EUROCRYPT construction and *claiming only* the honest-majority threshold is
the conservative option. These papers are the natural upgrade path if key size
becomes binding.

**Why not KP25:** novel non-standard assumptions, preprint only.
**Why not CBM15:** public-key operations per evaluation column and an output
group tied to the seed-homomorphic PRG's range; DDH machinery absent from the
repo. **Why not composing the existing two-party DPF pairwise or replicating
its keys:** explicitly forbidden by the task, and rightly so — giving any
evaluator both tree-DPF keys (or running independent pairwise instances whose
transcripts a coalition can join) collapses privacy; no reduction to
`t = ⌊(N−1)/2⌋` security exists for such compositions, and none is claimed.

---

## 3. What the selected construction does *not* provide

Stated up front to prevent over-claiming (details in
[`multiparty_fss/SECURITY.md`](../../multiparty_fss/SECURITY.md)):

- **No malicious security.** Semi-honest only. A deviating evaluator can
  return a wrong share and silently corrupt the result; this is not detected.
  (Verifiable DPFs exist for 2 parties — e.g. de Castro–Polychroniadou,
  EUROCRYPT 2022 — but no verifiable ≥3-party analogue is implemented here.)
- **No threshold availability / robustness.** All N output shares are
  required. One missing or malformed response ⇒ the request fails closed.
- **No dishonest-majority privacy claim.** The *deployment model* claims
  `t = ⌊(N−1)/2⌋`. The construction's theorem covers up to N−1 corruptions;
  the implementation records both numbers in metadata but the system claim is
  the honest-majority bound (Phase 3 mandate; also the weakest-link principle:
  surrounding non-FSS components of this repo are analyzed only at honest
  majority or weaker).
- **No hiding of** the universe, its size, the access schedule, response
  lengths, or timing (§5.5 leakage list).

---

## 4. Threat model (Phase 3, normative for `multiparty_fss/`)

**Adversary.** A static, passive (semi-honest) adversary corrupts a coalition
`C` of evaluator parties with `|C| ≤ t = ⌊(N−1)/2⌋`; strictly more than half
of the N evaluators remain honest. Corrupted evaluators follow the protocol
exactly, retain everything they observe, analyze local state, and pool their
complete views. They do not alter, omit, forge, reorder, or replace messages.

Required instantiations (all tested): N=3, t=1 · N=4, t=1 · N=5, t=2 ·
N=7, t=3.

**Privacy goal.** For every pair of query points `α_0, α_1` (and payloads
`β_0, β_1`) consistent with the same public leakage (§5.5), the joint view of
any coalition `C`, `|C| ≤ t`, is computationally indistinguishable. Formally
this is BGI15 Definition 2 instantiated with `T = C`: the corrupted key tuple
`(k_i)_{i∈C}` for `f_{α_0,β_0}` vs `f_{α_1,β_1}` is indistinguishable, under
the PRG assumption on `G`. The coalition view consists of: the corrupted
parties' key shares, their local randomness, the replicated opaque-index
state, evaluator requests, their own scalar/batch output shares and
candidate-projection shares (all deterministic functions of key share + public
data, hence simulatable from the keys), protocol metadata, public parameters,
and all messages exchanged with client/coordinator. Because evaluation is
non-interactive and deterministic given the key and public store, the
coalition view reduces to `(k_i)_{i∈C}` plus public data — the exact object
of Definition 2.

**Basis of the claim.** BGI15 §3.1 establishes (p−1)-security of
(`Gen^{p0}`, `Eval^{p0}`); Remark 2.1's definition makes t-security for any
`t ≤ p−1` an immediate consequence (the security quantifier ranges over all
`T` with `|T| ≤ t ⊆ |T| ≤ p−1`). The deployed claim `t = ⌊(N−1)/2⌋` is
therefore *strictly inside* the proven threshold for every N ≥ 2. The
implementation never relies on the honest-majority bound being tight — but it
also never *claims* more than the paper argues, and the paper's argument is a
proceedings proof sketch (recorded honestly in §1.1 above).

**Explicitly out of scope / not protected:** malicious or actively deviating
evaluators; dishonest majority *as a system claim* (see §3); coalitions larger
than t (system claim) or larger than N−1 (construction); denial of service and
arbitrary response omission (fail-closed, not tolerated); forged or
inconsistent shares (rejected only when they violate structural validation —
a well-formed wrong value is undetectable); compromise of the client,
coordinator, or setup-key holder; side channels (timing, cache, memory) —
Python/NumPy execution is not constant-time and PRG expansion count depends
only on public parameters, but no constant-time claim is made; traffic
analysis (no cover traffic is implemented).

---

## 5. Trust boundaries (Phase 4)

| Question | Answer in this design |
|---|---|
| Who generates FSS keys? | The **query client** (the retrieval orchestrator acting for the querier). `generate()` runs locally in the client process. |
| Is keygen performed by the query client? | Yes. |
| Trusted dealer required? | No third-party dealer. The key generator necessarily knows (α, β) — in this deployment that is the client itself, which knows its own query. |
| What does the dealer learn? | Nothing beyond its own inputs: (α, β), public parameters, and the N key shares it created. It must delete key shares after dispatch (best-effort in Python; see SECURITY.md on memory limitations). |
| Does any setup authority retain correlated randomness? | No. There is no preprocessing or correlated randomness. The only long-lived secret is the repo's existing HMAC `FEDKG_SETUP_KEY` (namespace encoding), unchanged by this work. |
| Who knows α and β? | The client only (plus anyone holding ≥ N−? … no: *any* number of key shares up to N−1 reveals nothing; all N keys jointly determine α, β). |
| Who holds replicated DB/index contents? | All N evaluators hold byte-identical opaque snapshots (HMAC-encoded, plaintext-free). The universe is *not* secret from evaluators. |
| Who receives individual evaluator output shares? | Only the combiner (the client/coordinator role). Evaluators never see each other's outputs and never communicate with each other. |
| Who performs reconstruction? | The authorized result recipient = the client/coordinator that issued the request. `combine()` requires all N responses and full metadata consistency. |
| What does the result recipient learn? | The reconstructed per-slot values: β at the slot containing α's rank, 0 elsewhere — i.e., the intended query result (match indicator/payload) plus the public slot layout. |
| Does the coordinator learn the reconstructed output? | Yes — in this deployment the coordinator *is* the client. If the roles are split, the combiner learns exactly the reconstructed slot vector (which candidate handles are nonzero), same as the legacy path's documented coordinator leakage. |
| Can the coordinator collude with evaluators? Is it counted within t? | **The coordinator/client is NOT counted within t and MUST NOT collude with evaluators.** This is explicit, not ambiguous: the client knows α outright, so client–evaluator collusion trivially reveals α; a combiner-only coordinator that colludes with even one evaluator adds the reconstructed output and all N output share vectors to the coalition view, which is strictly more than Definition 2's experiment gives the adversary, and no bound is claimed for it. Deployments requiring coordinator-collusion resistance need a different functionality (e.g., share-preserving downstream processing) and are out of scope. |
| Can the client collude with evaluators? | Same answer: the model is vacuous under client collusion (the client knows α). |
| Channels confidential? Authenticated? | **Deployment assumption, not implemented here**: client↔evaluator and evaluator↔combiner channels must be confidential and mutually authenticated (e.g., mTLS), and evaluator identities must be bound to party indices by that authentication layer. The wire format binds (session, N, t, party index, construction, parameters, digests) so that misrouting and mixing are *detectable*, but the transport itself is out of scope. |
| How are evaluator identities bound to party indices? | Statically in the evaluator-set manifest (`replication.py` writes per-evaluator manifests carrying `evaluator_id`, `party_index`, N, t, and the store digests); each service refuses key shares whose `party_index` ≠ its manifest index and whose evaluator-set digest ≠ its own. |
| Replay / cross-request / cross-protocol reuse? | Key shares carry a fresh 128-bit `keygen_id` and are bound to `(construction_id, wire version, params digest, N, t, party index)`. Responses bind `(request_id, keygen_id, universe digest, projection digest)`. The combiner refuses mixed `keygen_id`s, mixed versions, mixed constructions, and duplicate party indices. PRG inputs are domain-separated by construction + parameter digest, so identical seeds in different parameter sets produce unrelated streams. Note: a key share is not *cryptographically* single-use — re-evaluating it is harmless for privacy (evaluation is deterministic); the request binding exists to prevent cross-request mixing, not to enforce one-time use. |
| What leaks? | §5.5 list below (universe size and content, N, t, domain, digests, response lengths, capacity, timing, success/failure, the reconstructed output at the recipient). |

### 5.5 Permitted leakage (enumerated)

To all parties: protocol and construction identifier; wire-format version; N
and t; input-domain size 2^n and the universe size U it encodes; output group
identifier (GF(2)^64); universe digest and full universe content (the opaque
HMAC point list — already public to evaluators in the legacy path);
candidate-slot capacity and slot handles; projection digest; message lengths;
request timing and access schedule (which requests arrive when); per-request
success/failure. To the result recipient additionally: the reconstructed slot
vector (β at the matched slot). Nothing else is claimed to be hidden — and in
particular α and β are claimed to be hidden *only* from coalitions of ≤ t
evaluators, per §4.

---

## 6. Security and correctness specification (Phase 5)

### 6.1 Functionality

Point function family over the rank domain: for `α ∈ [2^n]` (0-based rank; in
deployment `α < U ≤ 2^n`) and `β ∈ {0,1}^64`:

```
f_{α,β} : [2^n] → GF(2)^64,   f_{α,β}(x) = β if x = α, else 0^64
```

- Input domain: `[2^n]`, `n = ⌈log₂ max(U, 2)⌉`, `n ∈ [1, 30]` (cap enforced;
  the √-key scaling makes larger n impractical, §2 table).
- Output group: `GF(2)^64` = 64-bit strings under bitwise XOR. β is a 64-bit
  unsigned value interpreted as its bit string. **This differs from the
  two-party path's Z/(2^64); the two groups' combine operations are mutually
  incompatible and the wire formats are mutually rejecting.**
- Parties: `N = p ∈ [3, 10]` (upper cap enforced; key size scales with
  `2^{p−1}`). N = 2 is refused by this path — the legacy path owns it.
- Threshold: claimed corruption bound `t`, default `⌊(N−1)/2⌋`; accepted range
  `1 ≤ t ≤ N−1` (every value in that range is inside the construction's proven
  coverage; values > ⌊(N−1)/2⌋ exceed the honest-majority deployment model and
  the integration layer never sets them). `t` is recorded in every key share,
  manifest, request, and response, and consistency is enforced everywhere.

### 6.2 Algorithms (transcribed from BGI15 §3.1; 1-based paper indices, the
implementation uses 0-based indices — mapping table in
`paper_to_code_mapping.md`)

**Notation 2 (BGI15).** For `p ∈ N`, `E_p` (resp. `O_p`) is the set of binary
`p × 2^{p−1}` arrays whose columns are *all* the p-bit strings with an even
(resp. odd) number of 1 bits, each exactly once. `A ∈_R E_p` samples a uniform
such array (a uniform permutation of the 2^{p−1} even-parity columns).
`e_δ·b ∈ ({0,1}^m)^μ` is the μ-block vector with `b` in block δ and `0^m`
elsewhere.

**Algorithm 3 — `Gen^{p0}(1^λ, a, b)`**

```
1.  Let G : {0,1}^λ → {0,1}^{mμ} be a PRG (μ defined in line 2).
2.  Let μ ← ⌈ 2^{n/2} · 2^{(p−1)/2} ⌉ and ν ← ⌈ 2^n / μ ⌉.
3.  Regard a as a pair (γ, δ), γ ∈ [ν], δ ∈ [μ].
4.  Choose ν arrays A_1,…,A_ν s.t. A_γ ∈_R O_p and A_{γ'} ∈_R E_p for all γ' ≠ γ.
5.  Choose randomly and independently ν·2^{p−1} seeds s_{1,1},…,s_{ν,2^{p−1}} ∈ {0,1}^λ.
6.  Choose 2^{p−1} random strings cw_1,…,cw_{2^{p−1}} ∈ {0,1}^{mμ}
      s.t. ⊕_{j=1}^{2^{p−1}} (cw_j ⊕ G(s_{γ,j})) = e_δ·b.
7.  Set σ_{i,γ'} ← (s_{γ',1}·A_{γ'}[i,1]) ∥ … ∥ (s_{γ',2^{p−1}}·A_{γ'}[i,2^{p−1}])
      for all 1 ≤ i ≤ p, 1 ≤ γ' ≤ ν.       [s·1 = s, s·0 = 0^λ]
8.  Set σ_i = σ_{i,1} ∥ … ∥ σ_{i,ν} for 1 ≤ i ≤ p.
9.  Let k_i = (σ_i ∥ cw_1 ∥ … ∥ cw_{2^{p−1}}) for 1 ≤ i ≤ p.
10. Return (k_1, …, k_p).
```

**Algorithm 4 — `Eval^{p0}(i, k_i, x)`**

```
1. Let G : {0,1}^λ → {0,1}^{mμ} be a PRG (μ as above).
2. Let μ ← ⌈2^{n/2}·2^{(p−1)/2}⌉ and ν ← ⌈2^n/μ⌉.
3. Regard x as a pair (γ', δ'), γ' ∈ [ν], δ' ∈ [μ].
4. Parse k_i as (σ_i, cw_1, …, cw_{2^{p−1}}).
5. Parse σ_i as s_{1,1} ∥ … ∥ s_{ν,2^{p−1}}.
6. Let y_i ← ⊕_{1 ≤ j ≤ 2^{p−1}, s_{γ',j} ≠ 0} (cw_j ⊕ G(s_{γ',j})).
7. Return y_i[δ'].
```

**Pair mapping.** BGI15 fixes only "regard a as a pair (γ, δ)". The
implementation's documented convention (0-based): `γ = ⌊x/μ⌋`, `δ = x mod μ`
(row-major). `ν·μ ≥ 2^n` holds by construction of line 2.

**Correctness equation (exact; the output decoder is XOR — BGI15 Definition 1
with G = GF(2)^64):**

```
⊕_{i=1}^{N} Eval^{p0}(i, k_i, x)  =  β        if x = α
                                  =  0^64     otherwise
```

Argument (paper §3.1): for `γ' ≠ γ`, `A_{γ'} ∈ E_p`, so each term
`cw_j ⊕ G(s_{γ',j})` occurs an even number of times across the p evaluations
and cancels under ⊕. For `γ' = γ`, `A_γ ∈ O_p`, so each term occurs an odd
number of times, leaving `⊕_j (cw_j ⊕ G(s_{γ,j})) = e_δ·b`; block δ' of that
vector is `b` iff `δ' = δ`.

**This equation is a correctness statement only. It is not, and is never used
as, evidence of privacy.** Privacy rests solely on the §4 claim.

**Security argument (paper §3.1, relied upon):** any subset of ≤ p−1 keys
reveals, per row γ', only p−1 rows of `A_{γ'}` — identically distributed
whether `A_{γ'}` was drawn from `E_p` or `O_p` — and the correction words,
which are uniform subject to a single constraint masked by `G(s_{γ,j*})` for
at least one seed `s_{γ,j*}` held by no coalition member (in `O_p` every party
has a column where it is the sole holder, so the missing party's exclusive
seed always exists). PRG security makes the masked constraint
indistinguishable from uniform.

**Known negligible correctness caveat (paper-inherent):** Eval's "held" test is
`s_{γ',j} ≠ 0^λ`; a genuinely-held all-zero seed would be skipped. `Gen`
therefore resamples the (probability 2^{−128} per draw) all-zero seed, making
the zero block an unambiguous "not held" sentinel. Deviation from the paper:
distribution distance ≤ ν·2^{p−1}·2^{−λ} (negligible); it removes the paper's
own negligible correctness error rather than adding one.

### 6.3 Instantiation parameters

| Parameter | Value | Justification |
|---|---|---|
| λ (seed length) | 128 bits | Standard PRG seed size; matches the paper's λ. |
| m (output block) | 64 bits | Matches the repo's 64-bit payload convention; β ∈ {0,1}^64. |
| G (PRG) | `SHAKE256("fedkg-mpdpf/bgi15-eurocrypt2015/prg/v1" ∥ params_tag ∥ seed)` squeezed to `μ·8` bytes; `params_tag = (n, p, μ, ν, m, λ)` fixed-width encoded | FIPS 202 XOF modeled as a PRG on a uniform 128-bit suffix. Domain separation binds the expansion to construction, version, and parameter set, so a seed value can never produce related streams under different parameter sets. Available in the Python stdlib (no new dependency). The PRG input must NOT include party- or session-specific data: correctness requires all holders of a seed to expand it identically within one key generation. |
| Randomness source | `secrets.token_bytes` / `secrets.SystemRandom` (OS CSPRNG) for seeds, correction words, and array permutations | Task requirement; fixes the class of defect found in the legacy CLI (mt19937). Deterministic generation exists only inside test vectors, clearly isolated. |
| Sampling `A ∈_R E_p/O_p` | Enumerate all even/odd-parity p-bit columns, Fisher–Yates shuffle with `secrets.SystemRandom` | Exactly Notation 2's uniform choice. |
| cw sampling | `cw_1,…,cw_{2^{p−1}−1}` uniform; `cw_{2^{p−1}} = e_δ·b ⊕ (⊕_j G(s_{γ,j})) ⊕ (⊕_{j<2^{p−1}} cw_j)` | The uniform-subject-to-constraint distribution of line 6, sampled by fixing the last word. |

### 6.4 Domain encoding

The multi-party path evaluates over the **shared opaque universe** exactly as
the legacy path does (same `OpaqueIndexSnapshot` stores, same sorted opaque
point lists, same SHA-256 universe digest algorithm). The DPF input is the
**rank** of a point in that sorted list: `x = index of point in
sorted(universe)`, `α = rank of the queried point's 64-bit projection`. The
64-bit projected-HMAC namespace (`src/crypto/dpf_domain.py`, collision-checked
at index build) is retained as the point *naming* layer; only the DPF domain
changes. This is the standard "database row index" usage of a √N-key DPF
(BGI15 §1, multi-server PIR application: servers hold a table indexed by
position). The universe (hence the rank mapping) is public to all protocol
participants and bound into every request/response via the universe digest;
using ranks therefore adds no leakage beyond §5.5. Requests fail closed if
the client's and any evaluator's universe digests differ.

### 6.5 Serialization invariants

Full field tables in [`multiparty_fss/docs/wire_format.md`](../../multiparty_fss/docs/wire_format.md).
Invariants: every key share binds
`(wire_version, construction_id = "bgi15-mpdpf-p0", params_id, N, t,
party_index, domain_bits n, universe_binding, output_group = "xor64",
keygen_id, prg_id)`; every request/response additionally binds
`(request_id, evaluator_id, evaluator set digest, universe_digest,
projection_digest (when projected), vector lengths)`. Parsing is strict
(`json` + explicit schema walk, no regex): unknown fields, wrong types,
non-canonical lengths, and out-of-range integers are rejected. Binary payloads
(σ_i, cw's) are base64 of fixed-length little-endian encodings; lengths are
recomputed from (n, p, λ, m) and must match exactly.

### 6.6 Failure semantics (all fail-closed)

| Condition | Behavior |
|---|---|
| Missing any of the N responses | `combine` raises; no partial reconstruction. |
| Duplicate party index / duplicate share | Rejected before combining. |
| Malformed or truncated key share / response | Rejected at parse with no partial state. |
| Mixed `keygen_id`, construction, wire version, params, N, t, group, domain | Rejected. |
| Mismatched request_id / universe digest / projection digest | Rejected. |
| Unsupported N (< 3 or > 10), invalid t (< 1 or ≥ N) | Rejected at `generate`. |
| Two-party (`"group":"uint64"` / legacy payload) material on this path, or `xor64` material on the legacy path | Rejected by schema (distinct required fields + explicit construction check). |
| Extra unexpected responses | Rejected (count must equal N exactly). |

### 6.7 Implementation form

Pure Python 3.10 + NumPy (`uint64` word vectors; XOR is exact — no float
paths, no signed conversions; `m = 64` makes one NumPy word per output block).
No CUDA: the construction shares nothing with the vendored tree DPF, GPU work
would only obscure review, and measured prototype performance (see
`multiparty_fss/docs/benchmarks.md`) is adequate for the repo's universe
sizes. Sensitive-buffer handling and its CPython limits are documented in
`multiparty_fss/SECURITY.md`.

### 6.8 Availability specification (distinct from privacy)

All N output shares are required to reconstruct; **no** qualified subset
suffices; missing-party tolerance is **0**; robustness against malformed
shares is **not** provided (semi-honest model). The privacy threshold t does
not imply any availability threshold, and none is claimed.

### 6.9 Two-party compatibility caveat

The existing N=2 path remains available and untouched. It is a **two-server
non-collusion model**: privacy holds only if the two evaluators do not collude
at all. With N=2, "one corrupted evaluator" is one of two — not a strict
honest majority — so the legacy path lies **outside** the honest-majority
deployment model of this document and is never presented as satisfying it.
The N=2 row appears in benchmarks for cost comparison only.
