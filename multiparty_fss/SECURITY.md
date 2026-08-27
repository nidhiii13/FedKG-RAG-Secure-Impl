# SECURITY — `multiparty_fss/`

This file states exactly what is and is not claimed. Anything not listed as a
guarantee here is **not** guaranteed. Normative background:
[docs/multiparty_fss/research_and_design.md](../docs/multiparty_fss/research_and_design.md)
(sections 4–6).

## Construction and basis of the claim

The implemented scheme is the p-party DPF of Boyle–Gilboa–Ishai, *Function
Secret Sharing*, EUROCRYPT 2015, Section 3.1 (Algorithms 3–4,
`Gen^{p0}`/`Eval^{p0}`), under the paper's Definition 2 (T-secure FSS,
indistinguishability of the corrupted coalition's key tuple) and Remark 2.1
(t-security = T-security for all |T| ≤ t). The paper presents the
construction with a correctness proof and a secrecy argument and states
security against **any coalition of at most p−1 key holders**; the
proceedings text is a proof sketch (full proofs of that section's schemes are
deferred to the paper's full version), and this (p−1)-security is restated as
established prior art by Bunn–Kushilevitz–Ostrovsky (PKC 2022) and
Goel–Wang–Wang (CRYPTO 2025). Assumption: the PRG `G` (instantiated here as
domain-separated SHAKE-256 on a uniform 128-bit seed) is a secure PRG.

## Threat model (the deployment claim)

**Semi-honest adversaries with an honest majority of evaluators.**

- N evaluator parties, `3 ≤ N ≤ 10`, runtime-configurable.
- A static passive adversary corrupts a coalition of at most
  **`t = ⌊(N−1)/2⌋`** evaluators (N=3→t=1, N=4→t=1, N=5→t=2, N=7→t=3).
  Strictly more than half of the evaluators remain honest.
- Corrupted evaluators follow the protocol, keep everything they see, and
  pool their complete views (key shares, local randomness, replicated
  opaque-index state, requests, their own output and projection shares,
  metadata, public parameters, and all messages they send/receive).
- **Privacy guarantee:** for any two queries (α₀, β₀), (α₁, β₁) consistent
  with the same public leakage (below), such a coalition's joint view is
  computationally indistinguishable. Because evaluation is non-interactive
  and deterministic given the key share and public store, the coalition view
  reduces to its key-share tuple plus public data — exactly the object of the
  paper's Definition 2 experiment.
- The construction's proven threshold (`t ≤ N−1`) is strictly larger than the
  claimed one; the deployed **claim** is the honest-majority bound above.
  Metadata records the claimed `t`; the library accepts explicit
  `1 ≤ t ≤ N−1` (all inside the paper's coverage), and every shipped tool and
  manifest defaults to `⌊(N−1)/2⌋`.

### Reconstruction and availability (separate from privacy)

- Reconstruction = XOR of **all N** output shares (`β` at `x = α`, else `0`).
- No qualified subset smaller than N can reconstruct. Missing-party
  tolerance: **0**. One missing, duplicated, or malformed response fails the
  request closed.
- Correct reconstruction is a functionality property. It is never cited here
  as evidence of privacy.
- No robustness: a semi-honest model does not detect a *wrong but
  well-formed* share; a deviating evaluator can silently corrupt the result.

## Trust boundaries

| Component | Trust |
|---|---|
| **Client (query issuer)** | Trusted. Knows (α, β) by definition; runs `Gen` locally (there is no third-party dealer); must deliver share *i* only to evaluator *i*; must not collude with evaluators (collusion makes the model vacuous — the client already knows α). Best-effort deletion of key shares after dispatch; see memory limitations below. |
| **Dealer / setup authority** | Identical to the client. No preprocessing, no correlated randomness, no retained secrets. The repo's existing `FEDKG_SETUP_KEY` (HMAC namespace) and `FEDKG_PRIO_HANDLE_KEY` (candidate handles) remain deployment secrets exactly as on the legacy path. |
| **Evaluators (×N)** | Semi-honest; up to t may collude. Each holds: its manifest (identity, party index, N, t, evaluator list), the full replicated opaque snapshot store (public within the protocol), and per request: its key share and the public projection. Each independently computes output shares; evaluators never communicate with each other. |
| **Coordinator / combiner** | The client-side role that combines the N responses. **It is the authorized result recipient**: it learns the reconstructed slot vector (which candidate matched, value β) — the intended output — plus all response metadata. **Coordinator–evaluator collusion is NOT covered and NOT counted inside t**: a combiner that pools state with any evaluator holds strictly more than the Definition-2 adversary view, and no bound is claimed for it. Deployments needing a collusion-tolerant combiner must keep downstream processing share-preserving, which this prototype does not implement. |
| **Channels** | Assumed (not implemented): confidential, mutually authenticated client↔evaluator transport with evaluator identities bound to party indices (e.g., mTLS with pinned identities). The wire format makes misrouting/mixing *detectable* (identity, index, N, t, keygen ID, digests are bound and checked), but confidentiality/authenticity of transport is a deployment assumption. |

Replay and cross-context reuse: key shares bind
(construction, wire version, parameter-set digest, N, t, party index, keygen
ID, universe digest); responses additionally bind request ID and projection
digest; combiners refuse mixed keygen IDs/constructions/versions/parameters
and duplicate indices. Re-evaluating the same key is harmless for privacy
(evaluation is deterministic); bindings exist to prevent cross-request and
cross-protocol confusion, not to enforce one-time use.

## Permitted leakage (exhaustive)

To every protocol participant: construction and protocol identifiers; wire
versions; N and t; domain size `2^n` and universe size U; the full shared
opaque universe (HMAC-encoded IDs — public to evaluators by design, as on the
legacy path); universe digest; candidate capacity, slot handles, projection
digest; message lengths; the access schedule (when requests occur); request
success/failure; timing. To the combiner/client additionally: the
reconstructed output (β at the matched slot). α and β are hidden **only**
from coalitions of ≤ t evaluators (≤ N−1 by the underlying theorem), and
from nobody else.

## Explicitly out of scope / not protected

- Malicious (actively deviating) evaluators, clients, or combiners; no
  verifiability of shares or outputs.
- Dishonest majority as a system claim (see threshold discussion above).
- Coalitions larger than t (claim) / N−1 (construction).
- Denial of service; any missing response aborts the query (fail-closed, no
  tolerance).
- Compromise of the client, the combiner, `FEDKG_SETUP_KEY`, or
  `FEDKG_PRIO_HANDLE_KEY`.
- Side channels: Python/NumPy execution is **not constant-time**; branch on
  seed-held patterns and row indexing are data-dependent in principle
  (per-row work depends only on public parameters, but no constant-time
  claim is made). Cache/timing/memory side channels are unmitigated.
- Traffic analysis; no cover traffic, no padding of the access schedule.
- Universe content/size hiding, volume hiding, or access-pattern hiding
  beyond what the DPF itself provides (the evaluated universe is public).

## Key-material handling and its limits

Seeds, correction words, and permutation randomness come from the OS CSPRNG
(`secrets`). Key payloads are never logged and never appear in exception
messages. **Limitation (CPython):** key shares live in immutable `bytes` and
garbage-collected objects; secure zeroization of immutable buffers is not
possible in pure Python, copies may persist in interpreter memory, and no
claim of memory hygiene beyond "no unnecessary copies, no logging" is made.
The legacy two-party CLI's use of a non-cryptographic RNG (`std::mt19937_64`)
is documented in the audit
([docs/multiparty_fss/two_party_audit.md](../docs/multiparty_fss/two_party_audit.md),
finding C3/S1) and is deliberately not inherited here; it also was not
"fixed" there, since the task forbids modifying the two-party path.

## The two-party path (compatibility mode)

`tools/fss_cli` + `src/runtime` remain available and unchanged. Their model
is **two-server non-collusion**: privacy only if the two evaluators share
nothing. That is *not* an honest-majority deployment (1 corruption out of 2
leaves no strict honest majority) and is never claimed as one. The two wire
formats are mutually rejecting; neither path will consume the other's keys,
responses, stores, or projections.

## Maturity

Research-grade prototype. Not production-ready. Tests demonstrate functional
correctness and fail-closed validation, **not** cryptographic privacy; no
formal verification, no independent cryptographic review, no constant-time
implementation, and no official cross-implementation test vectors (none
exist publicly for this construction as of 2026-08-27).
