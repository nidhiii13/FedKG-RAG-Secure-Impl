# Two-Party DPF/FSS Audit

Audit date: 2026-08-27. Audited tree: `main` at `d2d93c7` plus uncommitted user
changes (which touch none of the audited FSS files).

Purpose: identify every assumption that restricts the existing private-lookup
implementation to exactly two FSS evaluators, classify each one, and state what
an N-party generalization requires. This audit is the basis for the separate
implementation under `multiparty_fss/`; **none of the findings below were
"fixed" in place** — the two-party path is preserved unchanged as a
compatibility mode (see `multiparty_fss/README.md`).

Terminology used throughout:

- **Evaluator** — a role-separated FSS evaluation service holding a replicated
  opaque index store (role IDs like `fss_evaluator_0`). This is the party count
  the task's N refers to.
- **Data party** — a federated KG owner (`p0`, `p1`, …). In the older
  "party-as-evaluator" prototype path (`run_private_exact_query.py` and the
  frontier scripts) data parties also act as DPF evaluators, which silently
  imports the two-evaluator restriction into the data-party count (finding S5).
- **Coordinator** — the component that generates DPF keys and combines output
  shares (`RoleSeparatedFssQueryOrchestrator`, `combine_fss_candidate_shares.py`).
  In the current code the key generator and the combiner are the same trusted
  client-side component.

## 1. Lifecycle trace (current two-party path)

```
query/alpha (plaintext label)
  │  src/crypto/hmac_ids.py:35-38            HMAC-SHA256(setup_key, namespace:label) → 256-bit hex ID
  ▼
domain encoding
  │  src/crypto/dpf_domain.py:23-29          project_hmac_id: first 64 bits / 16 hex chars
  │  src/crypto/dpf_domain.py:42-84          collision scan; index build rejects colliding projections
  │  tools/fss_cli/main.cu:126-153           ProjectHexToDomain re-projects hex → uint64 (truncates >16 chars)
  ▼
FSS key generation                                       [CRYPTOGRAPHIC CORE]
  │  src/crypto/fss_cli_backend.py:75-84     gen() → {"op":"gen","alpha",…,"share_count":len(party_ids)}
  │  tools/fss_cli/main.cu:244-272           HandleGen: rejects share_count != 2; myl7/fss tree DPF
  │                                          Gen(cws, seeds[2], alpha, beta); β low-bit clamped
  │  tools/fss_cli/main.cu:164-168,256-258   seeds from std::mt19937_64 seeded by std::random_device
  ▼
key serialization
  │  tools/fss_cli/main.cu:198-209           ShareJson: {"party":0|1,"seed":int4,"correction_words":[65],
  │                                           "domain_bits":64,"group":"uint64","projection":…}
  │                                          both shares embed the SAME correction-word array
  │  tools/fss_cli/main.cu:211-242           ParseShare: regex JSON parse; party must be 0 or 1
  ▼
evaluator dispatch
  │  src/orchestration/role_separated_fss_query.py:40-54   exactly 2 services, indices {0,1};
  │                                          keygen happens here (client/coordinator role)
  │  scripts/run_fss_evaluator.py:41-75      per-evaluator worker: stdin request, --store/--evaluator-id
  │  src/runtime/fss_evaluator_service.py:128-152          binds key_share.party_id to store identity and
  │                                          payload["party"] to manifest evaluator_index
  ▼
scalar / batch evaluation
  │  tools/fss_cli/main.cu:274-312           Eval/EvalMany: dpf.Eval(share.party == 1, …) → uint64 share
  │  src/crypto/fss_cli_backend.py:93-118    batching (256/request), bisection on CLI failure
  ▼
candidate projection
  │  src/runtime/fss_projection_builder.py:32-67           query-independent padded slot layout
  │  src/runtime/fss_candidate_projection.py:72-84         project(): slot += eval_share * weight  (mod 2^64)
  │                                          — a Z_{2^64}-LINEAR map over ADDITIVE shares
  ▼
evaluator response validation
  │  src/runtime/fss_candidate_projection.py:98-129        from_mapping: evaluator_index ∈ {0,1};
  │                                          request_id/domain/universe_digest/projection_digest strings
  │  src/runtime/fss_evaluator_service.py:175-180          universe_digest = SHA-256 over ordered points
  ▼
output-share reconstruction                              [CRYPTOGRAPHIC CORE]
  │  src/runtime/fss_candidate_projection.py:163-203       combine(): exactly 2 responses, indices {0,1},
  │                                          metadata equality, (left + right) mod 2^64 per slot
  │  src/aggregation/private_lookup.py:69-90               older path: sum(values) mod 2^64 over party_ids
  │                                          (loop is N-generic; share source is 2)
  ▼
retrieval result
  │  src/runtime/fss_candidate_projection.py:153-159       nonzero_slots ⇒ candidate match
  │  src/runtime/fss_projection_builder.py:19-24           handle → candidate ID mapping
  ▼
downstream Prio/MPC processing
  │  src/orchestration/prio_candidate_pipeline.py:45-58    reconstructs candidates BEFORE Prio3; asserts
  │                                          lookup_evaluator_count == 2 (metadata gate, not share logic)
  │  src/aggregation/prio3_candidates.py                   evaluator-agnostic; aggregator_count ∈ [2,255]
  │  scripts/run_role_separated_secure_retrieval.py:182    emits literal "fss_evaluator_count": 2
```

Key structural facts:

1. **The Python layer is mostly count-generic; the native CLI is the hard
   floor.** `DpfBackend.gen(alpha, beta, party_ids)`
   ([dpf.py:19](../../src/crypto/dpf.py#L19)) and
   `FssCliBackend.gen` ([fss_cli_backend.py:75-84](../../src/crypto/fss_cli_backend.py#L75-L84))
   accept any number of party IDs and forward `share_count=len(party_ids)`;
   `tools/fss_cli/main.cu:247-250` throws for anything but 2 because the
   underlying `myl7/fss` `Dpf` scheme (`third_party/myl7-fss/include/fss/dpf.cuh`)
   is a two-party tree DPF by construction.
2. **The additive output group is load-bearing.** `CandidateProjection.project`
   computes a Z_{2^64}-linear combination of eval shares. Any N-party scheme
   whose output shares combine under a different group operation (e.g. XOR)
   cannot be dropped behind this projection; it needs its own projection/combine
   with matching group semantics (this is what `multiparty_fss/` does).
3. **Keys are generated and shares are combined by the same trusted
   client-side coordinator.** There is no dealer separate from the querier.

## 2. Findings table

Categories: **C** cryptographic, **P** protocol, **O** orchestration,
**St** storage, **Se** serialization, **U** CLI/UI, **D** documentation,
**T** test. BC-risk = backward-compatibility risk if the site were generalized
in place (the selected approach instead leaves all of them untouched).
Sec-risk = security risk if the site were generalized *incorrectly* (e.g. by
looping 2→N without changing the cryptography).

### 2.1 Cryptographic sites

| # | File & symbol | Current behavior | Exact 2-party assumption | Cat | Required N-party change | BC risk | Security risk if generalized incorrectly |
|---|---|---|---|---|---|---|---|
| C1 | [tools/fss_cli/main.cu:247-250](../../tools/fss_cli/main.cu#L247-L250) `HandleGen` | Generates one myl7/fss tree-DPF key pair | `share_count != 2` → throw; the myl7/fss `Dpf` template is inherently 2-party (single seed pair + shared CW list) | C | A different construction. A p-party DPF cannot be obtained by looping this Gen; the tree correction-word mechanism is defined only for two seeds with complementary control bits | High (any change to this binary alters the deployed 2-party wire format) | **Fatal.** Running ⌈N/2⌉ pairwise instances or duplicating one key to several evaluators gives coalitions of 2 the full reconstruction; "it still reconstructs" is not privacy |
| C2 | [tools/fss_cli/main.cu:213-215](../../tools/fss_cli/main.cu#L213-L215) `ParseShare` | Parses key payload | `party` field must be 0 or 1; `Eval` takes `share.party == 1` as a sign bit | C/Se | N-party key format with integer party index, per-party seed sets, and construction/param binding | High | Party-index confusion between constructions ⇒ shares combined under the wrong role; can silently produce wrong-but-plausible results |
| C3 | [tools/fss_cli/main.cu:256-258,164-168](../../tools/fss_cli/main.cu#L256-L258) `HandleGen`/`RandomSeed` | DPF seeds from `std::mt19937_64` seeded by 64 bits of `std::random_device` | (Not a 2-party issue, but a defect the new path must not inherit.) MT19937 is not a CSPRNG; seed space effectively 64 bits | C | New path must use an OS CSPRNG for all key material | — | Predictable seeds break DPF secrecy outright regardless of party count |
| C4 | [src/runtime/fss_candidate_projection.py:189-195](../../src/runtime/fss_candidate_projection.py#L189-L195) `ProjectedFssCoordinator.combine` | `(left + right) mod 2^64` per slot | Exactly two addends; pairwise unpack `left, right = by_index[0], by_index[1]` | C/P | Group-correct combination over N shares. For the selected XOR-output p-party construction this is XOR over all N vectors, not a mod-2^64 sum | Med | Summing XOR shares (or XORing additive shares) yields garbage that can still be nonzero ⇒ false candidate matches presented as reconstructed values |
| C5 | [src/aggregation/private_lookup.py:82-89](../../src/aggregation/private_lookup.py#L82-L89) `_matched_points` | `sum(values) % 2^64 != 0` ⇒ match | Loop is N-generic; correctness inherits from the 2-share backend. `0 ≠ Σ shares` is interpreted as a match with no share-count or group validation | C/P | Same group caveat as C4; must also fail closed when a party's share is missing (it currently skips the point via the `for…else`) | Low | Mixing shares from different key generations or groups is not detected; nonzero noise ⇒ false matches |
| C6 | [src/crypto/dpf_domain.py:13-16](../../src/crypto/dpf_domain.py#L13-L16) | 64-bit projected HMAC domain, `DPF_MODULUS = 2^64` | Not 2-party per se, but the *tree* DPF makes 64-bit domains cheap (65 CWs). A √N-key multi-party DPF cannot use a 2^64 domain (keys would be ≥2^32 blocks) | C | Multi-party path re-encodes the shared evaluator universe as ranks in [0, 2^n), n = ⌈log₂ U⌉, bound to the universe digest | None (new path only) | Silently reusing the 64-bit encoding in a √-domain scheme is impossible to miss (key size explodes), but an undersized n that truncates ranks would map two points to one DPF input ⇒ wrong hits |
| C7 | [tools/fss_cli/main.cu:62-124](../../tools/fss_cli/main.cu#L62-L124) regex JSON parsing | Security-relevant fields parsed by `std::regex` | Documented as temporary; batch size capped at 256 for this reason | C/Se | New path must use a structured parser (Python `json` with strict schema validation) | — | Regex mis-parse of key material or points ⇒ silent evaluation of wrong points |
| C8 | [tools/fss_cli/main.cu:177-196](../../tools/fss_cli/main.cu#L177-L196) `Key0/Key1` | Fixed AES-128 keys for the MMO PRG | Two fixed public AES keys = the two MMO branch permutations. This is *by design* for fixed-key AES-MMO hashing (keys are public parameters, not secrets) — but the count 2 is the tree DPF's branching factor | C | The selected p-party construction uses one seeded PRG `G` (no per-branch keys); instantiated with SHAKE-256 and explicit domain separation | None | Confusing MMO parameter keys with secret keys, or reusing PRG outputs across constructions without domain separation ⇒ cross-protocol interactions |

### 2.2 Protocol / orchestration sites

| # | File & symbol | Current behavior | Exact 2-party assumption | Cat | Required N-party change | BC risk | Security risk if generalized incorrectly |
|---|---|---|---|---|---|---|---|
| P1 | [src/orchestration/role_separated_fss_query.py:40-54](../../src/orchestration/role_separated_fss_query.py#L40-L54) `query` | Orchestrates gen → 2 evals → combine | `len(evaluators) != 2` guard; `set(by_index) != {0,1}`; literal `(0, 1)` ordering twice | P/O | Evaluator list of length N; indices `range(N)`; per-evaluator key routing; N-aware combine | Med | Sending share i to the wrong evaluator is currently caught by the `party` check (C2); a generalized version without per-index binding lets one host collect ≥2 key shares ⇒ coalition-by-misrouting |
| P2 | [src/runtime/fss_candidate_projection.py:170-174](../../src/runtime/fss_candidate_projection.py#L170-L174) `combine` | Requires exactly 2 responses, indices {0,1} | Literal counts and index set | P | Require exactly N responses with indices `0..N-1`, no duplicates, all metadata equal | Med | Accepting N−1 of N shares "best effort" breaks correctness silently; accepting duplicates lets one evaluator's response count twice |
| P3 | [src/runtime/fss_evaluator_service.py:133-135](../../src/runtime/fss_evaluator_service.py#L133-L135) `evaluate` | `payload["party"] == store.evaluator_index` | Binds the CLI's binary party field to the binary store index | P | Bind (construction ID, party index, N, t, key/session ID) from the key share to the store manifest | Med | Without this binding an evaluator will evaluate a share not addressed to it, enabling key-share aggregation at one host |
| P4 | [src/orchestration/prio_candidate_pipeline.py:50-55](../../src/orchestration/prio_candidate_pipeline.py#L50-L55) `run` | Refuses `lookup_evaluator_count != 2` | Deliberate fail-closed guard (see test T3) | P | Accept N with explicit threshold metadata; keep refusing counts that no configured backend provides | Low | Relaxing the guard without a real N-party backend would *claim* multi-party FSS while running the 2-party CLI — precisely the misrepresentation the guard exists to prevent |
| P5 | [src/runtime/secure_roles.py:74-75,86-87](../../src/runtime/secure_roles.py#L74-L87) `validate` | Topology requires exactly 2 evaluator roles with 2 distinct authorities | `!= 2` cap (contrast `>= 2` floor for Prio aggregators) | P/O | `len(evaluators) == N ≥ 3`, authorities pairwise distinct (`len(set) == N`), plus explicit threshold field t | Med | With t colluders tolerated, authority-distinctness is the only machine proxy for non-collusion; an N-party topology that keeps `!= 2`-style checks can under-count authorities and admit sibling evaluators controlled by one operator |
| P6 | [src/gateway/query_compiler.py:58-66](../../src/gateway/query_compiler.py#L58-L66); [src/orchestration/private_frontier_handoff.py:50-56](../../src/orchestration/private_frontier_handoff.py#L50-L56); [src/orchestration/private_semantic_routing.py:46-246](../../src/orchestration/private_semantic_routing.py) | `backend.gen(…, party_ids=party_ids)` where `party_ids` are **data parties** | Data-party count is silently coupled to the CLI's `share_count == 2` | P | In the new path, evaluator count is an explicit protocol parameter, never inferred from a data-party list | Low | The silent coupling is the audit's most dangerous latent behavior: a 3-owner federation fails at runtime deep in a subprocess (see S5), and a "fix" that spreads 2-party keys across 3 owners would break privacy |

### 2.3 Storage / serialization sites

| # | File & symbol | Current behavior | Exact 2-party assumption | Cat | Required N-party change | BC risk | Security risk if generalized incorrectly |
|---|---|---|---|---|---|---|---|
| St1 | [src/runtime/opaque_index_replication.py:48-49](../../src/runtime/opaque_index_replication.py#L48-L49) `replicate_opaque_snapshots` | Writes identical snapshot stores per evaluator | "exactly two unique evaluator IDs"; the write loop itself is already N-generic | St | Accept N ≥ 3 IDs; manifest gains version/N/t/index fields | Low | Replicas must stay byte-identical across all N; a generalized verifier comparing only `records[0] == records[1]` (St2) misses a diverging third replica ⇒ evaluators evaluate different universes and the combiner's universe-digest check becomes the only (late) defense |
| St2 | [src/runtime/opaque_index_replication.py:81-89](../../src/runtime/opaque_index_replication.py#L81-L89) `verify_replicas` | Pairwise record-set equality | `len(manifests) != 2`; `record_sets[0] != record_sets[1]` | St | All-N equality against the first, or pairwise over all | Low | As St1 |
| St3 | [src/runtime/fss_evaluator_service.py:45-46](../../src/runtime/fss_evaluator_service.py#L45-L46) `FssEvaluatorStore.load` | Manifest check | `evaluator_index not in (0, 1)` | St/Se | Index in `[0, N)` with N recorded in the manifest | Med | An index accepted without a bound N cannot be validated for duplicates/out-of-range at combine time |
| Se1 | [tools/fss_cli/main.cu:198-209](../../tools/fss_cli/main.cu#L198-L209) `ShareJson` | Key payload fields | Binary `party`; no protocol version, construction ID, N, t, party count, session/keygen ID, request binding | Se | Full binding vector: wire version, construction ID, parameter-set ID, N, t, party index, domain params, output group, keygen/session ID, domain-separation context | High (format is deployed) | Unversioned keys are re-interpretable across constructions; mixing keys from different generations is undetectable (only the shared CW list would differ, producing plausible garbage) |
| Se2 | [src/runtime/fss_candidate_projection.py:109-113](../../src/runtime/fss_candidate_projection.py#L109-L113) `from_mapping` | Response validation | `evaluator_index not in (0, 1)` | Se | Index in `[0, N)`, plus N, t, construction, group fields; reject mixed values across responses | Med | As P2 |
| Se3 | [scripts/run_role_separated_secure_retrieval.py:182](../../scripts/run_role_separated_secure_retrieval.py#L182) | Emits result JSON | Literal `"fss_evaluator_count": 2` (not derived from `len(stores)`) | Se/D | Derive from configuration | Low | Misreports the deployed trust model if anything changes; downstream consumers cannot detect it |
| Se4 | [scripts/run_hybrid_dpf_prio_retrieval.py:131](../../scripts/run_hybrid_dpf_prio_retrieval.py#L131); [scripts/run_mpc_dpf_prio_pipeline.py:163](../../scripts/run_mpc_dpf_prio_pipeline.py#L163) | Result JSON | Literal `"lookup": "two-non-colluding-dpf-fss-evaluators"` | Se/D | Backend/threat-model string derived from the actually configured path | Low | Same as Se3 |

### 2.4 CLI/UI sites

| # | File & symbol | Current behavior | Exact 2-party assumption | Cat | Required N-party change | BC risk | Security risk if generalized incorrectly |
|---|---|---|---|---|---|---|---|
| U1 | [scripts/run_role_separated_fss_query.py:29-30,63-65](../../scripts/run_role_separated_fss_query.py#L29-L30); [scripts/run_role_separated_secure_retrieval.py:37-38,107-109](../../scripts/run_role_separated_secure_retrieval.py#L37-L38) | `--store-0`, `--store-1` required flags; `{0,1}` index check | Flag-per-evaluator scheme | U | Repeated `--evaluator`/`--store` flags or an evaluator manifest; `--party-count`, `--threshold` | Low | A CLI that accepts N stores but passes only 2 downstream would silently drop evaluators |
| U2 | [scripts/combine_fss_candidate_shares.py:22-23](../../scripts/combine_fss_candidate_shares.py#L22-L23) | stdin = JSON array of exactly 2 responses | Length check | U/Se | Length == N from explicit configuration, never inferred from input length | Med | Inferring N from the input array lets an attacker (or bug) that drops one response redefine the protocol as (N−1)-party; must fail closed |
| U3 | [scripts/run_hybrid_dpf_prio_retrieval.py:34-35,76-79](../../scripts/run_hybrid_dpf_prio_retrieval.py#L34-L35); [scripts/run_mpc_dpf_prio_pipeline.py:43-44,105-108](../../scripts/run_mpc_dpf_prio_pipeline.py#L43-L44) | Forward `--store-0/--store-1` verbatim to the underlying script | Same as U1 | U | Same as U1 | Low | As U1 |
| U4 | [scripts/run_prio_candidate_aggregation.py:44,91-96](../../scripts/run_prio_candidate_aggregation.py#L44) | `--lookup-evaluators` int flag; fallback literal 2; clamped to 2 by P4 | The only count-parameterized CLI, but pinned downstream | U | Honest N once a backend exists | Low | A flag that accepts N while the backend runs 2-party is a misrepresentation vector; currently prevented by P4 |
| U5 | [scripts/export_opaque_fss_snapshots.py:85-96](../../scripts/export_opaque_fss_snapshots.py#L85-L96) | Replication driven by topology; reports `len(replicas)` | Good pattern — blocked only by St1/P5 | U | None beyond upstream | Low | — |
| U6 | [scripts/run_fss_evaluator.py:29-37](../../scripts/run_fss_evaluator.py#L29-L37) | Single-evaluator worker: `--store`, `--evaluator-id` | **N-clean.** No 0/1 assumption in this script itself (the store load enforces St3). Note L52: domain whitelist omits `relation_bucket`/`entity_bucket` | U | Model for the N-party worker | Low | — |

### 2.5 Documentation sites

| # | File & lines | Statement | Cat | Required change |
|---|---|---|---|---|
| D1 | [docs/prio3_aggregation.md:50-51,65,71-72,84-87,118-120,137-139](../../docs/prio3_aggregation.md) | "lookup evaluator count: exactly two"; "exactly two non-colluding evaluators execute the current native DPF/FSS"; "two non-colluding evaluator authorities"; coordinator index-{0,1} contract | D | Remains correct for the legacy path; N-party docs live under `multiparty_fss/` and `docs/multiparty_fss/` |
| D2 | [docs/secure_architecture.md:5,21](../../docs/secure_architecture.md) | "real two-party DPF lookup"; "Generate real two-party DPF key shares" | D | Same |
| D3 | [tools/fss_cli/fss_cli_protocol.md:13,26,34-51,84](../../tools/fss_cli/fss_cli_protocol.md); [tools/fss_cli/README.md:13-24](../../tools/fss_cli/README.md) | `share_count: 2`; two-element `shares` array; "Combining both party output shares modulo 2^64" | D | Remains the 2-party contract; the N-party wire format is separately versioned |
| D4 | [src/crypto/README.md:14,22](../../src/crypto/README.md) | "real two-party DPF CLI wrapper"; "across both parties modulo 2^64" | D | Same |
| D5 | [docs/threat_model.md](../../docs/threat_model.md) | **Gap:** the project-level threat model covers only the `doram_t2_3pc` 3-server committee (2-of-3 passive). It says nothing about the FSS evaluator pair; the FSS non-collusion assumption lives only in `docs/prio3_aggregation.md` | D | `multiparty_fss/SECURITY.md` states the FSS-evaluator threat model explicitly (both the legacy 2-party non-collusion model and the new honest-majority model) without amending the DORAM model |
| D6 | [scripts/README.md:183,207-208,228,239-240](../../scripts/README.md) | "two non-colluding DPF/FSS evaluators", `--store-0/--store-1` examples. File has uncommitted user modifications — deliberately not touched | D | New-path usage documented in `multiparty_fss/README.md` instead |

### 2.6 Test sites

| # | File & symbol | What it pins | Cat | N-party consequence |
|---|---|---|---|---|
| T1 | [tests/unit/test_secure_roles.py:31-37](../../tests/unit/test_secure_roles.py#L31-L37) `test_rejects_more_than_two_native_fss_evaluators` | Asserts a 3rd evaluator role is **refused** | T | Correct for the legacy topology; the N-party path uses its own manifest type, so this test stays valid |
| T2 | [tests/unit/test_opaque_index_replication.py:42-44](../../tests/unit/test_opaque_index_replication.py#L42-L44) `test_rejects_non_two_evaluator_replication` | Asserts 3-ID replication is refused | T | Same |
| T3 | [tests/unit/test_prio_candidate_pipeline.py:44-49](../../tests/unit/test_prio_candidate_pipeline.py#L44-L49) `test_rejects_claim_of_multi_party_native_fss` | Asserts the pipeline refuses to *claim* multi-party FSS | T | Intent-preserving: the new path makes the claim only with the new backend; legacy guard stays |
| T4 | [tests/unit/test_fss_candidate_projection.py:31-67](../../tests/unit/test_fss_candidate_projection.py#L31-L67); [tests/unit/test_fss_evaluator_service.py:37-77](../../tests/unit/test_fss_evaluator_service.py#L37-L77); [tests/unit/test_role_separated_fss_query.py:16-52](../../tests/unit/test_role_separated_fss_query.py#L16-L52) | Two-share fixtures, `{"party":0|1}` payloads, complement arithmetic | T | Stay as the 2-party regression suite; the N-party suite lives in `multiparty_fss/tests/` |
| T5 | [tests/integration/test_native_fss_cli.py:14-31](../../tests/integration/test_native_fss_cli.py#L14-L31); [tests/integration/test_native_fss_evaluator_service.py:20-97](../../tests/integration/test_native_fss_evaluator_service.py#L20-L97); [tests/integration/test_native_role_separated_fss_query.py:17-30](../../tests/integration/test_native_role_separated_fss_query.py#L17-L30); [tests/integration/test_native_role_separated_semantic_prio.py:61-88](../../tests/integration/test_native_role_separated_semantic_prio.py#L61-L88) | Pairwise reconstruction against the real CLI | T | Same |
| T6 | [tests/unit/test_private_exact_retriever.py:12-17,72-113](../../tests/unit/test_private_exact_retriever.py#L72-L113) | 3 **data parties** pass — but only under a mock backend that ignores share counts | T | Documents S5: the same path with the real backend fails for 3 data parties |
| T7 | [tests/unit/test_query_share_bridge.py:8-25](../../tests/unit/test_query_share_bridge.py#L8-L25) | MPC query-share bridge tested at N=3 | T | Counter-example: non-FSS components are already N-party |

## 3. Cryptographic core vs. neutral infrastructure

**Genuinely cryptographic (must NOT be "generalized" by loop-widening):**

- `tools/fss_cli/main.cu` + `third_party/myl7-fss` (tree DPF: Gen/Eval/CW
  mechanics, PRG, seeds) — C1–C4, C7, C8.
- Share combination semantics (additive mod 2^64) — C4, C5.
- Key payload contents (seed, correction words, party bit) — Se1.
- The 64-bit domain projection **as used by the tree DPF** — C6.

**Neutral infrastructure (safely reusable for N parties, and reused by
`multiparty_fss/` via import where noted):**

- HMAC ID layer `src/crypto/hmac_ids.py` (reused).
- Projection-collision scan `src/crypto/dpf_domain.py:42-84` (reused for the
  64-bit intermediate encoding).
- Opaque snapshots `src/party/opaque_index_snapshot.py` (`OpaqueIndexSnapshot`,
  `ReplicatedEvaluatorIndex`) — party-count-free (reused).
- Universe digest `src/runtime/fss_evaluator_service.py:175-180` (algorithm
  reused with a distinct version label in the N-party wire format).
- Candidate handle provider `src/aggregation/prio3_candidates.py`
  (`SessionCandidateHandleProvider`) — evaluator-agnostic (reused).
- Slot layout logic of `src/runtime/fss_projection_builder.py` — the *layout*
  is neutral; the *projection arithmetic* is not (Z_{2^64}-linear). The N-party
  path re-implements projection for its output group and reuses the layout idea.
- Replication write-loop shape of `opaque_index_replication.py` (pattern
  reused, generalized, in `multiparty_fss/replication.py`).

**Deliberately not reused:** the native CLI, its wire format, and
`ProjectedFssCoordinator`. The selected multi-party construction (BGI15
p-party DPF, see `research_and_design.md`) shares no algorithmic component
with the myl7/fss tree DPF, so reusing its key format or evaluation plumbing
would only invite cross-construction confusion.

## 4. Additional security-relevant observations (legacy path, unchanged)

- **S1 — non-CSPRNG key material (C3):** `std::mt19937_64` seeded with 64 bits
  from `std::random_device` generates DPF seeds. Not fixed here (the task
  forbids modifying the two-party path); recorded as a known defect of the
  legacy prototype. The new path uses `secrets.token_bytes`/`os.urandom`.
- **S2 — regex JSON parsing (C7):** acknowledged in the repo's own docs as
  temporary; capped batch size is a symptom.
- **S3 — no session/request binding in keys (Se1):** legacy key payloads can be
  replayed across requests and mixed across generations without detection.
- **S4 — store-0 authority bias:** `run_role_separated_fss_query.py:90-91` and
  `run_role_separated_secure_retrieval.py:118,140` build projections from
  `stores[0].index` only; a diverging replica 1 is caught late (universe-digest
  mismatch at combine), not at projection build.
- **S5 — silent data-party coupling (P6):** every script that calls
  `compile_private_shares`/frontier/semantic routing against the native CLI
  requires exactly 2 *data parties*, undocumented, failing at runtime inside a
  subprocess. `tests/unit/test_private_exact_retriever.py` masks this with a
  count-agnostic mock.
- **S6 — leakage surface of the evaluator role (documented, not fixed):** each
  evaluator sees the full opaque universe, per-request domain, universe and
  projection digests, candidate capacity, and timing. This is inherited by the
  N-party path and enumerated as permitted leakage in `multiparty_fss/SECURITY.md`.

## 5. Conclusion

The two-evaluator restriction is real cryptography, not plumbing: it enters at
`myl7/fss`'s tree DPF and its binary `party` bit, and everything upstream
(store manifests, response validators, coordinators, CLIs, docs, tests) encodes
it faithfully — in several places with deliberate fail-closed guards whose
*intent* (refuse to claim multi-party security that the backend does not
provide) the N-party work preserves. A genuine N-party path therefore requires
a different paper-backed construction with its own key format, combination
rule, domain encoding, and validation matrix, implemented side-by-side. That
path is `multiparty_fss/`; its construction choice and security model are
justified in [research_and_design.md](research_and_design.md).
