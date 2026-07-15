# Optional Prio3 Aggregation Backend

The Prio3 implementation is additive and opt-in. It does not replace or modify
the two-party DPF/FSS private lookup implementation under `src/crypto` and
`tools/fss_cli`.

Current implementation boundary:

1. A data party contributes one bounded integer vector.
2. `libprio-rs` shards each vector among a configurable number of aggregators.
3. Aggregators execute Prio3 preparation, rejecting invalid measurements.
4. Each aggregator combines its output shares.
5. The local validation CLI reconstructs the final element-wise sum.

The reconstruction in step 5 is intended only for local correctness testing and
benchmarking. The production design must split preparation and aggregation into
network-separated services and convert aggregate shares into distributed MPC or
garbled-circuit ranking inputs without revealing the full aggregate vector.

The next integration stage will create fixed, padded candidate slots containing
presence, fixed-point score, and support coordinates. That stage must define
bounds and overflow checks before accepting measurements.

## Candidate-vector validation stage

`src/aggregation/prio3_candidates.py` implements the local validation version
of that stage without changing the existing FSS/additive path:

1. Existing opaque candidate IDs are re-keyed into session-scoped HMAC handles.
2. Real handles and deterministic dummy handles are sorted into a fixed-capacity
   slot layout.
3. Every data party creates equally sized presence, score, and support vectors.
4. Presence uses one-bit Prio3 SumVec measurements; score and support use their
   independently configured bounds.
5. The local backend reconstructs aggregate vectors and exposes aggregate
   candidate statistics for correctness testing.

One party may contribute to a candidate at most once. Scores must be
non-negative and fit the configured fixed-point bound; support values must fit
their configured bit bound. Production deployment must additionally hide the
slot-to-candidate mapping from aggregation servers and keep aggregate vectors
secret-shared until ranking.

## Opt-in orchestration

`src/orchestration/prio_candidate_pipeline.py` adds a parallel local-validation
pipeline. It ranks reconstructed Prio aggregates by lower average score, then by
higher support. It records the protocol boundaries explicitly:

- lookup backend: two-party DPF/FSS;
- lookup evaluator count: exactly two;
- aggregation backend: Prio3 with configurable aggregator count;
- aggregate reconstruction and ranking: local validation only.

The standalone `scripts/run_prio_candidate_aggregation.py` command requires
`--aggregation-backend prio3` and `--allow-local-reconstruction`. It consumes
already generated party candidate contributions. It does not claim that Prio3
turns the lookup layer into n-party FSS.

## Role topology

`src/runtime/secure_roles.py` separates the three participant sets:

- N KG data parties generate candidate contributions;
- exactly two non-colluding evaluators execute the current native DPF/FSS;
- M independently operated Prio aggregators validate and aggregate vectors.

`configs/secure/prio3_roles.example.json` is a local simulation topology. In
production mode, the validator rejects shared FSS authorities, fewer than two
Prio authorities, duplicate cross-role identifiers, and local endpoints. The
topology defines roles only; it does not yet provide a secure mechanism for the
two evaluators to access N private party indexes.

## Replicated opaque evaluator indexes

`src/party/opaque_index_snapshot.py` exports a separate evaluator snapshot that
contains HMAC identifiers, encoded adjacency, encoded types, and precomputed
frontier-token mappings. It excludes plaintext display maps, normalized aliases,
the original party ID, and all HMAC key material.

`scripts/export_opaque_fss_snapshots.py` writes byte-equivalent logical
snapshots to exactly two evaluator stores and records SHA-256 digests in each
manifest. This enables ordinary two-server DPF evaluation because both servers
hold the same encoded database. It relies on two non-colluding evaluator
authorities and still reveals encoded graph topology, partition membership, and
database size to each evaluator. It is therefore a practical honest-but-curious
prototype, not full database privacy against an evaluator.

## Role-separated FSS evaluator

`src/runtime/fss_evaluator_service.py` loads one evaluator replica, verifies all
snapshot digests, and enforces the evaluator's native DPF share index. For each
request it evaluates one key share over a deterministic entity, relation, type,
or frontier universe and returns:

- request and evaluator metadata;
- a digest and length for the ordered universe;
- one uint64 DPF output share per universe point.

It does not reconstruct a match. `scripts/run_fss_evaluator.py` exposes this as
a JSON-stdin process boundary. Returning a dense vector is intentionally the
first correctness implementation; production should use a persistent service
and a fixed-size database-response projection to avoid transferring one share
per universe point.

## Direct candidate-slot projection

`src/runtime/fss_candidate_projection.py` avoids sending dense point-share
vectors to the coordinator. Each evaluator applies the same padded projection
from opaque universe points to session-scoped candidate handles while values are
still DPF shares:

```text
candidate_share[j] = sum(eval_share[x] * weight[x,j]) mod 2^64
```

The evaluator response contains candidate handles and candidate-slot shares,
but no universe point IDs or local match. `ProjectedFssCoordinator` accepts
exactly evaluator indices 0 and 1 and verifies request, domain, universe,
projection, and slot-order equality before combining corresponding shares.
`scripts/combine_fss_candidate_shares.py` exposes this combination boundary.

The coordinator learns which candidate handles have nonzero combined values. It
does not learn which exact or semantic bucket produced them. Avoiding even this
candidate-set leakage requires keeping the combined slots secret-shared and
adding a share-conversion protocol into Prio/MPC ranking; that is not provided
by Prio3 directly.
