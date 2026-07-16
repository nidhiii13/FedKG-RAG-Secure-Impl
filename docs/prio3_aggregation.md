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

## Automatic exact projection and query orchestration

`src/runtime/fss_projection_builder.py` derives a query-independent global
projection for exact entity, relation, type, and frontier domains. Exact points
map to their corresponding candidate IDs; type and frontier points map to their
encoded member entities. All real candidates and dummy slots receive
session-scoped handles.

`src/orchestration/role_separated_fss_query.py` generates exactly two native DPF
shares, invokes evaluator indices 0 and 1, combines their projected responses,
and resolves only nonzero candidate handles through the authorized local handle
map. `scripts/run_role_separated_fss_query.py` exposes this local simulation as
a standalone command. The projection is global rather than query-specific;
otherwise its sparse point mapping would disclose the requested point to each
evaluator.

## Semantic projection and encoded traversal

Opaque snapshots may optionally include HMAC-only relation and entity semantic
bucket mappings. Enable them during export with `--semantic-buckets`; the
selected `--semantic-bucket-mode` is recorded in the snapshot and must match
online routing. No plaintext labels, setup keys, or display maps are added.

`src/orchestration/role_separated_semantic_routing.py` derives the query's
alias/LSH bucket names at the trusted gateway and issues one projected DPF
lookup for each HMAC bucket token. Each evaluator projects its bucket
evaluation share directly into relation or entity candidate slots. The
coordinator combines candidate slots, not matched bucket positions. Candidate
penalties are deterministic bucket-coverage penalties because raw embedding
vectors are intentionally excluded from evaluator snapshots.

`src/orchestration/role_separated_encoded_matcher.py` consumes exact and
semantic candidate IDs and traverses the union of replicated HMAC adjacency
snapshots. It supports path-shaped multi-hop query graphs, reverse traversal,
and type constraints. Complete encoded paths are hashed into opaque candidate
IDs. Each supporting opaque partition contributes a presence row, the path
score, and its edge-support count to the Prio candidate pipeline.

`scripts/run_role_separated_secure_retrieval.py` connects these stages for
local validation:

```text
projected exact/semantic FSS lookup
  -> encoded multi-hop traversal
  -> per-partition CandidateContribution rows
  -> Prio3 presence/score/support aggregation
  -> local top-k validation
```

This command requires `--allow-local-reconstruction`. It loads both evaluator
stores and the Rust Prio implementation in one process, so the coordinator can
observe opaque candidate IDs and reconstructed aggregate values. A production
deployment still needs network-separated evaluators, share-preserving
FSS-to-ranking conversion, and distributed MPC/GC ranking.

For a local MetaQA export using the same local embedding configuration as
SimGRAG:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 scripts/export_opaque_fss_snapshots.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --topology configs/secure/metaqa_prio3_roles.local.json \
  --output-dir /tmp/fedkg-opaque-semantic \
  --semantic-buckets \
  --semantic-bucket-mode hybrid \
  --embedding-backend simgrag \
  --embedding-config ../SimGRAG/configs/federated/metaqa_party_0.json
```

The online command must use the same bucket mode and embedding backend:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
FEDKG_PRIO_HANDLE_KEY="dev-prio-handle-key" \
python3 scripts/run_role_separated_secure_retrieval.py \
  --store-0 /tmp/fedkg-opaque-semantic/fss_evaluator_0 \
  --store-1 /tmp/fedkg-opaque-semantic/fss_evaluator_1 \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|A Foreign Affair' \
  --request-id metaqa-semantic-two-hop \
  --query-nonce metaqa-query-0001 \
  --semantic-bucket-mode hybrid \
  --embedding-backend simgrag \
  --embedding-config ../SimGRAG/configs/federated/metaqa_party_0.json \
  --prio-aggregators 3 \
  --candidate-capacity 256 \
  --topk 3 \
  --allow-local-reconstruction
```
