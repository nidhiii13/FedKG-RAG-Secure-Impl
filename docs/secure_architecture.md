# Secure Federated Retrieval Architecture

This repository implements the first end-to-end secure exact-retrieval slice of
the planned federated KG-RAG architecture. The implementation currently focuses
on HMAC encoding, real two-party DPF lookup, raw eval-share aggregation, shared
opaque evaluation universes, private exact retrieval through the encoded
structural DFS path, additive score/support sharing, a top-k ranking interface,
and controlled reveal of only selected evidence paths.

## Current implemented flow

1. Party-local offline preparation
   - Load each party graph from the existing SimGRAG MetaQA manifest.
   - Normalize entity, relation, and type strings.
   - Encode them with HMAC-SHA256 using `FEDKG_SETUP_KEY`.
   - Check that the current DPF projection, `hmac_sha256_prefix64`, has no
     collisions inside entity, relation, or type IDs.

2. Query preparation
   - Compile query graph labels into HMAC exact IDs.
   - Generate real two-party DPF key shares with `tools/fss_cli/fedkg-fss-cli`.
   - The query plaintext is not sent to parties; parties receive only their DPF
     key shares.

3. Shared opaque evaluation universe
   - For each query node/relation/type label, build a shared set of encoded
     points that all parties must evaluate.
   - The universe contains HMAC IDs, not plaintext labels.
   - This is required because DPF outputs are shares; reconstruction only works
     when parties evaluate the same point.

4. Party-side private evaluation
   - Each party evaluates its DPF key share over the shared encoded universe.
   - The party returns raw uint64 eval shares, not local match decisions.
   - A single party's eval value must never be interpreted as a boolean match.

5. Private lookup aggregation
   - The aggregator combines party eval shares modulo `2^64`.
   - A reconstructed nonzero value indicates the queried HMAC ID matched that
     encoded point.
   - The aggregator emits candidate IDs only for parties that actually own the
     matched encoded point locally.

6. Structural retrieval
   - `PrivateExactRetriever` now orchestrates the full exact private lookup path.
   - Aggregated encoded candidates are passed into `EncodedExactRetriever.retrieve_from_candidates`.
   - Edge direction, relation constraints, type constraints, and alignment-based
     cross-party traversal remain encoded.

7. Score/support share generation
   - Each structural match is converted into an opaque candidate ID derived from
     the encoded evidence path.
   - Retrieval scores and support counts are encoded as fixed-point integers.
   - The encoded values are split into additive shares before aggregation.

8. Secure aggregation boundary
   - Candidate shares with the same opaque candidate ID are merged by
     `ShareAggregator`.
   - The aggregator combines score shares and support shares, but does not need
     plaintext query labels or party-local KG contents.
   - Prio/VDAF-style validation is still planned for checking well-formed shares
     before accepting them at production strength.

9. Ranking and controlled evidence reveal
   - Ranking is called through the `SecureTopK` interface.
   - The current end-to-end implementation can use `LocalGarbledCircuitTopK`,
     which evaluates ranking comparisons through local garbled Boolean circuits.
   - `PrototypeRevealingTopK` remains available only as a simple revealing test
     backend.
   - The production secure implementation still needs distributed GC execution,
     oblivious transfer, and network-separated n-party MPC roles.
   - `RankedEvidencePipeline` reveals only the evidence paths whose candidate IDs
     are selected by top-k.
   - Party ownership is not stored in `MatchResult` and is not emitted in the
     query result JSON. Party IDs remain internal routing metadata only.

10. Later stages
   - Semantic bucket lookup will use the same pattern: bucket token generation,
     DPF/FSS evaluation, and share aggregation.
   - Split `LocalGarbledCircuitTopK` into distributed n-party MPC/BMR-style ranking roles.
   - Add Prio/VDAF-style validation before score/support aggregation.

## Prototype boundary

The native FSS backend currently uses a 64-bit projection of 256-bit HMAC IDs.
This is acceptable for the first engineering prototype only because index build
now rejects projection collisions. The production direction should use a wider
DPF domain, preferably 128 bits or higher, if supported by the backend.

The current shared evaluation universe is built from encoded party indexes. This
keeps plaintext private, but the universe size and encoded-point overlap pattern
are still visible to the component coordinating evaluation. A stronger version
should add padding, batching, and possibly VDAF/Prio-style validity checks.

The current garbled-circuit top-k path is still a prototype boundary.
`LocalGarbledCircuitTopK` performs ranking comparisons with garbled Boolean
circuits, but all n-party roles run in one process and share-to-circuit input conversion is local. This validates the GC ranking
methodology and orchestration boundary, but production private ranking still
requires distributed n-party execution and secure share-to-circuit input conversion.


## Running the current exact private path

Build the native FSS CLI first:

```bash
cmake --build build/fss_cli
```

A small native-backend smoke test can be run with a query-ID universe:

```bash
FEDKG_SETUP_KEY=dev-smoke-test-key python3 scripts/run_private_exact_query.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --edge 'Kismet|starred_actors|Marlene Dietrich' \
  --universe query-ids
```

`--universe query-ids` validates the real DPF backend and retrieval wiring, but
it is not private because the evaluated universe is exactly the queried IDs.
The intended private mode is `--universe full`, where all parties evaluate the
same opaque HMAC universe. Full mode is guarded because the current CLI backend
starts one process per eval point; batch eval should be implemented next before
running full MetaQA-scale private lookup.



## Party-local structural matching status

The initial exact-retrieval prototype used central encoded DFS after DPF/FSS lookup.
That preserved correctness, but the orchestrator still needed internal party-route
metadata to call each party index.

The stronger path now implemented is party-local structural matching:

1. Each party checks exact structural paths inside its own HMAC-encoded KG.
2. The party returns only opaque path IDs plus additive score/support shares.
3. The aggregator ranks opaque candidates with the `SecureTopK` interface.
4. Selected evidence is revealed only by parties that hold the chosen opaque path
   IDs.

This removes party ownership from aggregator-side structural DFS for local paths.

Cross-party multi-hop handoff is now implemented as prototype plumbing:

1. The first party derives an opaque frontier token for the intermediate entity.
2. DPF/FSS key shares are generated for that frontier token.
3. All parties evaluate the shares against their local frontier indexes.
4. Matching parties can continue the second hop from their local KG.
5. The aggregator receives opaque path shares and selected evidence only.

This currently supports exact chain-shaped multi-hop frontier handoff. Production hardening still
needs batching, padding, token-linkage hiding, and a fully network-separated
party execution model.

## End-to-end ranked retrieval status

`PrivateExactRetriever.retrieve_ranked(...)` now runs the implemented exact
private retrieval path, creates additive score/support shares, aggregates shares
by opaque candidate ID, calls the `SecureTopK` interface, and returns only the
selected evidence paths in `ranked_results`. For GC ranking tests this should be run with `LocalGarbledCircuitTopK`; the
interface is deliberately shaped so a distributed garbled-circuit backend can
replace the local backend without changing the retriever API.

## Batch eval status

The native CLI supports `eval_many`, and `FssCliBackend` chunks party-side
evaluation requests. On the current MetaQA sample query
`Kismet|starred_actors|Marlene Dietrich`, full-universe private exact lookup
uses 80,311 eval points and completed in about 36 seconds with batch size 256.
The next performance improvement is replacing the temporary regex-based C++ JSON
parser with a proper parser or binary protocol so larger batches can be used
safely.
