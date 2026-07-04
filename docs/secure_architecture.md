# Secure Federated Retrieval Architecture

This repository implements the first secure exact-retrieval slice of the planned
federated KG-RAG architecture. The implementation currently focuses on HMAC
encoding, real two-party DPF lookup, raw eval-share aggregation, shared opaque
evaluation universes, and private exact retrieval through the encoded structural
DFS path.

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

7. Later stages
   - Semantic bucket lookup will use the same pattern: bucket token generation,
     DPF/FSS evaluation, and share aggregation.
   - Score aggregation can later be strengthened with Prio/VDAF-style validation.
   - Top-k ranking remains planned as a garbled-circuit ranking stage.

## Prototype boundary

The native FSS backend currently uses a 64-bit projection of 256-bit HMAC IDs.
This is acceptable for the first engineering prototype only because index build
now rejects projection collisions. The production direction should use a wider
DPF domain, preferably 128 bits or higher, if supported by the backend.

The current shared evaluation universe is built from encoded party indexes. This
keeps plaintext private, but the universe size and encoded-point overlap pattern
are still visible to the component coordinating evaluation. A stronger version
should add padding, batching, and possibly VDAF/Prio-style validity checks.


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


## Batch eval status

The native CLI supports `eval_many`, and `FssCliBackend` chunks party-side
evaluation requests. On the current MetaQA sample query
`Kismet|starred_actors|Marlene Dietrich`, full-universe private exact lookup
uses 80,311 eval points and completed in about 36 seconds with batch size 256.
The next performance improvement is replacing the temporary regex-based C++ JSON
parser with a proper parser or binary protocol so larger batches can be used
safely.
