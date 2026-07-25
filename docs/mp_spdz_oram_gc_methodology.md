# Client-Excluded MP-SPDZ ORAM Retrieval and GC Ranking Boundary

## Current Implemented Status

The current tested implementation uses MP-SPDZ `semi-party.x` for N-party
private computation. Lookup, graph traversal, cross-party join, aggregation, and
top-k selection are executed inside one MPC program.

This is circuit-based MPC, but it is not a standalone distributed garbled-circuit
ranking backend. The local repository also contains a local garbled-circuit
ranking prototype in `src/ranking/garbled_circuit.py`; that module validates the
ranking comparator logic over additive score/support shares, but it reconstructs
shares in one process and is not a production network-separated GC protocol.

The earlier DPF/FSS private-frontier pipeline already uses this local GC
prototype through `LocalGarbledCircuitTopK`. In that path, party-local structural
matches are converted into additive score/support shares, shares are aggregated
by opaque candidate ID, and the local GC comparator is used to order candidates.
This is accurate as an executable prototype of the GC ranking logic, but it must
not be described as a deployed distributed garbled-circuit protocol.

The MP-SPDZ ORAM batch runners now expose the same prototype through:

```text
--ranking-backend local-gc-prototype
```

This option reranks only the paths already selected by MP-SPDZ using
`LocalGarbledCircuitTopK`. It demonstrates that the ORAM path can call the same
GC comparator module as the FSS/private-frontier path. It does not replace the
hidden-candidate MPC top-k step with a distributed GC.

The repository also includes a stronger HMAC-ID variant for the MP-SPDZ ORAM
path. Instead of truncating HMAC-SHA256 to one 61-bit field element, it stores
each entity/relation identifier as four 32-bit limbs:

```text
id = (hmac_limb_0, hmac_limb_1, hmac_limb_2, hmac_limb_3)
```

Equality is checked limb-wise inside MPC:

```text
left_0 == right_0 AND left_1 == right_1 AND left_2 == right_2 AND left_3 == right_3
```

This uses the first 128 bits of HMAC-SHA256 exactly while preserving conservative
MP-SPDZ field-size assumptions. The implementation is isolated in:

```text
mpspdz_client_excluded/scripts/build_metaqa_oram_limb_indexes.py
mpspdz_client_excluded/scripts/run_source_oram_limb_metaqa_batch.py
mpspdz_client_excluded/programs/secure_kg_twohop_source_oram_limb_batch_topk.mpc.template
```

The 128-bit ORAM path now also supports relation semantic bucket routing at the
query-gateway stage:

```text
--semantic-buckets --semantic-bucket-mode hybrid
```

During offline index construction, the builder records a semantic bucket
metadata map for the indexed public relation partition:

```text
bucket name -> indexed relation label(s)
alias:actor -> starred_actors
tok:starred -> starred_actors
lsh:... -> starred_actors
```

During query preparation, relation phrases are bucketized with the same logic.
For example:

```text
query relation: actor
bucket: alias:actor
selected indexed relation: starred_actors
```

After this routing step, the selected relation label is encoded as a 128-bit
HMAC ID and used by the MP-SPDZ ORAM traversal. This connects semantic bucket
routing to the 128-bit ORAM flow, but the bucket routing itself is currently a
gateway-side metadata step. A fully private semantic-bucket ORAM inside MPC
would require an additional private bucket-index lookup:

```text
bucket_id -> candidate relation/entity IDs
```

inside MP-SPDZ before graph traversal.

## Role Model

- Client: submits the natural-language query and is not included in the private
  computation after query preparation.
- Query gateway, MP-SPDZ player 0: rewrites the query graph and secret-inputs
  HMAC query IDs/probe positions to MPC.
- Data parties, MP-SPDZ players 1..N: secret-input their private encoded ORAM
  indexes and evidence handles.
- MPC computation layer: performs private lookup, path join, aggregation, and
  ranking.
- Controlled reveal layer: resolves only selected evidence handles after top-k.

## End-to-End Flow

1. Offline indexing.
   Each data party converts its local KG edges into HMAC IDs. For every edge,
   both forward and reverse logical rows are materialized. The optimized ORAM
   path stores only `source_directory` and `source_edges`; reverse rows are used
   for second-hop target lookup.

2. Private query preparation.
   The query gateway rewrites a query into a two-hop query graph. For example:

   ```text
   Kismet --acted in--> UNKNOWN
   UNKNOWN --acted in--> Angel
   ```

   With MetaQA relation aliases enabled, `acted in` is normalized to
   `starred_actors`. The gateway then HMAC-encodes the source, target, and
   relation labels, and computes ORAM probe positions. These values enter
   MP-SPDZ as secret input from player 0.

3. Private ORAM lookup.
   Each data party secret-inputs its query-independent ORAM index. MPC privately
   probes each party directory. Hop 1 looks up:

   ```text
   HMAC(Kismet), HMAC(starred_actors), forward
   ```

   Hop 2 is optimized by reverse lookup:

   ```text
   HMAC(Angel), HMAC(starred_actors), reverse
   ```

   The matched directory offsets/counts and candidate edge reads remain secret.

4. Encoded structural traversal and cross-party join.
   MPC reads a fixed padded number of candidate edges from every party. It joins
   hop 1 and hop 2 by checking whether:

   ```text
   left_target_id == right_source_id
   ```

   This preserves encoded structural matching across parties without revealing
   which party contributed which hop during the computation.

5. Aggregation model.
   Candidate support is computed as secret values inside MPC. Contributions from
   all data parties are combined in the computation layer. The client is not a
   participant in this aggregation. This is an aggregation model, but it is not
   Prio-only aggregation because private KG lookup and graph traversal require
   MPC/ORAM, not just validated summation.

6. Ranking boundary.
   The current tested MP-SPDZ path performs private top-k with a prefix-count
   circuit over secret match/support values and reveals only selected evidence
   handles. This is the production-secure ranking mode available in the current
   checkout:

   ```text
   --ranking-backend mpc --production-secure
   ```

   In this mode, candidate support aggregation and top-k selection remain inside
   MP-SPDZ before controlled evidence reveal.

   The previous GC ranking prototype can be called after this boundary for local
   algorithm testing:

   ```text
   MP-SPDZ-selected candidate path
     -> additive score/support shares
     -> LocalGarbledCircuitTopK comparator
     -> selected candidate IDs
   ```

   In code, this is the same ranking backend used by the FSS/private-frontier
   scripts and exposed in the ORAM batch runners by
   `--ranking-backend local-gc-prototype`:

   ```text
   src/ranking/garbled_circuit.py::LocalGarbledCircuitTopK
   ```

   This checks the intended ranking rule:

   ```text
   lower score is better;
   if scores tie, higher support is better.
   ```

   A production standalone garbled-circuit ranking integration would move this
   before reveal and replace the local reconstruction part with distributed GC
   input handling:

   ```text
   secret candidate score/support values
     -> share-to-GC input conversion
     -> distributed GC or BMR-style n-party comparator/top-k
     -> selected candidate/evidence handles only
   ```

   For two ranking servers this could be Yao-style 2PC GC. For N computation
   parties, the appropriate direction is BMR-style n-party garbled circuits or
   an equivalent n-party private comparison protocol. The local
   `LocalGarbledCircuitTopK` module is only a prototype for the comparator logic,
   not the final distributed GC deployment.

   The current optimized secure implementation therefore satisfies the
   client-excluded N-party MPC lookup/traversal/scoring/aggregation/top-k
   design, but it should be described as MPC top-k rather than distributed
   garbled-circuit top-k.

7. Controlled evidence reveal.
   After top-k, only selected evidence handles are opened. The evidence vault
   resolves those handles to plaintext paths, for example:

   ```text
   Kismet --starred_actors--> Marlene Dietrich
   Marlene Dietrich --starred_actors--> Angel
   ```

   Non-selected candidates, non-matching edges, intermediate ORAM accesses, and
   party ownership are not included in the final output.

## Private Semantic Bucket ORAM Path

The latest opt-in path moves relation semantic bucket resolution into MP-SPDZ.
The gateway no longer resolves a phrase such as `acted in` or `is starred by`
to `starred_actors` before traversal. Instead, it secret-inputs a HMAC bucket
identifier, for example:

```text
HMAC_128(relation_bucket:alias:actor)
```

Each data party privately inputs two additional party-local ORAM tables:

```text
relation_bucket_directory:
  bucket_id -> offset, count

relation_bucket_edges:
  relation_id candidate rows
```

Inside MP-SPDZ, the computation performs:

```text
secret bucket probe
  -> private bucket directory lookup
  -> private candidate relation ID block
  -> entity-only graph ORAM lookup
  -> private relation-ID filter over candidate edges
  -> cross-party middle-entity join
  -> private top-k support selection
  -> selected evidence handles only
```

This required changing graph access from `(entity, relation, direction)` to
`(entity, direction)`. If the graph directory still used relation IDs as part
of the ORAM address, the gateway would need to know the resolved relation ID in
order to compute probe slots. The entity-only directory avoids that leakage by
reading a padded block of candidate edges for the entity and filtering the
relation privately inside MPC.

Implemented files:

```text
mpspdz_client_excluded/scripts/build_metaqa_oram_limb_private_semantic_indexes.py
mpspdz_client_excluded/scripts/run_source_oram_limb_private_semantic_metaqa_batch.py
mpspdz_client_excluded/programs/secure_kg_twohop_source_oram_limb_private_semantic_batch_topk.mpc.template
```

Current boundary: this implementation supports a fixed padded number of query
buckets per relation phrase in one MPC run. The runner uses
`--max-query-buckets` to secret-input multiple bucket IDs. The optimized default
is `4`, ordered as alias buckets, content-token buckets, content-bigram buckets,
and then LSH buckets. Increasing this value improves semantic recall but
increases private bucket ORAM lookups and relation-candidate comparisons
linearly.

The entity-edge fanout is controlled by `--max-candidates`. For local
benchmarking, the runner supports `--auto-tighten-max-candidates`, which
computes the smallest safe fanout for the selected batch from the prepared local
indexes. With `--require-full-fanout`, the run fails instead of silently
truncating if the requested upper bound is too small. This is useful for
accurate experiments, but a production privacy model should normally use a
fixed public fanout bound because query-dependent runtime can leak a degree
bound.

For local timing experiments, the runner also supports
`--compact-probed-benchmark`. This compacts the generated MP-SPDZ input instance
to only the directory probe slots and edge blocks touched by the selected batch.
It preserves the same MPC equality/filter/join logic for those compacted rows,
but it is not production-secure because compact table sizes reveal
query-dependent access-set information. It is intended for fast experimental
comparison while the full ORAM path remains available for the cleaner privacy
profile.

To avoid query-specific optimization while still improving runtime, the code now
supports public-bound compact profiles and compile caching. The analyzer
`analyze_private_semantic_oram_bounds.py` computes dataset-wide fanout
statistics from the offline index, such as p95/p99/max entity degree and
relation-bucket degree. A fixed public profile can then be chosen for a dataset
or benchmark suite and reused for all queries. The runner also hashes public
circuit dimensions into the MP-SPDZ program name and supports
`--skip-compile-if-present`, so repeated runs with the same public shape can
reuse compiled bytecode without depending on a specific query.

For the current `starred_actors` MetaQA partition, `--max-relation-candidates 1`
is sufficient because each semantic bucket maps to one indexed relation.

## What Must Be Added for Real Distributed GC Ranking

The current MP-SPDZ binary available in this checkout is `semi-party.x`; no
Yao/BMR GC runtime is currently built. To integrate real distributed GC ranking,
one of the following must be added:

- build and connect an MP-SPDZ Yao backend for a 2-party ranking stage; or
- implement/connect BMR-style n-party garbled-circuit ranking; or
- keep ranking inside MP-SPDZ N-party MPC and describe it as MPC top-k rather
  than a standalone garbled circuit.

The third option is what is currently implemented and tested.
