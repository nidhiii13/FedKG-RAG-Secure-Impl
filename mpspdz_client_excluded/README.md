# MP-SPDZ Client-Excluded Retrieval Prototype

This folder is an isolated experiment for the N-party MPC possibility. It does
not replace the existing federated, FSS, Prio, Milvus, or Ollama code.

The goal is to prototype this model:

```text
client/query gateway prepares private query input
        |
        v
N MPC parties jointly compute lookup/scoring/ranking
        |
        v
only selected/aggregated outputs are revealed
```

MP-SPDZ is used as the MPC engine. It gives us the arithmetic/binary secure
computation layer, but it does not provide a private graph database by itself.
We still have to encode retrieval into bounded arrays/circuits.

## What This Prototype Implements

The first target is a bounded exact one-hop lookup:

```text
query: (source entity, relation, UNKNOWN target)
```

Each party contributes a fixed-size padded table of encoded local KG edges:

```text
source_id relation_id target_slot score
```

The MP-SPDZ program computes, inside MPC:

```text
source_id == query_source_id
AND
relation_id == query_relation_id
```

For matching rows, it adds support and score into fixed candidate slots. The
program can reveal aggregate support/score for the bounded candidate slots in
this first debugging version.

## Why This Is Useful

This tests the main client-excluded MPC idea:

```text
the query is provided as secret input once,
then the computation parties run lookup and aggregation without the client.
```

It is intentionally bounded because full KG traversal inside MPC is expensive.
Once this works, the next step is to extend the candidate table from one-hop
edges to bounded multi-hop path candidates.

## What This Does Not Yet Solve

This is not yet a full private KG-RAG implementation.

Current limitations:

- one-hop exact lookup, bounded two-hop path-row lookup, and experimental bounded edge-table join only
- bounded candidate slots
- relation alias mapping only; full semantic bucket routing is still separate from this MP-SPDZ path
- arbitrary private multi-hop frontier expansion is not implemented
- no production access-pattern hiding

## Setup

Install MP-SPDZ separately from the official repository:

```bash
git clone https://github.com/data61/MP-SPDZ.git external/MP-SPDZ
cd external/MP-SPDZ
make -j mascot-party.x semi-party.x shamir-party.x
```

For local semi-honest testing, `semi-party.x` is usually the fastest starting
point. For stronger security experiments, use an MP-SPDZ protocol matching the
threat model.

## Generate A MetaQA MPC Instance

From the FedKG-RAG-Secure-Impl repo root:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 mpspdz_client_excluded/scripts/prepare_metaqa_mpspdz_inputs.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --edge 'Kismet|starred_actors|UNKNOWN' \
  --output-dir mpspdz_client_excluded/generated/kismet_starred_actors \
  --rows-per-party 256 \
  --candidate-capacity 64
```

This writes:

```text
generated/kismet_starred_actors/secure_kg_lookup_topk.mpc
generated/kismet_starred_actors/Player-Data/Input-P0-0
generated/kismet_starred_actors/Player-Data/Input-P1-0
generated/kismet_starred_actors/Player-Data/Input-P2-0
generated/kismet_starred_actors/public_mapping.json
```

`P0` is used as the query input provider in this local MP-SPDZ simulation.
`P1..PN` correspond to the data parties from the manifest. In a stronger
deployment, the query gateway would provide input shares and then leave the
online computation.

## Run With MP-SPDZ

Assuming MP-SPDZ is cloned or symlinked at `external/MP-SPDZ`:

```bash
MP_SPDZ_HOME=external/MP-SPDZ \
bash mpspdz_client_excluded/scripts/run_mpspdz_instance.sh \
  mpspdz_client_excluded/generated/kismet_starred_actors
```

The script copies the generated program and input files into MP-SPDZ, compiles
the program, and runs it with the semi-honest local protocol.

## Generate A Two-Hop MetaQA MPC Instance

From the FedKG-RAG-Secure-Impl repo root:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 mpspdz_client_excluded/scripts/prepare_metaqa_twohop_mpspdz_inputs.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --edge 'Kismet|starred_actors|UNKNOWN' \
  --edge 'UNKNOWN|starred_actors|Angel' \
  --output-dir mpspdz_client_excluded/generated/kismet_angel_twohop \
  --rows-per-party 256 \
  --path-capacity 64
```

Then run:

```bash
MP_SPDZ_HOME=external/MP-SPDZ \
bash mpspdz_client_excluded/scripts/run_mpspdz_instance.sh \
  mpspdz_client_excluded/generated/kismet_angel_twohop
```

This two-hop version still uses bounded precomputed path rows. It tests the
MPC computation shape for path matching, but it does not yet perform arbitrary
private graph expansion inside MPC.

## Two-Hop Private Top-k Ranking

The debug two-hop program reveals every candidate slot's aggregate
support/score. To test the ranking stage, use `--reveal-mode topk`:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 mpspdz_client_excluded/scripts/prepare_metaqa_twohop_mpspdz_inputs.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --edge 'Kismet|starred_actors|UNKNOWN' \
  --edge 'UNKNOWN|starred_actors|Angel' \
  --output-dir mpspdz_client_excluded/generated/kismet_angel_twohop_topk \
  --rows-per-party 256 \
  --path-capacity 64 \
  --reveal-mode topk \
  --topk 3
```

Then run:

```bash
MP_SPDZ_HOME=external/MP-SPDZ \
bash mpspdz_client_excluded/scripts/run_mpspdz_instance.sh \
  mpspdz_client_excluded/generated/kismet_angel_twohop_topk
```

This ranks privately inside MP-SPDZ using secure comparisons:

```text
higher support first, then lower score
```

Only selected path slot IDs are revealed. All non-selected candidate
support/score values remain hidden.

## Decode Selected Top-k Slots

After a top-k run, decode only the selected slots:

```bash
python3 mpspdz_client_excluded/scripts/decode_mpspdz_topk_output.py \
  --mapping mpspdz_client_excluded/generated/kismet_angel_twohop_topk/public_mapping.json \
  --mp-spdz-output /tmp/mpspdz_topk_output.txt
```

For quick testing, slots can be passed directly:

```bash
python3 mpspdz_client_excluded/scripts/decode_mpspdz_topk_output.py \
  --mapping mpspdz_client_excluded/generated/kismet_angel_twohop_topk/public_mapping.json \
  --slot 0
```

This reveals only the selected evidence path, for example:

```text
Kismet --starred_actors--> Marlene Dietrich
Marlene Dietrich --starred_actors--> Angel
```

## Single End-to-End Command

The wrapper below generates the instance, runs MP-SPDZ, parses the selected
slot IDs, and performs controlled reveal:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 mpspdz_client_excluded/scripts/run_twohop_e2e.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --edge 'Kismet|starred_actors|UNKNOWN' \
  --edge 'UNKNOWN|starred_actors|Angel' \
  --output-dir /tmp/fedkg-mpspdz-twohop-e2e \
  --rows-per-party 16 \
  --path-capacity 8 \
  --topk 3 \
  --mp-spdz-home external/MP-SPDZ
```

For natural-language MetaQA relation aliases such as `acted in`, enable
canonical relation mapping before HMAC/MPC encoding:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 mpspdz_client_excluded/scripts/run_twohop_e2e.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|Angel' \
  --output-dir /tmp/fedkg-mpspdz-twohop-semantic \
  --rows-per-party 16 \
  --path-capacity 8 \
  --topk 3 \
  --semantic-relations \
  --mp-spdz-home external/MP-SPDZ
```

## Batch Smoke Test

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 mpspdz_client_excluded/scripts/run_twohop_batch.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --queries-jsonl mpspdz_client_excluded/examples/twohop_queries.jsonl \
  --output /tmp/fedkg-mpspdz-twohop-batch.jsonl \
  --rows-per-party 16 \
  --path-capacity 8 \
  --topk 3 \
  --semantic-relations \
  --mp-spdz-home external/MP-SPDZ
```

## Experimental Edge-Table Join

The path-row two-hop runner above precomputes bounded path rows before MPC. The
separate edge-table prototype instead lets each data party input padded one-hop
edge rows and performs the two-hop join inside MP-SPDZ:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 mpspdz_client_excluded/scripts/run_twohop_edge_join_e2e.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|Angel' \
  --output-dir /tmp/fedkg-mpspdz-edge-join \
  --edge-rows-per-party 16 \
  --topk 3 \
  --semantic-relations \
  --prioritize-query-rows \
  --mp-spdz-home external/MP-SPDZ
```

This is the cleaner MPC shape for private traversal, but it is much heavier:
the local smoke test checks all edge-row pairs inside MPC. The
`--prioritize-query-rows` flag is only a local testing shortcut to keep the
bounded table small; a production design needs fixed padded edge tables,
batching, ORAM/PIR, or another access-pattern-hiding layer.

The current template precomputes first-hop matches, second-hop matches, and
pair support once before top-k ranking. It then selects the first top-k matching
pairs using a secure prefix count instead of repeatedly running a full max
comparison circuit. On the 16-row-per-party smoke test, this reduced the local
run from roughly `49s` E2E / `7.67GB` global communication / `144k` rounds to
roughly `12s` E2E / `1.55GB` global communication / `6.9k` rounds.

## Split Edge-Table Join

The split edge-table prototype separates bounded first-hop rows from bounded
second-hop rows, reducing the MPC join space from `all_edges x all_edges` to
`left_edges x right_edges`:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 mpspdz_client_excluded/scripts/run_twohop_split_edge_join_e2e.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|Angel' \
  --output-dir /tmp/fedkg-mpspdz-split-edge-join \
  --left-rows-per-party 4 \
  --right-rows-per-party 8 \
  --topk 3 \
  --semantic-relations \
  --prioritize-query-rows \
  --mp-spdz-home external/MP-SPDZ
```

On the same smoke query, this produced the selected path in roughly `2.4s` E2E,
with `0.82s` MPC time, `195MB` global communication, and `1459` rounds. This is
currently the fastest private-traversal prototype, but the bounded role-specific
tables are still a research/protocol design choice that must be made privacy
safe for production.

For stricter query privacy against data parties, use query-independent table
construction:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 mpspdz_client_excluded/scripts/run_twohop_split_edge_join_e2e.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --edge 'Stephen Furst|act in|UNKNOWN film 1' \
  --edge 'UNKNOWN film 1|acted by|Stephen Furst' \
  --output-dir /tmp/fedkg-mpspdz-private-tables \
  --left-rows-per-party 8 \
  --right-rows-per-party 8 \
  --topk 3 \
  --semantic-relations \
  --private-tables \
  --mp-spdz-home external/MP-SPDZ
```

In `--private-tables` mode, party tables are built from fixed universal logical
KG rows rather than by filtering on the query entity/relation. This is the
correct privacy direction, but small row bounds may miss the answer because the
needed edge might not be inside the bounded universal table. Larger bounds
increase coverage and MPC cost.

## Simulating Parties On Different Hosts

The default runner uses `Scripts/semi.sh`, which starts separate MP-SPDZ party
processes on `localhost`. To simulate parties on different machines or
containers, generate an instance first and then print the per-party commands:

```bash
python3 mpspdz_client_excluded/scripts/print_distributed_mpspdz_commands.py \
  --instance-dir /tmp/fedkg-mpspdz-twohop-semantic-check \
  --mp-spdz-home external/MP-SPDZ \
  --players 3 \
  --host0 10.0.0.10 \
  --port 14000
```

Each host needs the same compiled MP-SPDZ program, but each party should receive
only its own `Player-Data/Input-P{id}-0` file. Party 0 coordinates startup at
`--host0`; the other parties connect to it using the same port base.

To create per-party bundle directories for copying to separate hosts:

```bash
python3 mpspdz_client_excluded/scripts/package_distributed_mpspdz_instance.py \
  --instance-dir /tmp/fedkg-mpspdz-twohop-semantic-check \
  --output-dir /tmp/fedkg-mpspdz-party-bundles \
  --players 3 \
  --host0 10.0.0.10 \
  --port 14000
```

This creates `party_0`, `party_1`, and `party_2` folders. Each folder contains
the common MPC source and only that party's own input file.

## Security Interpretation

This folder is for evaluating the N-party MPC direction, not for claiming the
final system is solved.

Compared with the 2-server DPF/FSS design:

- this can support more than two computation parties;
- lookup/scoring can happen inside MPC;
- the client does not need to stay in the computation after input sharing;
- scalability is harder because graph traversal becomes circuit work.

## Query-Independent ORAM Adjacency Retrieval

The ORAM path removes query-dependent plaintext table construction. Each data
party first builds two private adjacency indexes without seeing an online
query: a source/relation directory for hop 1 and a target/relation directory
for hop 2. Directory records point to compact contiguous edge blocks. Both the
directory and edge stores are accessed through MP-SPDZ `OptimalORAM` using
secret indexes.

Build the public `starred_actors` schema partition once:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 mpspdz_client_excluded/scripts/build_metaqa_oram_indexes.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --output-dir /tmp/fedkg-metaqa-oram-starred-index \
  --relation starred_actors \
  --max-candidates 64
```

Run a private two-hop query over those indexes:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" \
python3 mpspdz_client_excluded/scripts/run_twohop_oram_e2e.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --index-dir /tmp/fedkg-metaqa-oram-starred-index \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|Angel' \
  --output-dir /tmp/fedkg-metaqa-oram-kismet-angel \
  --max-candidates 64 \
  --topk 3 \
  --semantic-relations \
  --mp-spdz-home external/MP-SPDZ
```

The online computation performs this sequence:

```text
secret HMAC query IDs
  -> secret ORAM directory probes at every data party
  -> fixed-size private adjacency blocks
  -> cross-party middle-entity join inside MPC
  -> secure prefix-count top-k
  -> selected evidence handles only
  -> party-local controlled plaintext reveal
```

The query gateway is represented by MP-SPDZ player 0 in local tests; it is a
dedicated input provider, not the end client. Data parties are players 1..N.
The N-party runner derives the player count from the generated input files.

Current boundaries are explicit:

- `--semantic-relations` currently applies the established MetaQA relation
  alias mapping before secret input; full LSH semantic-bucket lookup inside
  N-party MPC is not yet connected.
- Known-target two-hop queries and synthetic MetaQA type-identity edges are
  supported. Unknown-to-unknown second-hop expansion requires another private
  frontier ORAM access round and is rejected.
- `max-candidates` is a public padded adjacency bound. The builder reports the
  maximum degree so truncation can be avoided.
- The local runner initializes ORAM state for every process. A deployment and
  meaningful performance benchmark should persist/preprocess ORAM state rather
  than charge offline initialization to every query.
- `query_gateway_receipt.json` and party evidence vaults are role-private
  artifacts and must not be copied into data-party bundles or public results.

## Source-Only ORAM Optimization

`run_source_oram_metaqa_batch.py` is an optimized batch runner that keeps the
baseline ORAM path unchanged. It uses only `source_directory` and
`source_edges`. The offline index already contains reverse logical rows, so a
second hop of the form:

```text
middle --relation--> known_target
```

is evaluated by privately looking up:

```text
known_target --relation(reverse_direction)--> middle
```

inside the same source ORAM. The MPC circuit swaps that row back into logical
second-hop orientation before joining on the middle entity. This removes the
target directory ORAM and target edge ORAM from the batch circuit, reducing the
largest initialization cost while preserving the same controlled evidence reveal
policy.

Run the optimized 10-query batch:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 \
  mpspdz_client_excluded/scripts/run_source_oram_metaqa_batch.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --index-dir /tmp/fedkg-metaqa-oram-starred-index \
  --queries-jsonl examples/private_frontier_from_federated_q2_500.jsonl \
  --output results/mpspdz_source_oram_q2_first10.jsonl \
  --instance-dir /tmp/fedkg-mpspdz-source-oram-q2-first10 \
  --max-queries 10 \
  --max-candidates 64 \
  --auto-tighten-max-candidates \
  --require-full-fanout \
  --topk 3 \
  --semantic-relations \
  --mp-spdz-home external/MP-SPDZ
```

## Private Semantic Bucket ORAM

`run_source_oram_limb_private_semantic_metaqa_batch.py` is a separate opt-in
path for private relation semantic routing. The gateway secret-inputs HMAC
relation-bucket IDs, such as `alias:actor`, and MP-SPDZ privately resolves:

```text
relation bucket ID -> candidate relation ID(s) -> entity-only ORAM edge filter
```

This is different from the older gateway-side semantic path, where the gateway
resolved the bucket to `starred_actors` before MPC. To make the relation private
inside MPC, this path uses an entity-only graph directory and filters relation
IDs after the candidate edge block has been read.

For the N-party MPC design from Possibility 2, use the clearer wrapper:

```text
run_private_indexed_mpc_metaqa_batch.py
```

It preserves the same private indexed implementation but enables the cleaner
production profile by default:

```text
private semantic bucket lookup
-> private entity-index lookup
-> bounded MPC graph traversal/join
-> MPC support aggregation and top-k
-> controlled evidence reveal
```

The client/query gateway provides secret query inputs and does not participate
after input setup. Data parties provide secret padded indexes. The public
dataset/profile parameters are directory capacities, probe limits, candidate
padding, query-bucket padding, party count, protocol, and top-k.

Build a private semantic 128-bit index:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 \
  mpspdz_client_excluded/scripts/build_private_indexed_mpc_metaqa_indexes.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --output-dir /tmp/fedkg-metaqa-private-semantic-oram-index \
  --relation starred_actors \
  --semantic-bucket-mode hybrid \
  --max-candidates 16 \
  --max-relation-candidates 1
```

Run the private semantic batch path in the cleaner production-secure profile:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 \
  mpspdz_client_excluded/scripts/run_private_indexed_mpc_metaqa_batch.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --index-dir /tmp/fedkg-metaqa-private-semantic-oram-index \
  --queries-jsonl examples/private_frontier_from_federated_q2_500.jsonl \
  --output results/mpspdz_private_semantic_oram_q2_first10.jsonl \
  --instance-dir /tmp/fedkg-mpspdz-private-semantic-oram-q2-first10 \
  --max-queries 10 \
  --max-candidates 16 \
  --max-relation-candidates 1 \
  --max-query-buckets 4 \
  --topk 3 \
  --semantic-bucket-mode hybrid \
  --mp-spdz-protocol semi \
  --mp-spdz-home external/MP-SPDZ
```

The run wrapper automatically adds `--production-secure`,
`--ranking-backend mpc`, and `--skip-compile-if-present` unless explicitly
overridden. Use the underlying runner directly only for ablations and local
benchmark modes.

The runner supports padded multi-bucket routing per relation phrase through
`--max-query-buckets`. The optimized default is `4`, ordered as high-value
alias buckets, content-token buckets, content-bigram buckets, and then LSH
buckets. The gateway still does not choose or see the resolved relation IDs
from each party's bucket table.

Cost boundary: increasing `--max-query-buckets` increases private bucket ORAM
lookups and relation-candidate comparisons linearly. `--max-candidates` controls
the padded entity-edge fanout. For local benchmarking, use a safe high build
padding, then run with `--auto-tighten-max-candidates --require-full-fanout`.
This compiles the smallest circuit needed by the selected batch without
truncating candidate edges. In a production privacy model, the fanout bound
should normally be fixed publicly because query-dependent runtime can leak a
degree bound.

Local benchmark profile:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 \
  mpspdz_client_excluded/scripts/run_source_oram_limb_private_semantic_metaqa_batch.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --index-dir /tmp/fedkg-metaqa-private-semantic-oram-index \
  --queries-jsonl examples/private_frontier_from_federated_q2_500.jsonl \
  --output results/mpspdz_private_semantic_oram_q2_first10_benchmark.jsonl \
  --instance-dir /tmp/fedkg-mpspdz-private-semantic-oram-q2-first10-benchmark \
  --max-queries 10 \
  --max-candidates 64 \
  --auto-tighten-max-candidates \
  --require-full-fanout \
  --compact-probed-benchmark \
  --topk 3 \
  --semantic-bucket-mode hybrid \
  --ranking-backend local-gc-prototype \
  --mp-spdz-home external/MP-SPDZ
```

`--production-secure` rejects `--ranking-backend local-gc-prototype` and
`--auto-tighten-max-candidates`. This keeps ranking inside MP-SPDZ before
evidence reveal and avoids query-dependent fanout timing leakage.

`--compact-probed-benchmark` is an additional local speed mode. It rewrites the
generated MP-SPDZ instance so each party input contains only the directory probe
slots and edge blocks touched by the selected batch. This dramatically reduces
ORAM initialization cost for experiments, but it is not a production privacy
profile because table sizes become query-dependent. On one full MetaQA query,
the compact benchmark reduced the entity directory from `131072` rows to `9`
rows and completed in about `7.6s` locally.

For a dataset-independent public-bound profile, first analyze the offline index:

```bash
python3 mpspdz_client_excluded/scripts/analyze_private_semantic_oram_bounds.py \
  --index-dir /tmp/fedkg-metaqa-private-semantic-oram-index \
  --percentile 99 \
  --max-query-buckets 4 \
  --max-queries 1
```

This reports public fanout and compact-table bounds such as p95/p99/max entity
degree. Choose a public profile once for the dataset or benchmark suite, then
reuse it for all queries. For repeated runs with the same public circuit shape,
add:

```text
--skip-compile-if-present
```

The runner hashes only public circuit dimensions into the MP-SPDZ program name,
so compile caching is query-independent. On a tiny fixed profile, the second run
skipped compilation and reduced wall time from about `16.6s` to `10.4s`.

For the current `starred_actors` MetaQA partition, `--max-relation-candidates 1`
is sufficient because every matching semantic bucket maps to a single indexed
relation.

## Fixed Bucketized MPC Path

`build_metaqa_bucketized_mpc_indexes.py` and
`run_bucketized_mpc_metaqa_batch.py` implement the ORAM-free N-party MPC path.
Each data party secret-inputs a fixed padded table of bucketized KG edge rows:

```text
bucket_id, source_id, relation_id, target_id, evidence_handle, direction, valid
```

MP-SPDZ scans the fixed public table size, privately matches query bucket IDs
and entity IDs, compacts matches into fixed left/right candidate buffers,
performs a bounded private two-hop join, aggregates support, and reveals only
selected evidence handles. This avoids private random-access ORAM and avoids the
earlier `ROW_TOTAL^2` all-row join. The public circuit cost is approximately:

```text
ROW_TOTAL * (LEFT_CANDIDATE_CAP + RIGHT_CANDIDATE_CAP)
+ LEFT_CANDIDATE_CAP * RIGHT_CANDIDATE_CAP
```

The candidate caps are fixed public security-profile parameters, not
query-dependent tightening knobs. Increase them for high-fanout datasets; lower
values are faster but can truncate candidate sets before top-k.

Build a small alias-bucket index:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 \
  mpspdz_client_excluded/scripts/build_metaqa_bucketized_mpc_indexes.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --output-dir /tmp/fedkg-metaqa-bucketized-alias-index \
  --relation starred_actors \
  --semantic-bucket-mode alias \
  --rows-per-party 200000
```

Run the bucketized MPC path:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 \
  mpspdz_client_excluded/scripts/run_bucketized_mpc_metaqa_batch.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --index-dir /tmp/fedkg-metaqa-bucketized-alias-index \
  --queries-jsonl examples/private_frontier_from_federated_q2_500.jsonl \
  --output results/mpspdz_bucketized_alias_q2_first1.jsonl \
  --instance-dir /tmp/fedkg-mpspdz-bucketized-alias-q2-first1 \
  --max-queries 1 \
  --max-query-buckets 2 \
  --left-candidate-cap 32 \
  --right-candidate-cap 32 \
  --topk 3 \
  --semantic-bucket-mode alias \
  --skip-compile-if-present \
  --mp-spdz-home external/MP-SPDZ
```

Validation on the tiny two-party fixture passed with `correct=True`. Compile
caching also works for this path.
