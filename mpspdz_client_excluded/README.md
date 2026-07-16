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
