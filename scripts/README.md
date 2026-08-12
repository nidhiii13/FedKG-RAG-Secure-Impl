# Scripts

Command-line entry points for setup, party-local indexing, query execution, and experiments.

## Three-party DORAM regression

`run_doram_regression.py` runs the packed oblivious-scan DORAM over the bundled
three-owner diverse fixture, the prepared bounded-fanout MetaQA fixture, or
both. Because the MPC program supports at most ten queries per batch, a
250-query run consists of 25 batches. The fixtures contain ten distinct
validated queries; the runner repeats them cyclically for execution regression
and checks every decoded result against its cleartext/reference output.

Run both datasets, preserving console output as a top-level log:

```bash
RUN_DIR="results/doram_regression_250_$(date -u +%Y%m%dT%H%M%SZ)"

python3 scripts/run_doram_regression.py \
  --dataset both --query-count 250 --batch-size 10 \
  --mpspdz-home ../SimGRAG/external/MP-SPDZ \
  --metaqa-fixture-dir /tmp/doram-metaqa-cap2-q10 \
  --output-dir "$RUN_DIR" 2>&1 | tee "${RUN_DIR}.log"
```

Each batch directory contains its queries, three private input files, copied
server logs, decoded client output, and a `batch_summary.json`. The run is
resumable after interruption:

```bash
python3 scripts/run_doram_regression.py \
  --dataset both --query-count 250 --batch-size 10 \
  --mpspdz-home ../SimGRAG/external/MP-SPDZ \
  --metaqa-fixture-dir /tmp/doram-metaqa-cap2-q10 \
  --output-dir "$RUN_DIR" --resume 2>&1 | tee -a "${RUN_DIR}.log"
```

Analyze completeness, reference accuracy, stage times, communication, and
reported rounds:

```bash
python3 scripts/analyze_doram_regression.py \
  --run-dir "$RUN_DIR" --strict | tee "${RUN_DIR}/analysis.log"
```

The machine-readable report is written to `$RUN_DIR/analysis.json`. A quick
one-batch end-to-end smoke test is:

```bash
python3 scripts/run_doram_regression.py \
  --dataset diverse --query-count 10 --max-batches 1 \
  --mpspdz-home ../SimGRAG/external/MP-SPDZ \
  --output-dir /tmp/doram-diverse-smoke
```

The MetaQA input is the existing deterministic fanout-two snapshot with ten
selected cap-preserving queries. Repeating those queries does not constitute a
250-distinct-query or uncapped MetaQA accuracy evaluation. MP-SPDZ also warns
that rounds reported by the multithreaded program can be counted twice; the
analysis retains that caveat rather than presenting them as sequential WAN
round trips.

## SimGRAG-compatible semantic embeddings

`run_private_frontier_query.py` defaults to the lightweight deterministic hashing
embedder used by unit tests. To use the same local SentenceTransformer model path
configured by SimGRAG, pass:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" python3 scripts/run_private_frontier_query.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|A Foreign Affair' \
  --semantic-relations \
  --semantic-bucket-mode hybrid \
  --embedding-backend simgrag \
  --embedding-device cpu
```

This loads `embedding_model.model_path` from the first party config in the
manifest unless `--embedding-config` or `--embedding-model-path` is supplied.
The model is loaded with `local_files_only=True`; query and party labels are
embedded only inside the trusted gateway/party-local indexing boundary. DPF/FSS
still evaluates only HMACed bucket tokens, not raw text or raw embeddings.

## Hybrid DPF/FSS Lookup + Prio Aggregation

`run_hybrid_dpf_prio_retrieval.py` is the practical-speed validation path:

```text
two non-colluding DPF/FSS evaluators for private lookup
-> encoded graph traversal over HMAC-only snapshots
-> Prio3 validated candidate score/support aggregation
-> local validation ranking
```

Export semantic-enabled evaluator snapshots first:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 scripts/export_opaque_fss_snapshots.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --topology configs/secure/metaqa_prio3_roles.local.json \
  --output-dir /tmp/fedkg-opaque-fss-semantic-hybrid \
  --semantic-buckets \
  --semantic-bucket-mode hybrid \
  --embedding-backend hashing
```

Run a query:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key \
FEDKG_PRIO_HANDLE_KEY=dev-prio-handle-key-123456 \
python3 scripts/run_hybrid_dpf_prio_retrieval.py \
  --store-0 /tmp/fedkg-opaque-fss-semantic-hybrid/fss_evaluator_0 \
  --store-1 /tmp/fedkg-opaque-fss-semantic-hybrid/fss_evaluator_1 \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|Angel' \
  --request-id hybrid-smoke-kismet-angel \
  --query-nonce hybrid-smoke-kismet-angel-0001 \
  --output results/hybrid_dpf_prio_kismet_angel.json \
  --semantic-bucket-mode hybrid \
  --allow-local-validation-reconstruction
```

The local command reconstructs Prio aggregates for validation. Production should
replace that last step with MPC/GC top-k over aggregate shares.

## MPC Query Shares + DPF/FSS Lookup + Prio Aggregation

`run_mpc_dpf_prio_pipeline.py` adds an explicit local MPC-style query-share
bridge before the same practical lookup/aggregation path:

```text
query graph -> additive shares of HMAC query tokens
-> two non-colluding DPF/FSS evaluators for private lookup
-> Prio3 validated candidate aggregation
-> local validation ranking
```

Run the smoke query with timing:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key \
FEDKG_PRIO_HANDLE_KEY=dev-prio-handle-key-123456 \
python3 scripts/run_mpc_dpf_prio_pipeline.py \
  --store-0 /tmp/fedkg-opaque-fss-semantic-hybrid/fss_evaluator_0 \
  --store-1 /tmp/fedkg-opaque-fss-semantic-hybrid/fss_evaluator_1 \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|Angel' \
  --request-id mpc-dpf-prio-smoke-kismet-angel \
  --query-nonce mpc-dpf-prio-smoke-kismet-angel-0001 \
  --output results/mpc_dpf_prio_kismet_angel.json \
  --semantic-bucket-mode hybrid \
  --allow-local-validation-reconstruction
```

This command does not replace the production requirement: the query-share bridge
and final ranking are still local validation stages. A deployment should keep
query shares with network-separated MPC parties and rank Prio aggregate shares
with distributed MPC/GC.

## SealPIR/Lattice PIR Lookup Adapter

`run_sealpir_bucket_query.py` is a separate adapter path for replacing DPF/FSS
lookup with native SealPIR/FastPIR/Spiral-style private retrieval:

```text
private query bucket
-> native lattice-PIR bucket retrieval
-> bounded encoded candidate edges
-> Prio/MPC aggregation
-> GC/MPC top-k
```

Build the encoded bucket index:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 scripts/build_pir_bucket_index.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --output-dir /tmp/fedkg-pir-bucket-index \
  --semantic-bucket-mode alias \
  --max-edges-per-record 64 \
  --record-size 32768
```

Run through the native adapter:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 scripts/run_sealpir_bucket_query.py \
  --index-dir /tmp/fedkg-pir-bucket-index \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|Angel' \
  --semantic-bucket-mode alias \
  --sealpir-cli tools/sealpir_cli/fedkg-sealpir-cli
```

The command requires a native CLI implementing the contract in
`tools/sealpir_cli/README.md`. Python owns the encoded bucket layout and
post-retrieval handoff; the native backend owns PIR setup/query/answer/decode.
