# Scripts

Command-line entry points for setup, party-local indexing, query execution, and experiments.

## ComplexWebQuestions 1.1 (gold-SPARQL two-hop evaluation)

The CWQ pipeline evaluates the relation-paged backend on held-out
ComplexWebQuestions test+validation questions whose **gold SPARQL** is a pure
dependent two-hop chain, over one fixed union of RoG-CWQ subgraphs.  Unlike
the RoG-WebQSP oracle-path runner, relation paths are never derived from gold
answers.

```bash
# 1. profile: parses every held-out SPARQL, writes data/cwq/{compatibility_summary.json,twohop_compatible.jsonl,rejected_examples.jsonl}
python3 scripts/profile_cwq.py

# 2. cleartext retrieval evaluation (all 1,267 compatible questions)
python3 scripts/run_cwq_eval.py --questions 0 --bound 8 --topk 32 \
  --neighbourhood-cap 50 --out results/cwq_cleartext_full1267_...

# 3. ablations (bound / top-k / cap / owners / partition)
bash scripts/run_cwq_ablations.sh

# 4. Ollama generation over retrieved evidence only
python3 scripts/run_cwq_answers.py --run <run_dir> --answers 300

# 5. MP-SPDZ Temi validation on a 10-query workload closure
python3 scripts/build_cwq_mpc_fixture.py --queries 10 --out data/cwq/mpc_fixture/q10_closure
python3 scripts/run_kqapro_relation_mpc.py --fixture data/cwq/mpc_fixture/q10_closure \
  --output results/cwq_mpc_temi_q10 --protocol temi
```

Raw inputs live in `data/cwq/raw/`: official `ComplexWebQuestions_{dev,test}.json`
(Dropbox release, SPARQL included) and `rog_cwq_{test,validation}.jsonl`
(HuggingFace `rmanluo/RoG-cwq` parquet converted to JSONL).

## KQA Pro compatibility profiling

`profile_kqapro.py` downloads the frozen KQA Pro KB and question splits from
the published Hugging Face mirror, records file hashes, and conservatively
profiles the dataset against the current anchored two-relation retrieval
functionality:

```bash
python3 scripts/profile_kqapro.py \
  --download \
  --data-dir data/kqa_pro/raw \
  --out data/kqa_pro/profile
```

The script does not report full KQA Pro accuracy. It first selects the exact
KoPL shape `Find -> Relate -> FilterConcept -> Relate -> FilterConcept -> What`,
then independently evaluates the path and concept constraints against
`kb.json`. A row is exported only if removing both concept filters preserves
the intermediate frontier and final entity IDs and the endpoint name equals the
published answer. This stronger check matters because an otherwise harmless
extra middle entity could consume a bounded MPC frontier slot.

The generated files are:

* `kqapro_compatibility_summary.json`: coverage, rejection reasons, KB scale,
  and limitations;
* `kqapro_twohop_syntactic_candidates.jsonl`: all candidate programs and their
  audit outcome;
* `kqapro_twohop_path_equivalent.jsonl`: only rows supported by the current
  two-hop path functionality;
* `PROVENANCE.json`: source URLs, byte counts, and SHA-256 hashes.

KQA Pro's public test split contains no programs or answers, so only train and
validation can be compatibility-profiled locally. Any owner allocation is
synthetic because the KB has no owner provenance.

Build the full frozen-graph capacity fixture and the separately labelled
21-query validation-closure correctness fixture:

```bash
python3 scripts/build_kqapro_relation_fixture.py \
  --kb data/kqa_pro/raw/kb.json \
  --compatible data/kqa_pro/profile/kqapro_twohop_path_equivalent.jsonl \
  --out data/kqa_pro/relation_fixture
```

`full/capacity_report.json` is the only artifact suitable for whole-graph
capacity discussion. `validation_closure` contains every path reachable from
the 21 public validation query anchors and relation pairs, without consulting
their answers; it is only a controlled correctness fixture.

Execute those 21 queries in the circuit's mandatory 10+10+1 batching and check
every reconstructed field against the independent cleartext oracle:

```bash
python3 scripts/run_kqapro_relation_mpc.py \
  --fixture data/kqa_pro/relation_fixture/validation_closure \
  --output results/kqapro_relation_mpc_temi_q21 \
  --mpspdz-home external/MP-SPDZ \
  --batch-size 10 --protocol temi --resume
```

This is a localhost semi-honest dishonest-majority Temi measurement. It does
not instantiate three separately administered hosts, and it must be labelled
“KQA Pro snapshot-equivalent two-hop validation subset,” not full KQA Pro.

## Three-party DORAM regression

`run_doram_regression.py` runs the packed MPC-oblivious linear scan over the
bundled three-owner diverse fixture, the prepared bounded-fanout MetaQA fixture,
or both. `--backend relation-paged` runs the experimental paged layout instead;
see below. Because the MPC program supports at most ten queries per batch, a
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

### Running the regression against the experimental paged layout

`--backend relation-paged` drives the same regression through the EXPERIMENTAL
relation-paged layout instead of the supported packed scan:

```bash
python3 scripts/run_doram_regression.py \
  --backend relation-paged --dataset diverse --query-count 10 \
  --mpspdz-home ../SimGRAG/external/MP-SPDZ \
  --output-dir /tmp/doram-paged-regression
```

Only `--dataset diverse` is supported: the MetaQA fixture ships pre-built packed
shards, and re-sharding it for the paged layout needs raw edges that are not in
the tree. The harness refuses the combination rather than producing something
misleading, and it refuses to resume a run recorded under the other backend.

The two backends share the entire client-facing contract — same query shards,
same output lines, same decoding — and differ only in server-side storage, the
generated circuit, and the cleartext oracle each is checked against. Because
each is validated against its **own** independently implemented oracle, a
comparison of the two runs' `decoded.json` is meaningful rather than circular.
The recorded `backend` and `backend_status` fields in `run_manifest.json` keep
the experimental runs distinguishable from supported ones.

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
