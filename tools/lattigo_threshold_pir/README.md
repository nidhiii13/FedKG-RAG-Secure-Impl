# Lattigo Threshold PIR Adapter

This is the best-fit direction for:

```text
distributed PIR client
-> threshold output decryption
-> MPC/private traversal and ranking
```

The relevant implementation is Lattigo's multiparty `int_pir` example:

```text
external/lattigo/examples/multiparty/int_pir/main.go
```

It uses an N-party, t-out-of-N threshold BGV setup:

```text
1. N parties generate threshold secret-key shares.
2. Parties generate collective public/evaluation keys.
3. Data rows are encrypted under the collective public key.
4. A query is encoded as an encrypted selector vector.
5. A helper evaluates PIR over the encrypted database.
6. Any threshold t of parties participates in output decryption.
```

This avoids the SealPIR limitation where one PIR client owns the full secret key
and locally decrypts the selected bucket.

## Current Local Blocker

The current machine does not have Go installed:

```text
go: command not found
```

Install Go first, then run:

```bash
cd <repository>/external/lattigo
go run ./examples/multiparty/int_pir 3 2 1
```

The arguments are:

```text
3 = number of parties
2 = threshold required for output decryption
1 = Go routines
```

## FedKG Integration Plan

The FedKG-specific backend now adapts the Lattigo example as:

```text
encoded KG bucket records
-> integer vectors
-> threshold-encrypted PIR database
-> encrypted selector query
-> helper evaluates PIR
-> threshold parties decrypt selected encoded bucket
-> bounded encoded candidate paths
-> local Prio validation and GC-compatible top-k ranking
```

Build the FedKG-specific native threshold-PIR CLI:

```bash
cd <repository>/tools/lattigo_threshold_pir
/usr/local/go/bin/go build -o lattigo-fedkg-threshold-pir fedkg_lattigo_threshold_pir.go
```

Build a small real-data smoke index:

```bash
cd <repository>

FEDKG_SETUP_KEY=dev-secure-test-key python3 scripts/build_pir_bucket_index.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --output-dir /tmp/fedkg-lattigo-threshold-pir-kismet-angel-smoke-index \
  --semantic-bucket-mode alias \
  --relation starred_actors \
  --entity Kismet \
  --entity Angel \
  --max-edges-per-record 32 \
  --record-size 4096
```

For faster PIR evaluation, build a packed index. This packs several logical
bucket records into one encrypted PIR row, reducing the number of encrypted rows
the helper scans:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 scripts/build_pir_bucket_index.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --output-dir /tmp/fedkg-lattigo-packed-kismet-angel-smoke-index \
  --semantic-bucket-mode alias \
  --relation starred_actors \
  --entity Kismet \
  --entity Angel \
  --max-edges-per-record 32 \
  --records-per-pir-row 8 \
  --record-size 8192
```

For a larger generic benchmark, use compact IDs. This keeps record payloads
within Lattigo's 8192 slots while preserving one global PIR database, so the
query remains hidden among all PIR rows rather than only within a shard:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 scripts/build_pir_bucket_index.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --output-dir /tmp/fedkg-lattigo-packed-compact-metaqa-starred-index-r32-cap8 \
  --semantic-bucket-mode alias \
  --relation starred_actors \
  --max-edges-per-record 8 \
  --records-per-pir-row 32 \
  --record-size 8192 \
  --compact-ids
```

This produced:

```json
{
  "database_size": 5813,
  "max_payload_size": 3509,
  "record_size": 8192
}
```

Run the end-to-end validation query:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key \
FEDKG_PRIO_HANDLE_KEY=dev-prio-handle-key-123456 \
python3 scripts/run_lattigo_threshold_pir_bucket_query.py \
  --index-dir /tmp/fedkg-lattigo-threshold-pir-kismet-angel-smoke-index \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|Angel' \
  --output results/lattigo_threshold_pir_kismet_angel.json \
  --semantic-bucket-mode alias \
  --max-query-buckets 1 \
  --topk 3 \
  --parties 3 \
  --threshold 2 \
  --go-routines 1
```

Current smoke timing on a 96-record, 4096-byte index:

```json
{
  "threshold_pir_retrieval": 10.15,
  "bounded_join_prio_and_gc_validation": 0.05,
  "total": 10.20
}
```

Current packed smoke timing on the same data, with 8 logical records per PIR
row:

```json
{
  "database_size": 12,
  "persistent_setup_seconds": 0.41,
  "retrieval_time": 1.31,
  "hit_rate": 1.0
}
```

Current generic compact timing for a real one-hop query over the starred_actors
index:

```json
{
  "query": "Joe Thomas appears in which movies",
  "correct": true,
  "candidates": 2,
  "persistent_setup_seconds": 25.49,
  "retrieval_time": 42.94
}
```

The FedKG CLI now supports persistent per-run setup for multiple bucket
lookups:

```bash
tools/lattigo_threshold_pir/lattigo-fedkg-threshold-pir \
  --records-jsonl /tmp/fedkg-lattigo-threshold-pir-kismet-angel-smoke-index/records.jsonl \
  --indices 0,1 \
  --record-size 4096 \
  --parties 3 \
  --threshold 2 \
  --go-routines 1
```

`--indices` retrieves several bucket records after one threshold key setup and
one encrypted database construction. The Python runner uses this mode by
default, so a two-hop query does not repeat setup/encryption separately for the
left and right bucket.

For multiple queries, use the persistent batch runner. It starts the native
Lattigo process once, keeps the threshold setup and encrypted database alive,
and sends per-query bucket index requests over stdin:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key \
FEDKG_PRIO_HANDLE_KEY=dev-prio-handle-key-123456 \
python3 scripts/run_lattigo_threshold_pir_bucket_batch.py \
  --index-dir /tmp/fedkg-lattigo-packed-kismet-angel-smoke-index \
  --queries-jsonl examples/private_frontier_from_federated_q2_500.jsonl \
  --output results/lattigo_threshold_pir_persistent_batch.jsonl \
  --max-queries 10 \
  --semantic-bucket-mode alias \
  --max-query-buckets 1 \
  --topk 3 \
  --parties 3 \
  --threshold 2 \
  --go-routines 1
```

The setup line is printed once:

```text
Lattigo threshold-PIR service ready: setup=0.75s database=96 record_size=4096
```

Then each query prints the normal progress line:

```text
[1/10] OK index=0 hit candidates=1 retrieval=9.67s query=...
```

## Security Boundary

This is stronger than the current SealPIR roundtrip validation because no single
client needs to hold the PIR decryption key. The current FedKG runner still uses
local validation after threshold decryption: bounded candidates are joined in
Python, then Prio and GC-compatible ranking are validated locally. For a fully
clean deployment, the threshold-decrypted bucket should be handed into the MPC
layer as shares rather than opened to a local coordinator.
