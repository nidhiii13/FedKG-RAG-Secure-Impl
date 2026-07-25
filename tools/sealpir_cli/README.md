# SealPIR CLI Adapter Contract

This directory contains the native SealPIR integration boundary.

`fedkg-sealpir-roundtrip` is currently implemented as a validation wrapper over
Microsoft SealPIR. It performs setup, query, answer, and decode in one native
process for a selected encoded bucket record. This gives a real lattice-PIR
execution path for correctness/timing, but it is not yet the network-separated
`setup/query/answer/decode` service described below.

## Build

SealPIR requires Microsoft SEAL 4.0.0. The local build used:

```bash
git clone --depth 1 --branch 4.0.0 https://github.com/microsoft/SEAL.git external/SEAL-4.0.0
cmake -S external/SEAL-4.0.0 -B build/seal-4.0 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=$PWD/external/seal-4.0-install \
  -DSEAL_BUILD_DEPS=ON \
  -DSEAL_BUILD_EXAMPLES=OFF \
  -DSEAL_BUILD_TESTS=OFF
cmake --build build/seal-4.0 -j2
cmake --install build/seal-4.0

git clone --depth 1 https://github.com/microsoft/SealPIR.git external/SealPIR
cmake -S external/SealPIR -B build/sealpir \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=$PWD/external/seal-4.0-install
cmake --build build/sealpir -j2

cmake -S tools/sealpir_cli -B build/fedkg-sealpir-cli \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=$PWD/external/seal-4.0-install
cmake --build build/fedkg-sealpir-cli -j2
```

## Current Roundtrip Runner

Build a small real-data smoke index:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 scripts/build_pir_bucket_index.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --output-dir /tmp/fedkg-sealpir-kismet-angel-smoke-index \
  --semantic-bucket-mode alias \
  --relation starred_actors \
  --entity Kismet \
  --entity Angel \
  --max-edges-per-record 32 \
  --record-size 4096
```

Run the native SealPIR roundtrip:

```bash
FEDKG_SETUP_KEY=dev-secure-test-key python3 scripts/run_sealpir_roundtrip_bucket_query.py \
  --index-dir /tmp/fedkg-sealpir-kismet-angel-smoke-index \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|Angel' \
  --output results/sealpir_roundtrip_kismet_angel.json \
  --semantic-bucket-mode alias \
  --max-query-buckets 1 \
  --topk 3
```

The smoke run uses query-dependent filtering only to keep the validation index
small. It should not be used as a production privacy benchmark.

## Operations

### setup

Input:

```json
{
  "op": "setup",
  "config": {
    "database_size": 1000,
    "record_size": 4096,
    "label": "fedkg-sealpir:example"
  },
  "records_b64": ["..."]
}
```

Output:

```json
{
  "server_state_b64": "..."
}
```

### query

Input:

```json
{
  "op": "query",
  "index": 42,
  "config": {
    "database_size": 1000,
    "record_size": 4096,
    "label": "fedkg-sealpir:example"
  }
}
```

Output:

```json
{
  "client_state_b64": "...",
  "request_b64": "..."
}
```

### answer

Input:

```json
{
  "op": "answer",
  "server_state_b64": "...",
  "request_b64": "..."
}
```

Output:

```json
{
  "response_b64": "..."
}
```

### decode

Input:

```json
{
  "op": "decode",
  "client_state_b64": "...",
  "response_b64": "..."
}
```

Output:

```json
{
  "record_b64": "..."
}
```

## Retrieval Flow

```text
encoded bucket index
-> native SealPIR setup/query/answer/decode
-> bounded encoded candidate edges
-> Prio/MPC score aggregation
-> GC/MPC top-k ranking
-> controlled evidence reveal
```

Use `scripts/run_sealpir_bucket_query.py` after building an encoded bucket index
with `scripts/build_pir_bucket_index.py`.
