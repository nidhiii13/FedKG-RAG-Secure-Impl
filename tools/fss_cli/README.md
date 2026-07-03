# FSS/DPF CLI Backend

This directory is for the real FSS/DPF command-line backend used by
`src/crypto/fss_cli_backend.py`.

The Python side expects a stateless JSON protocol over stdin/stdout.

## Generate

Input:

```json
{"op":"gen","alpha":"<hex-or-domain-id>","beta":1,"party_ids":["party_0","party_1"]}
```

Output:

```json
{"shares":{"party_0":{...},"party_1":{...}}}
```

Each party share must contain everything needed for that party to evaluate the
DPF share independently, typically:

- party index
- party seed
- correction words
- domain parameters
- output group metadata

## Evaluate

Input:

```json
{"op":"eval","share":{...},"point":"<hex-or-domain-id>"}
```

Output:

```json
{"value":0}
```

The current implementation intentionally does not include a fake backend. Build
this wrapper against `third_party/myl7-fss` before claiming private lookup.

## Build Prerequisites

The cloned `myl7/fss` package currently requires:

- CMake >= 3.22
- CUDA toolkit / `nvcc` >= 12.0
- OpenSSL development headers for the CPU AES-128 MMO PRG path

This environment was checked and currently lacks `cmake`, `nvcc`, and OpenSSL
pkg-config metadata, so this backend cannot be compiled here yet.
