# FSS CLI Protocol Contract

The Python adapter is implemented in `src/crypto/fss_cli_backend.py`.
This document defines the backend process contract.

## Domain Encoding

The HMAC layer produces 256-bit hex identifiers. The concrete DPF backend must
choose and document a finite input domain. Current implementation:

- uses `myl7/fss` DPF with a 64-bit input domain;
- projects a 256-bit HMAC hex identifier to the first 64 bits / first 16 hex characters;
- uses the `uint64` additive output group, so two party eval outputs reconstruct modulo `2^64`.

This is suitable for the first engineering prototype. The production direction should avoid silent truncation; the index builder must detect and reject projection collisions before private retrieval is used on a dataset.

## Operation: gen

Request:

```json
{
  "op": "gen",
  "alpha": "hex-domain-point",
  "beta": 1,
  "share_count": 2
}
```

Response:

```json
{
  "shares": [
    {
      "party": 0,
      "seed": "...",
      "correction_words": "...",
      "domain_bits": 64,
      "group": "uint64",
      "projection": "hmac_sha256_prefix64"
    },
    {
      "party": 1,
      "seed": "...",
      "correction_words": "...",
      "domain_bits": 64,
      "group": "uint64",
      "projection": "hmac_sha256_prefix64"
    }
  ]
}
```

The native crypto helper does not receive real party identifiers. It returns
ordered shares, and the trusted Python orchestration layer maps `shares[0]`,
`shares[1]`, ... to session-local parties.

## Operation: eval

Request:

```json
{
  "op": "eval",
  "share": {
    "party": 0,
    "seed": "...",
    "correction_words": "...",
    "domain_bits": 64,
    "group": "uint64",
    "projection": "hmac_sha256_prefix64"
  },
  "point": "hex-domain-point"
}
```

Response:

```json
{"value": 0}
```

`value` is this party's uint64 output share. Combining both party output shares modulo `2^64` must reconstruct `beta` at `x = alpha` and zero otherwise. A single party's value is not a boolean match.


## Operation: eval_many

Request:

```json
{
  "op": "eval_many",
  "share": {
    "party": 0,
    "seed": "...",
    "correction_words": "...",
    "domain_bits": 64,
    "group": "uint64",
    "projection": "hmac_sha256_prefix64"
  },
  "points": ["hex-domain-point-1", "hex-domain-point-2"]
}
```

Response:

```json
{"values": [0, 123]}
```

`values[i]` is the uint64 output share for `points[i]`. The Python adapter chunks large requests; the current conservative default is 256 HMAC IDs per native CLI call because the temporary regex-based C++ JSON parser is unstable on larger real-HMAC payloads.
