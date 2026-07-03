# Crypto

Cryptographic wrappers and backend interfaces.

Implemented now:

- `hmac_ids.py`: HMAC-SHA256 deterministic identifiers.
- `dpf.py`: strict FSS/DPF backend contract that fails closed when unconfigured.
- `fss_cli_backend.py`: JSON stdin/stdout adapter for an external real FSS/DPF CLI.

Native backend:

- `third_party/myl7-fss/`: vendored upstream FSS/DPF implementation.
- `tools/fss_cli/`: real two-party DPF CLI wrapper around `myl7/fss`.

Important: there is no toy DPF backend in production code. A single DPF eval
result is a share, so private lookup requires cross-party reconstruction or
secure aggregation before deciding whether a candidate matched.

## Native `myl7/fss` CLI status

`tools/fss_cli` now builds a real two-party DPF wrapper around `myl7/fss`. The current domain is a collision-checked-prototype 64-bit projection of HMAC-SHA256 IDs (`hmac_sha256_prefix64`) with `uint64` additive output shares. A single `eval` result is a secret share, not a local match bit; callers must reconstruct/aggregate shares across both parties modulo `2^64`.


Private lookup now evaluates DPF shares over a shared opaque evaluation universe. This ensures all parties evaluate the same HMAC points before reconstruction; the aggregator then emits candidates only for parties that own the reconstructed point locally.
