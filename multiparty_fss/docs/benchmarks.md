# Benchmarks — BGI15 p-party DPF prototype

**Prototype measurements, not production performance claims.** Pure-Python +
NumPy reference implementation, single process, single CPU core, no I/O or
network. Numbers will vary with hardware; re-run with the command below.

## Methodology

- Harness: [`benchmarks/bench_multiparty_fss.py`](../benchmarks/bench_multiparty_fss.py).
- Command used for the tables below (2026-08-27, Linux 6.8, repo `.venv`,
  Python 3.10.12, NumPy 2.2.6):

  ```bash
  .venv/bin/python multiparty_fss/benchmarks/bench_multiparty_fss.py \
      --universe 4096 --universe 65536 --repeat 5
  ```

- Each timing is the **median of 5 runs** (scalar eval: ≥5; batch: ≥2) via
  `time.perf_counter`.
- `keygen` = one full `Gen^{p0}` (N key shares). "Key raw" = `|sigma| +
  |correction words|` per evaluator; "key JSON" = the serialized wire object
  (base64 + metadata) — this is also the client→evaluator communication per
  query. "Universe eval" = all U points (`evaluate_universe`). "Combine" =
  XOR-combining N full dense share vectors as Python ints
  (`combine_vectors`; the projected path combines `capacity`-length vectors
  instead, which is far smaller).
- `t = ⌊(N−1)/2⌋` throughout. β = 1; α random per run; correctness of the
  combined sweep is asserted inside the harness.
- The **N=2 row is comparison only**: it drives the existing native
  two-party CLI (`build/fss_cli/fedkg-fss-cli`, myl7/fss tree DPF) through
  `FssCliBackend`. It is a different construction over a different domain
  (2^64 vs rank domain) in a different output group (Z/2^64), and its
  timings are dominated by one **subprocess spawn per CLI call** (batches of
  256 points per call). It shows what the deployed legacy path actually
  costs end-to-end today, not what the tree DPF costs as a library.

## Results — U = 4,096 points (n = 12)

| N | t | μ×ν grid | keygen | key raw / eval. | key JSON / eval. | total key raw | scalar eval | universe eval | combine (dense) |
|---|---|---|---|---|---|---|---|---|---|
| 3 | 1 | 128×32 | 0.7 ms | 6.0 KiB | 8.4 KiB | 18 KiB | 0.04 ms | 1.1 ms | 3.9 ms |
| 4 | 1 | 182×23 | 1.1 ms | 14.2 KiB | 19.4 KiB | 57 KiB | 0.07 ms | 1.5 ms | 4.5 ms |
| 5 | 2 | 256×16 | 1.6 ms | 36.0 KiB | 48.4 KiB | 180 KiB | 0.15 ms | 2.4 ms | 6.0 ms |
| 7 | 3 | 512×8 | 4.8 ms | 264 KiB | 352 KiB | 1.8 MiB | 0.75 ms | 6.2 ms | 8.2 ms |
| 8 | 3 | 725×6 | 10.1 ms | 737 KiB | 983 KiB | 5.8 MiB | 1.82 ms | 11.0 ms | 8.9 ms |
| 2 (legacy CLI) | n/a | tree, 2^64 | 17.2 ms | — | 4.5 KiB | 9 KiB | 41.2 ms | 0.65 s | — |

## Results — U = 65,536 points (n = 16)

| N | t | μ×ν grid | keygen | key raw / eval. | key JSON / eval. | total key raw | scalar eval | universe eval | combine (dense) |
|---|---|---|---|---|---|---|---|---|---|
| 3 | 1 | 512×128 | 5.5 ms | 24.0 KiB | 32.4 KiB | 72 KiB | 0.06 ms | 7.8 ms | 56 ms |
| 4 | 1 | 725×91 | 3.5 ms | 56.7 KiB | 76.0 KiB | 227 KiB | 0.12 ms | 11.6 ms | 76 ms |
| 5 | 2 | 1024×64 | 5.4 ms | 144 KiB | 192 KiB | 720 KiB | 0.37 ms | 19.4 ms | 92 ms |
| 7 | 3 | 2048×32 | 16.2 ms | 1.03 MiB | 1.38 MiB | 7.2 MiB | 1.94 ms | 63.1 ms | 127 ms |
| 8 | 3 | 2897×23 | 35.9 ms | 2.87 MiB | 3.83 MiB | 23 MiB | 5.30 ms | 118.8 ms | 149 ms |
| 2 (legacy CLI) | n/a | tree, 2^64 | 16.0 ms | — | 4.5 KiB | 9 KiB | 40.1 ms | 10.35 s | — |

Communication per query (dense mode, U = 65,536): client→evaluator = one key
JSON (table above) + request envelope; evaluator→combiner ≈ 0.9 MiB of JSON
share values per evaluator (dominated by 64-bit ints in decimal). The
**projected** mode used by the retrieval flow returns `capacity` slot shares
instead (e.g. 16 values ≈ a few hundred bytes) — dense mode is the
worst case, kept here because it bounds everything.

## Scaling reading

- Key size grows as `2^{(N−1)/2}·√U·(λ+m)` exactly as the paper's bound
  (each +2 parties ≈ ×2 key size; ×16 universe ≈ ×4 key size) — measured
  values track the formula.
- Evaluation cost is one PRG expansion per held seed per touched row;
  full-universe sweeps amortize rows, so universe eval grows ≈ linearly in
  `U·2^{N−1}` bytes hashed. SHAKE-256 is the bottleneck; a fixed-key-AES PRG
  or a C/CUDA port would move these numbers substantially (not done —
  reviewability over speed for the prototype).
- `combine (dense)` is pure-Python int XOR over U values per party and is a
  deliberate non-optimized reference; the projected path combines
  `capacity` values and is microseconds.
- Memory: peak resident sets are dominated by the key share and one
  `μ`-word row accumulator per evaluation (< a few MiB at N=8, U=65,536,
  beyond the ~23 MiB total key material at the client during Gen).
- The legacy N=2 CLI's universe eval (0.65 s / 10.35 s) reflects its
  256-point-per-subprocess protocol, consistent with the repo's own
  documented ≈36 s for an 80,311-point universe
  (`docs/secure_architecture.md`). Per-point tree-DPF cost inside the CLI is
  microseconds; the subprocess protocol dominates. This comparison is about
  deployed paths, not constructions.
