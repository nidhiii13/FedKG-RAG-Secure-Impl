# Prio3 CLI

This isolated Rust binary wraps `divviup/libprio-rs` without changing the
existing `tools/fss_cli` implementation.

The first operation, `sum_vec`, executes a complete local Prio3 protocol for
bounded integer vectors with a configurable number of aggregators. It is an
integration and benchmarking backend: it reconstructs the aggregate in this
single process and is not a substitute for network-separated Prio aggregators.

The crate pins `prio` 0.16.8 so it builds with the repository's current Rust
toolchain. This release implements an older VDAF draft whose API does not take
an application context during sharding/preparation. The JSON `context` field is
therefore metadata in this first backend. A future protocol upgrade must add a
versioned migration and test context/domain-separation behavior explicitly.

Build:

```bash
cargo build --manifest-path tools/prio3_cli/Cargo.toml --release
```

Example:

```bash
printf '%s' '{"op":"sum_vec","aggregator_count":3,"bits":8,"context":"test","measurements":[[1,2],[3,4],[5,6]]}' \
  | tools/prio3_cli/target/release/fedkg-prio3-cli
```

Expected aggregate: `[9, 12]`.
