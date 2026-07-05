# Ranking

Top-k ranking abstraction.

Implemented now:

- `SecureTopK` protocol defines the ranking boundary used by orchestration.
- `PrototypeRevealingTopK` reconstructs aggregate scores locally for basic tests.
  It is not a private ranking protocol.
- `LocalGarbledCircuitTopK` evaluates ranking comparisons with garbled Boolean
  circuits over n additive score/support shares. It validates the n-party ranking
  boundary, but it is not yet a distributed BMR/nPC deployment because share
  conversion, network-separated parties, and input-label delivery are still
  local.
- `UnconfiguredSecureTopK` fails closed when no ranking backend is configured.

Planned next:

- Replace local reconstruction with distributed n-party share-to-circuit input conversion.
- Implement BMR-style n-party garbled-circuit evaluation or an equivalent nPC comparison protocol.
- Keep only selected candidate IDs/evidence revealed after GC top-k.
