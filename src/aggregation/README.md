# Aggregation

Secure score and support aggregation.

Implemented now:

- `MatchScoreShareBuilder` converts each retrieved structural match into an
  opaque candidate ID plus additive fixed-point score/support shares.
- `ShareAggregator` merges shares for the same candidate ID.
- `reveal_candidate_score` exists for tests and prototype ranking only.

Planned next:

- Prio/VDAF-style validation before accepting score/support shares.
- Stronger policy checks around malformed, missing, or adversarial shares.
