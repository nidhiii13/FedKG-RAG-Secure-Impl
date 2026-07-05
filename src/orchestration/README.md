# Orchestration

End-to-end protocol runner.

Implemented now:

- `PrivateExactRetriever.retrieve(...)` runs private exact lookup over encoded
  party indexes and preserves structural DFS matching.
- `PrivateExactRetriever.retrieve_ranked(...)` extends that path with
  score/support sharing, aggregation, top-k backend invocation, and controlled
  reveal of selected evidence.
- `RankedEvidencePipeline` keeps the ranking boundary separate from retrieval so
  the prototype ranker can be replaced by a garbled-circuit backend later.

Still planned:

- Semantic bucket retrieval route.
- Garbled-circuit top-k implementation.
- Prio/VDAF-style validation around aggregation.
