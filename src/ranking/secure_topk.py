"""Private ranking interface.

The current interface is intentionally backend-neutral. A garbled-circuit backend
should implement this protocol for production private top-k.
"""

from __future__ import annotations

from typing import Protocol, Sequence

from src.aggregation.score_aggregation import CandidateShare


class SecureTopK(Protocol):
    def rank(self, candidates: Sequence[CandidateShare], k: int) -> Sequence[str]:
        ...


class UnconfiguredSecureTopK:
    def rank(self, candidates: Sequence[CandidateShare], k: int) -> Sequence[str]:
        raise NotImplementedError(
            "Garbled-circuit top-k backend required before private ranking is available."
        )
