"""Private ranking interface.

Production top-k should be implemented by a distributed garbled-circuit backend.
The local prototype below reveals aggregate scores and is only for basic testing.
`src.ranking.garbled_circuit.LocalGarbledCircuitTopK` adds a local garbled-circuit
comparison backend without networked OT.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, Sequence

from src.aggregation.score_aggregation import CandidateShare, reveal_candidate_score
from src.aggregation.secret_sharing import AdditiveSharing, FixedPointEncoder


class SecureTopK(Protocol):
    def rank(self, candidates: Sequence[CandidateShare], k: int) -> Sequence[str]:
        ...


class UnconfiguredSecureTopK:
    def rank(self, candidates: Sequence[CandidateShare], k: int) -> Sequence[str]:
        raise NotImplementedError(
            "Garbled-circuit top-k backend required before private ranking is available."
        )


@dataclass(frozen=True)
class PrototypeRevealingTopK:
    """Local top-k prototype for tests and demos.

    This is not private: it reconstructs scores in process. It preserves the
    backend contract so a garbled-circuit implementation can replace it later.
    Lower score is better; higher support breaks ties.
    """

    encoder: FixedPointEncoder = field(default_factory=FixedPointEncoder)
    sharing: AdditiveSharing = field(default_factory=AdditiveSharing)

    def rank(self, candidates: Sequence[CandidateShare], k: int) -> Sequence[str]:
        revealed = [reveal_candidate_score(candidate, self.encoder, self.sharing) for candidate in candidates]
        revealed.sort(key=lambda item: (item.score, -item.support, item.candidate_id))
        return [item.candidate_id for item in revealed[:k]]
