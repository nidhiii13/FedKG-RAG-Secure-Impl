"""Aggregate candidate score/support shares by opaque candidate ID."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping

from src.aggregation.secret_sharing import AdditiveSharing


@dataclass(frozen=True)
class CandidateShare:
    candidate_id: str
    score_shares: List[int]
    support_shares: List[int]


class ShareAggregator:
    def __init__(self, sharing: AdditiveSharing | None = None):
        self.sharing = sharing or AdditiveSharing()

    def aggregate(self, shares: Iterable[CandidateShare]) -> Dict[str, CandidateShare]:
        aggregated: Dict[str, CandidateShare] = {}
        for item in shares:
            current = aggregated.get(item.candidate_id)
            if current is None:
                aggregated[item.candidate_id] = CandidateShare(
                    item.candidate_id,
                    list(item.score_shares),
                    list(item.support_shares),
                )
                continue
            aggregated[item.candidate_id] = CandidateShare(
                item.candidate_id,
                self.sharing.add(current.score_shares, item.score_shares),
                self.sharing.add(current.support_shares, item.support_shares),
            )
        return aggregated
