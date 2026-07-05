"""Aggregate candidate score/support shares by opaque candidate ID."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Sequence

from src.aggregation.secret_sharing import AdditiveSharing, FixedPointEncoder
from src.common.types import MatchResult


@dataclass(frozen=True)
class CandidateShare:
    candidate_id: str
    score_shares: List[int]
    support_shares: List[int]


@dataclass(frozen=True)
class RevealedCandidateScore:
    candidate_id: str
    score: float
    support: int


def candidate_id_for_edges(edges: Sequence[tuple[str, str, str]]) -> str:
    payload = json.dumps(list(edges), separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def candidate_id_for_match(match: MatchResult) -> str:
    return candidate_id_for_edges(match.edges)


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


@dataclass(frozen=True)
class MatchScoreShareBuilder:
    share_count: int = 2
    encoder: FixedPointEncoder = field(default_factory=FixedPointEncoder)
    sharing: AdditiveSharing = field(default_factory=AdditiveSharing)

    def share_match(self, match: MatchResult) -> CandidateShare:
        score_value = self.encoder.encode(match.score)
        support_value = len(match.edges) % self.sharing.field
        return CandidateShare(
            candidate_id=candidate_id_for_match(match),
            score_shares=self.sharing.share(score_value, self.share_count),
            support_shares=self.sharing.share(support_value, self.share_count),
        )

    def share_matches(self, matches: Iterable[MatchResult]) -> list[CandidateShare]:
        return [self.share_match(match) for match in matches]


def reveal_candidate_score(
    candidate: CandidateShare,
    encoder: FixedPointEncoder | None = None,
    sharing: AdditiveSharing | None = None,
) -> RevealedCandidateScore:
    encoder = encoder or FixedPointEncoder()
    sharing = sharing or AdditiveSharing()
    return RevealedCandidateScore(
        candidate_id=candidate.candidate_id,
        score=encoder.decode(sharing.combine(candidate.score_shares)),
        support=sharing.combine(candidate.support_shares),
    )


def reveal_candidate_scores(
    candidates: Iterable[CandidateShare],
    encoder: FixedPointEncoder | None = None,
    sharing: AdditiveSharing | None = None,
) -> Dict[str, RevealedCandidateScore]:
    return {candidate.candidate_id: reveal_candidate_score(candidate, encoder, sharing) for candidate in candidates}
