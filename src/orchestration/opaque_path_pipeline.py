"""Aggregate and rank opaque party-local path shares."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from src.aggregation.score_aggregation import CandidateShare, ShareAggregator
from src.common.types import MatchResult
from src.party.private_structural_matcher import OpaquePathShare, PartyLocalStructuralMatcher
from src.ranking.secure_topk import SecureTopK


@dataclass(frozen=True)
class OpaquePathRankingResult:
    selected_ids: list[str]
    evidence: list[MatchResult]
    aggregated_shares: dict[str, CandidateShare]


@dataclass(frozen=True)
class OpaquePathAggregator:
    ranker: SecureTopK
    aggregator: ShareAggregator = field(default_factory=ShareAggregator)

    def run(
        self,
        path_share_batches: Sequence[Iterable[OpaquePathShare]],
        revealers: Sequence[PartyLocalStructuralMatcher],
        k: int,
    ) -> OpaquePathRankingResult:
        candidate_rows = [share.as_candidate_share() for batch in path_share_batches for share in batch]
        aggregated = self.aggregator.aggregate(candidate_rows)
        selected_ids = list(self.ranker.rank(list(aggregated.values()), k))

        by_id: dict[str, MatchResult] = {}
        for revealer in revealers:
            by_id.update(revealer.reveal(selected_ids))
        evidence = [by_id[candidate_id] for candidate_id in selected_ids if candidate_id in by_id]
        return OpaquePathRankingResult(
            selected_ids=selected_ids,
            evidence=evidence,
            aggregated_shares=aggregated,
        )
