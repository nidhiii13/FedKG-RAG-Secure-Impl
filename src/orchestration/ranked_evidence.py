"""Score aggregation, top-k selection, and controlled evidence reveal."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from src.aggregation.score_aggregation import (
    CandidateShare,
    MatchScoreShareBuilder,
    ShareAggregator,
    candidate_id_for_match,
)
from src.common.types import MatchResult
from src.ranking.secure_topk import SecureTopK


@dataclass(frozen=True)
class RankedEvidenceResult:
    selected_ids: list[str]
    evidence: list[MatchResult]
    aggregated_shares: dict[str, CandidateShare]


@dataclass(frozen=True)
class RankedEvidencePipeline:
    ranker: SecureTopK
    share_builder: MatchScoreShareBuilder = field(default_factory=MatchScoreShareBuilder)
    aggregator: ShareAggregator = field(default_factory=ShareAggregator)

    def run(self, matches: Sequence[MatchResult], k: int) -> RankedEvidenceResult:
        share_rows = self.share_builder.share_matches(matches)
        aggregated = self.aggregator.aggregate(share_rows)
        selected_ids = list(self.ranker.rank(list(aggregated.values()), k))
        by_id = {candidate_id_for_match(match): match for match in matches}
        evidence = [by_id[candidate_id] for candidate_id in selected_ids if candidate_id in by_id]
        return RankedEvidenceResult(
            selected_ids=selected_ids,
            evidence=evidence,
            aggregated_shares=aggregated,
        )
