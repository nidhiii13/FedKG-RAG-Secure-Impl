"""Opt-in Prio3 candidate aggregation and local ranking pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from src.aggregation.prio3_candidates import (
    CandidateAggregate,
    CandidateContribution,
    PrioCandidateAggregationResult,
    PrioCandidateAggregator,
)


@dataclass(frozen=True)
class PrioPipelineSecurityMetadata:
    lookup_backend: str = "two-party-dpf-fss"
    lookup_evaluator_count: int = 2
    aggregation_backend: str = "prio3"
    local_aggregate_reconstruction: bool = True
    local_ranking: bool = True


@dataclass(frozen=True)
class PrioCandidateRankingResult:
    selected_candidate_ids: list[str]
    selected_handles: list[str]
    aggregates: list[CandidateAggregate]
    aggregation: PrioCandidateAggregationResult
    security: PrioPipelineSecurityMetadata


class LocalPrioCandidatePipeline:
    """Aggregate contributions with Prio3 without replacing the FSS path.

    Aggregate reconstruction and ranking are local in this validation stage. A
    production pipeline must replace both with a share-preserving Prio-to-MPC/GC
    bridge.
    """

    def __init__(self, aggregator: PrioCandidateAggregator) -> None:
        self.aggregator = aggregator

    def run(
        self,
        party_ids: Sequence[str],
        contributions: Sequence[CandidateContribution],
        k: int,
        lookup_evaluator_count: int = 2,
    ) -> PrioCandidateRankingResult:
        if lookup_evaluator_count != 2:
            raise ValueError(
                "the current native DPF/FSS backend requires exactly two lookup evaluators"
            )
        if k < 1:
            raise ValueError("k must be positive")
        aggregation = self.aggregator.aggregate(party_ids, contributions)
        eligible = [candidate for candidate in aggregation.candidates if candidate.presence_count > 0]
        ranked = sorted(
            eligible,
            key=lambda candidate: (
                candidate.average_score,
                -candidate.support_sum,
                candidate.handle,
            ),
        )
        selected = ranked[:k]
        return PrioCandidateRankingResult(
            selected_candidate_ids=[candidate.candidate_id for candidate in selected],
            selected_handles=[candidate.handle for candidate in selected],
            aggregates=ranked,
            aggregation=aggregation,
            security=PrioPipelineSecurityMetadata(
                lookup_evaluator_count=lookup_evaluator_count,
            ),
        )

