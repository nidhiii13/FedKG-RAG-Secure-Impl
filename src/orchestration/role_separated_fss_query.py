"""Local orchestrator for two role-separated FSS evaluator services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from src.crypto.dpf import DpfBackend
from src.runtime.fss_candidate_projection import CombinedCandidateSlots, ProjectedFssCoordinator
from src.runtime.fss_evaluator_service import (
    EvaluationDomain,
    FssEvaluatorRequest,
    FssEvaluatorService,
)
from src.runtime.fss_projection_builder import BuiltCandidateProjection, OpaqueIndexProjectionBuilder


@dataclass(frozen=True)
class RoleSeparatedFssQueryResult:
    request_id: str
    domain: EvaluationDomain
    candidate_values: dict[str, int]
    combined_slots: CombinedCandidateSlots
    candidate_projection: BuiltCandidateProjection


@dataclass(frozen=True)
class RoleSeparatedFssQueryOrchestrator:
    key_generator: DpfBackend
    evaluators: Sequence[FssEvaluatorService]
    projection_builder: OpaqueIndexProjectionBuilder

    def query(
        self,
        request_id: str,
        domain: EvaluationDomain,
        alpha: str,
        capacity: int,
    ) -> RoleSeparatedFssQueryResult:
        if len(self.evaluators) != 2:
            raise ValueError("role-separated native FSS requires exactly two evaluator services")
        by_index = {service.store.evaluator_index: service for service in self.evaluators}
        if set(by_index) != {0, 1}:
            raise ValueError("evaluator services must have indices 0 and 1")
        evaluator_ids = [by_index[index].store.evaluator_id for index in (0, 1)]
        generated = self.key_generator.gen(alpha, beta=1, party_ids=evaluator_ids)
        built = self.projection_builder.build(domain, capacity)
        responses = [
            service.evaluate_projected(
                FssEvaluatorRequest(request_id, domain, generated[service.store.evaluator_id]),
                built.projection,
            )
            for service in (by_index[0], by_index[1])
        ]
        combined = ProjectedFssCoordinator().combine(responses)
        return RoleSeparatedFssQueryResult(
            request_id=request_id,
            domain=domain,
            candidate_values=built.candidate_values(combined.nonzero_slots),
            combined_slots=combined,
            candidate_projection=built,
        )

