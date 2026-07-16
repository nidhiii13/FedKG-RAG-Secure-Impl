"""Build query-independent candidate projections from opaque evaluator indexes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from src.aggregation.prio3_candidates import SessionCandidateHandleProvider
from src.party.opaque_index_snapshot import ReplicatedEvaluatorIndex
from src.runtime.fss_candidate_projection import CandidateProjection
from src.runtime.fss_evaluator_service import EvaluationDomain


@dataclass(frozen=True)
class BuiltCandidateProjection:
    projection: CandidateProjection
    handle_to_candidate_id: Mapping[str, str]

    def candidate_values(self, slot_values: Mapping[str, int]) -> dict[str, int]:
        return {
            self.handle_to_candidate_id[handle]: value
            for handle, value in slot_values.items()
            if handle in self.handle_to_candidate_id and value != 0
        }


@dataclass(frozen=True)
class OpaqueIndexProjectionBuilder:
    index: ReplicatedEvaluatorIndex
    handles: SessionCandidateHandleProvider

    def build(self, domain: EvaluationDomain, capacity: int) -> BuiltCandidateProjection:
        point_candidates = self._point_candidates(domain)
        candidate_ids = sorted(
            {candidate for candidates in point_candidates.values() for candidate in candidates}
        )
        if capacity < len(candidate_ids):
            raise ValueError(
                f"projection capacity {capacity} is smaller than candidate universe {len(candidate_ids)}"
            )

        candidate_handles = {
            candidate_id: self.handles.candidate_handle(f"{domain}:{candidate_id}")
            for candidate_id in candidate_ids
        }
        handle_to_candidate = {handle: candidate for candidate, handle in candidate_handles.items()}
        if len(handle_to_candidate) != len(candidate_handles):
            raise ValueError("candidate handle collision detected")
        slots = list(handle_to_candidate)
        slots.extend(
            self.handles.padding_handle(index)
            for index in range(capacity - len(slots))
        )
        if len(slots) != len(set(slots)):
            raise ValueError("candidate or padding handle collision detected")
        slots.sort()

        point_weights = {
            point: {
                candidate_handles[candidate_id]: 1
                for candidate_id in candidates
            }
            for point, candidates in point_candidates.items()
        }
        projection = CandidateProjection(tuple(slots), point_weights)
        projection.validate(self._points_for(domain))
        return BuiltCandidateProjection(projection, handle_to_candidate)

    def _points_for(self, domain: EvaluationDomain) -> list[str]:
        if domain == "entity":
            return self.index.entity_points
        if domain == "relation":
            return self.index.relation_points
        if domain == "type":
            return sorted(
                {type_id for snapshot in self.index.snapshots for type_id in snapshot.type_index}
            )
        if domain == "frontier":
            return self.index.frontier_points
        if domain == "relation_bucket":
            return self.index.relation_bucket_points
        if domain == "entity_bucket":
            return self.index.entity_bucket_points
        raise ValueError(f"unsupported projection domain: {domain}")

    def _point_candidates(self, domain: EvaluationDomain) -> dict[str, list[str]]:
        if domain == "entity":
            return {point: [point] for point in self.index.entity_points}
        if domain == "relation":
            return {point: [point] for point in self.index.relation_points}
        if domain == "type":
            result: dict[str, set[str]] = {}
            for snapshot in self.index.snapshots:
                for type_id, members in snapshot.type_index.items():
                    result.setdefault(type_id, set()).update(members)
            return {point: sorted(candidates) for point, candidates in sorted(result.items())}
        if domain == "frontier":
            result = {}
            for snapshot in self.index.snapshots:
                for token, members in snapshot.frontier_index.items():
                    result.setdefault(token, set()).update(members)
            return {point: sorted(candidates) for point, candidates in sorted(result.items())}
        if domain == "relation_bucket":
            result = {}
            for snapshot in self.index.snapshots:
                for token, relations in (snapshot.relation_bucket_index or {}).items():
                    result.setdefault(token, set()).update(relations)
            return {point: sorted(candidates) for point, candidates in sorted(result.items())}
        if domain == "entity_bucket":
            result = {}
            for snapshot in self.index.snapshots:
                for token, entities in (snapshot.entity_bucket_index or {}).items():
                    result.setdefault(token, set()).update(entities)
            return {point: sorted(candidates) for point, candidates in sorted(result.items())}
        raise ValueError(f"unsupported projection domain: {domain}")
