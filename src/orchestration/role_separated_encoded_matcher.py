"""Encoded graph traversal fed by role-separated exact and semantic FSS lookup."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping, Sequence

from src.aggregation.prio3_candidates import CandidateContribution
from src.common.normalization import extract_unknown_type, is_unknown, normalize_text
from src.common.types import QueryEdge
from src.crypto.hmac_ids import HmacIdProvider
from src.gateway.query_planner import PlannedQueryEdge, plan_query_path
from src.orchestration.role_separated_fss_query import RoleSeparatedFssQueryOrchestrator
from src.orchestration.role_separated_semantic_routing import RoleSeparatedSemanticRouter
from src.party.opaque_index_snapshot import ReplicatedEvaluatorIndex


@dataclass(frozen=True)
class EncodedPathCandidate:
    candidate_id: str
    edges: tuple[tuple[str, str, str], ...]
    score: float
    support_by_partition: Mapping[str, int]


@dataclass(frozen=True)
class EncodedGraphMatchResult:
    candidates: list[EncodedPathCandidate]
    party_ids: list[str]
    contributions: list[CandidateContribution]


@dataclass
class _PathState:
    current_id: str
    edges: tuple[tuple[str, str, str], ...]
    score: float
    support_by_partition: dict[str, int]


@dataclass
class RoleSeparatedEncodedGraphMatcher:
    ids: HmacIdProvider
    lookup: RoleSeparatedFssQueryOrchestrator
    index: ReplicatedEvaluatorIndex
    semantic_router: RoleSeparatedSemanticRouter | None = None
    relation_capacity: int = 128
    entity_capacity: int = 65536

    def match(self, query_graph: Sequence[QueryEdge]) -> EncodedGraphMatchResult:
        planned = plan_query_path(query_graph)
        if not planned:
            return EncodedGraphMatchResult([], self._party_ids(), [])

        entity_cache: dict[str, dict[str, float] | None] = {}
        relation_cache: dict[str, dict[str, float]] = {}
        states: list[_PathState] = []
        for edge_index, edge in enumerate(planned):
            if edge_index == 0:
                states = self._initial_states(edge, entity_cache, relation_cache)
            else:
                states = self._continue_states(states, edge, entity_cache, relation_cache)
            if not states:
                break

        candidates = self._candidates(states)
        contributions = [
            CandidateContribution(
                party_id=partition_id,
                candidate_id=candidate.candidate_id,
                score=candidate.score,
                support=support,
            )
            for candidate in candidates
            for partition_id, support in sorted(candidate.support_by_partition.items())
            if support > 0
        ]
        return EncodedGraphMatchResult(candidates, self._party_ids(), contributions)

    def _initial_states(
        self,
        edge: PlannedQueryEdge,
        entity_cache: dict[str, dict[str, float] | None],
        relation_cache: dict[str, dict[str, float]],
    ) -> list[_PathState]:
        source_candidates = self._entity_candidates(edge.source, entity_cache)
        if source_candidates is None:
            raise ValueError("encoded traversal requires a known source anchor")
        if self._type_id(edge) is not None:
            members = self._type_members(self._type_id(edge))
            return [
                _PathState(source_id, (), source_penalty, {})
                for source_id, source_penalty in source_candidates.items()
                if source_id in members
            ]

        relations = self._relation_candidates(edge.relation, relation_cache)
        targets = self._entity_candidates(edge.target, entity_cache)
        states = []
        for source_id, source_penalty in source_candidates.items():
            for relation_id, relation_penalty in relations.items():
                for target_id, partitions in self._targets_with_partitions(
                    source_id,
                    relation_id,
                    edge.reverse,
                ).items():
                    if targets is not None and target_id not in targets:
                        continue
                    support = {partition: 1 for partition in partitions}
                    states.append(
                        _PathState(
                            target_id,
                            (self._encoded_edge(source_id, relation_id, target_id, edge.reverse),),
                            source_penalty
                            + relation_penalty
                            + (targets or {}).get(target_id, 0.0),
                            support,
                        )
                    )
        return states

    def _continue_states(
        self,
        states: Sequence[_PathState],
        edge: PlannedQueryEdge,
        entity_cache: dict[str, dict[str, float] | None],
        relation_cache: dict[str, dict[str, float]],
    ) -> list[_PathState]:
        source_constraint = self._entity_candidates(edge.source, entity_cache)
        type_id = self._type_id(edge)
        if type_id is not None:
            members = self._type_members(type_id)
            return [state for state in states if state.current_id in members]

        relations = self._relation_candidates(edge.relation, relation_cache)
        targets = self._entity_candidates(edge.target, entity_cache)
        next_states = []
        for state in states:
            if source_constraint is not None and state.current_id not in source_constraint:
                continue
            for relation_id, relation_penalty in relations.items():
                for target_id, partitions in self._targets_with_partitions(
                    state.current_id,
                    relation_id,
                    edge.reverse,
                ).items():
                    if targets is not None and target_id not in targets:
                        continue
                    support = dict(state.support_by_partition)
                    for partition in partitions:
                        support[partition] = support.get(partition, 0) + 1
                    next_states.append(
                        _PathState(
                            target_id,
                            state.edges
                            + (
                                self._encoded_edge(
                                    state.current_id,
                                    relation_id,
                                    target_id,
                                    edge.reverse,
                                ),
                            ),
                            state.score
                            + relation_penalty
                            + (targets or {}).get(target_id, 0.0),
                            support,
                        )
                    )
        return next_states

    def _entity_candidates(
        self,
        label: str,
        cache: dict[str, dict[str, float] | None],
    ) -> dict[str, float] | None:
        if is_unknown(label):
            return None
        if label in cache:
            return cache[label]
        exact_id = self.ids.entity_id(label)
        exact = self.lookup.query(
            self.ids.id_for("role_exact_entity_request", label),
            "entity",
            exact_id,
            self._capacity("entity"),
        ).candidate_values
        if exact:
            result = {candidate_id: 0.0 for candidate_id in exact}
        elif self.semantic_router is not None:
            routed = self.semantic_router.route_entities(
                [label],
                self._capacity("entity_bucket"),
            )
            result = dict(routed.entity_penalties_by_label.get(label, {}))
        else:
            result = {}
        cache[label] = result
        return result

    def _relation_candidates(
        self,
        label: str,
        cache: dict[str, dict[str, float]],
    ) -> dict[str, float]:
        if label in cache:
            return cache[label]
        exact_id = self.ids.relation_id(label)
        exact = self.lookup.query(
            self.ids.id_for("role_exact_relation_request", label),
            "relation",
            exact_id,
            self._capacity("relation"),
        ).candidate_values
        if exact:
            result = {candidate_id: 0.0 for candidate_id in exact}
        elif self.semantic_router is not None:
            routed = self.semantic_router.route_relations(
                [label],
                self._capacity("relation_bucket"),
            )
            result = dict(routed.relation_penalties_by_label.get(label, {}))
        else:
            result = {}
        cache[label] = result
        return result

    def _targets_with_partitions(
        self,
        source_id: str,
        relation_id: str,
        reverse: bool,
    ) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        for snapshot in self.index.snapshots:
            adjacency = snapshot.reverse_adjacency if reverse else snapshot.adjacency
            for target_id in adjacency.get(source_id, {}).get(relation_id, []):
                result.setdefault(target_id, set()).add(snapshot.partition_id)
        return result

    def _type_members(self, type_id: str | None) -> set[str]:
        if type_id is None:
            return set()
        return {
            member
            for snapshot in self.index.snapshots
            for member in snapshot.type_index.get(type_id, [])
        }

    def _type_id(self, edge: PlannedQueryEdge) -> str | None:
        relation = normalize_text(edge.relation).replace("_", " ")
        if relation not in {"is a", "is an", "type", "has type", "of type"}:
            return None
        aliases = {
            "film": "movie",
            "films": "movie",
            "movies": "movie",
            "person": "actor",
            "people": "actor",
            "actors": "actor",
        }
        raw_type = extract_unknown_type(edge.target) if is_unknown(edge.target) else edge.target
        type_label = aliases.get(normalize_text(raw_type), normalize_text(raw_type))
        return self.ids.type_id(type_label) if type_label else None

    def _capacity(self, domain: str) -> int:
        if domain in {"relation", "relation_bucket"}:
            return max(self.relation_capacity, len(self.index.relation_points))
        return max(self.entity_capacity, len(self.index.entity_points))

    def _party_ids(self) -> list[str]:
        return sorted(snapshot.partition_id for snapshot in self.index.snapshots)

    @staticmethod
    def _encoded_edge(
        traversal_source: str,
        relation_id: str,
        traversal_target: str,
        reverse: bool,
    ) -> tuple[str, str, str]:
        if reverse:
            return traversal_target, relation_id, traversal_source
        return traversal_source, relation_id, traversal_target

    @staticmethod
    def _candidates(states: Sequence[_PathState]) -> list[EncodedPathCandidate]:
        merged: dict[tuple[tuple[str, str, str], ...], _PathState] = {}
        for state in states:
            existing = merged.get(state.edges)
            if existing is None or state.score < existing.score:
                merged[state.edges] = state
            elif state.score == existing.score:
                for partition, support in state.support_by_partition.items():
                    existing.support_by_partition[partition] = max(
                        support,
                        existing.support_by_partition.get(partition, 0),
                    )
        candidates = []
        for edges, state in merged.items():
            encoded = json.dumps(edges, separators=(",", ":"), ensure_ascii=True)
            candidate_id = hashlib.sha256(
                b"fedkg-encoded-path-v1\x00" + encoded.encode("ascii")
            ).hexdigest()
            candidates.append(
                EncodedPathCandidate(
                    candidate_id,
                    edges,
                    state.score,
                    dict(sorted(state.support_by_partition.items())),
                )
            )
        return sorted(candidates, key=lambda candidate: (candidate.score, candidate.candidate_id))
