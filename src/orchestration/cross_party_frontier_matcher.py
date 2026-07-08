"""Cross-party exact path extension with opaque frontier handoff.

This prototype supports chain-shaped exact query graphs. Intermediate entities are
handed from one hop to the next through DPF-shared frontier tokens. The aggregator
receives opaque path shares and selected evidence only; path shares do not contain
party identifiers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from src.aggregation.score_aggregation import MatchScoreShareBuilder
from src.common.normalization import is_unknown
from src.common.types import ExactQueryIds, MatchResult, QueryEdge
from src.crypto.dpf import DpfBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.gateway.query_compiler import ExactQueryCompiler
from src.orchestration.opaque_path_pipeline import OpaquePathAggregator, OpaquePathRankingResult
from src.orchestration.private_frontier_handoff import PrivateFrontierHandoff
from src.orchestration.private_semantic_routing import (
    PrivateSemanticEntityRouter,
    PrivateSemanticRelationRouter,
    SemanticEntityRouting,
    SemanticRelationRouting,
)
from src.party.frontier_index import FrontierIndex, frontier_token
from src.party.private_structural_matcher import OpaquePathShare, PartyEvidenceVault
from src.party.secure_index import SecurePartyIndex
from src.ranking.secure_topk import SecureTopK
from src.semantic.entity_buckets import EntitySemanticIndex
from src.semantic.relation_buckets import RelationSemanticIndex, SemanticBucketMode


@dataclass(frozen=True)
class FrontierPathState:
    request_id: str
    frontier_token: str
    edges: list[tuple[str, str, str]]
    score: float = 0.0


@dataclass
class CrossPartyFrontierMatcher:
    parties: Sequence[SecurePartyIndex]
    ids: HmacIdProvider
    backend: DpfBackend
    share_builder: MatchScoreShareBuilder
    evidence_vault: PartyEvidenceVault = field(default_factory=PartyEvidenceVault)
    enable_semantic_relations: bool = False
    enable_semantic_entities: bool = False
    semantic_bucket_mode: SemanticBucketMode = "hybrid"
    semantic_relation_penalty: float = 0.25
    semantic_lsh_relation_penalty: float = 0.5
    semantic_entity_penalty: float = 0.2
    semantic_lsh_entity_penalty: float = 0.45

    def retrieve_ranked(
        self,
        query_graph: Sequence[QueryEdge],
        ranker: SecureTopK,
        k: int,
    ) -> OpaquePathRankingResult:
        path_shares = self.match_multi_hop(query_graph)
        return OpaquePathAggregator(ranker).run([path_shares], [self], k)

    def reveal(self, selected_ids):
        return self.evidence_vault.reveal(selected_ids)

    def match_two_hop(self, query_graph: Sequence[QueryEdge]) -> list[OpaquePathShare]:
        if len(query_graph) != 2:
            raise ValueError("match_two_hop requires exactly two query edges")
        return self.match_multi_hop(query_graph)

    def match_multi_hop(self, query_graph: Sequence[QueryEdge]) -> list[OpaquePathShare]:
        edges = [tuple(edge) for edge in query_graph]
        if not edges:
            return []
        self._validate_chain(edges)

        exact = ExactQueryCompiler(self.ids).compile_ids(edges)
        party_ids = [party.party_id for party in self.parties]
        frontier_indexes = {party.party_id: FrontierIndex.from_secure_index(party, self.ids) for party in self.parties}
        frontier_universe = sorted({token for index in frontier_indexes.values() for token in index.tokens})
        semantic_routing = self._semantic_relation_routing(edges, party_ids)
        semantic_entity_routing = self._semantic_entity_routing(edges, party_ids)
        handoff = PrivateFrontierHandoff(self.backend, party_ids)

        states = self._initial_states(edges[0], exact, semantic_routing, semantic_entity_routing)
        if not states:
            return []
        if len(edges) == 1:
            return [self._share_final_path(state.edges, state.score) for state in states]

        for hop_index, edge in enumerate(edges[1:], start=1):
            is_final = hop_index == len(edges) - 1
            states, final_shares = self._continue_states(
                states,
                edge,
                exact,
                semantic_routing,
                semantic_entity_routing,
                frontier_indexes,
                frontier_universe,
                handoff,
                is_final,
            )
            if is_final:
                return final_shares
            if not states:
                return []
        return []

    @staticmethod
    def _validate_chain(edges: Sequence[QueryEdge]) -> None:
        for previous, current in zip(edges, edges[1:]):
            if previous[2] != current[0]:
                raise ValueError("frontier handoff prototype currently requires a chain-shaped query graph")

    def _initial_states(
        self,
        edge: QueryEdge,
        exact: ExactQueryIds,
        semantic_routing: SemanticRelationRouting | None,
        semantic_entity_routing: SemanticEntityRouting | None,
    ) -> list[FrontierPathState]:
        source_label, relation_label, target_label = edge
        source_ids = self._entity_candidates(source_label, exact, semantic_entity_routing)
        relation_ids = self._relation_candidates(relation_label, exact, semantic_routing)
        target_candidates = self._target_candidates(target_label, exact, semantic_entity_routing)
        states: list[FrontierPathState] = []
        for party in self.parties:
            for source_id in source_ids:
                for relation_id in relation_ids:
                    for target_id in party.adjacency.get(source_id, {}).get(relation_id, []):
                        if target_candidates is not None and target_id not in target_candidates:
                            continue
                        target_display = party.display_entities.get(target_id, target_id)
                        token = frontier_token(self.ids, target_display)
                        request_id = self._request_id(source_id, relation_id, target_id, 0)
                        score = (
                            self._entity_score(source_label, source_id, exact, semantic_entity_routing)
                            + self._relation_score(relation_label, relation_id, exact, semantic_routing)
                            + self._entity_score(target_label, target_id, exact, semantic_entity_routing)
                        )
                        states.append(
                            FrontierPathState(
                                request_id=request_id,
                                frontier_token=token,
                                edges=[
                                    (
                                        party.display_entities.get(source_id, source_id),
                                        party.display_relations.get(relation_id, relation_id),
                                        target_display,
                                    )
                                ],
                                score=score,
                            )
                        )
        return states

    def _continue_states(
        self,
        states: Sequence[FrontierPathState],
        edge: QueryEdge,
        exact: ExactQueryIds,
        semantic_routing: SemanticRelationRouting | None,
        semantic_entity_routing: SemanticEntityRouting | None,
        frontier_indexes: dict[str, FrontierIndex],
        frontier_universe: Sequence[str],
        handoff: PrivateFrontierHandoff,
        is_final: bool,
    ) -> tuple[list[FrontierPathState], list[OpaquePathShare]]:
        relation_ids = self._relation_candidates(edge[1], exact, semantic_routing)
        target_candidates = self._target_candidates(edge[2], exact, semantic_entity_routing)
        requests = [handoff.create_request(state.request_id, state.frontier_token) for state in states]
        state_by_request = {state.request_id: state for state in states}

        eval_batches = []
        for request in requests:
            for party in self.parties:
                eval_batches.append(
                    handoff.evaluate(
                        party.party_id,
                        frontier_indexes[party.party_id],
                        request,
                        points=frontier_universe,
                    )
                )
        frontier_matches = handoff.reconstruct(eval_batches)

        next_states: list[FrontierPathState] = []
        final_shares: list[OpaquePathShare] = []
        for frontier_match in frontier_matches:
            previous = state_by_request[frontier_match.request_id]
            for party in self.parties:
                for source_id in frontier_indexes[party.party_id].entities_for(frontier_match.frontier_token):
                    for relation_id in relation_ids:
                        for target_id in party.adjacency.get(source_id, {}).get(relation_id, []):
                            if target_candidates is not None and target_id not in target_candidates:
                                continue
                            edge_display = (
                                party.display_entities.get(source_id, source_id),
                                party.display_relations.get(relation_id, relation_id),
                                party.display_entities.get(target_id, target_id),
                            )
                            path_edges = previous.edges + [edge_display]
                            path_score = (
                                previous.score
                                + self._relation_score(edge[1], relation_id, exact, semantic_routing)
                                + self._entity_score(edge[2], target_id, exact, semantic_entity_routing)
                            )
                            if is_final:
                                final_shares.append(self._share_final_path(path_edges, path_score))
                            else:
                                target_display = party.display_entities.get(target_id, target_id)
                                next_states.append(
                                    FrontierPathState(
                                        request_id=self._request_id(source_id, relation_id, target_id, len(path_edges) - 1),
                                        frontier_token=frontier_token(self.ids, target_display),
                                        edges=path_edges,
                                        score=path_score,
                                    )
                                )
        return next_states, final_shares

    def _target_candidates(
        self,
        target_label: str,
        exact: ExactQueryIds,
        semantic_entity_routing: SemanticEntityRouting | None,
    ) -> set[str] | None:
        if target_label in exact.node_ids:
            return self._entity_candidates(target_label, exact, semantic_entity_routing)
        if target_label in exact.type_ids:
            type_id = exact.type_ids[target_label]
            return {entity_id for party in self.parties for entity_id in party.type_index.get(type_id, [])}
        return None

    def _share_final_path(self, edges: list[tuple[str, str, str]], score: float) -> OpaquePathShare:
        result = MatchResult(score=score, edges=edges, reuse_nodes=self._has_reused_node(edges))
        self.evidence_vault.add(result)
        candidate = self.share_builder.share_match(result)
        return OpaquePathShare(
            candidate_id=candidate.candidate_id,
            score_shares=candidate.score_shares,
            support_shares=candidate.support_shares,
        )

    def _request_id(self, source_id: str, relation_id: str, target_id: str, hop_index: int) -> str:
        return self.ids.id_for("frontier_request", f"{hop_index}:{source_id}:{relation_id}:{target_id}")

    def _semantic_relation_routing(
        self,
        edges: Sequence[QueryEdge],
        party_ids: Sequence[str],
    ) -> SemanticRelationRouting | None:
        if not self.enable_semantic_relations:
            return None
        labels = list(dict.fromkeys(edge[1] for edge in edges))
        semantic_indexes = {
            party.party_id: RelationSemanticIndex.from_secure_index(
                party,
                self.ids,
                mode=self.semantic_bucket_mode,
            )
            for party in self.parties
        }
        return PrivateSemanticRelationRouter(
            self.ids,
            self.backend,
            party_ids,
            bucket_mode=self.semantic_bucket_mode,
            alias_penalty=self.semantic_relation_penalty,
            lsh_penalty=self.semantic_lsh_relation_penalty,
        ).route(labels, semantic_indexes)

    def _semantic_entity_routing(
        self,
        edges: Sequence[QueryEdge],
        party_ids: Sequence[str],
    ) -> SemanticEntityRouting | None:
        if not self.enable_semantic_entities:
            return None
        labels = []
        seen = set()
        for source, _, target in edges:
            for label in (source, target):
                if label in seen or is_unknown(label):
                    continue
                labels.append(label)
                seen.add(label)
        semantic_indexes = {
            party.party_id: EntitySemanticIndex.from_secure_index(
                party,
                self.ids,
                mode=self.semantic_bucket_mode,
            )
            for party in self.parties
        }
        return PrivateSemanticEntityRouter(
            self.ids,
            self.backend,
            party_ids,
            bucket_mode=self.semantic_bucket_mode,
            alias_penalty=self.semantic_entity_penalty,
            lsh_penalty=self.semantic_lsh_entity_penalty,
        ).route(labels, semantic_indexes)

    def _entity_candidates(
        self,
        entity_label: str,
        exact: ExactQueryIds,
        semantic_entity_routing: SemanticEntityRouting | None,
    ) -> set[str]:
        candidates = set()
        exact_id = exact.node_ids[entity_label]
        if any(exact_id in party.display_entities for party in self.parties):
            candidates.add(exact_id)
        if semantic_entity_routing is not None:
            candidates.update(semantic_entity_routing.entity_ids_by_label.get(entity_label, set()))
        return candidates or {exact_id}

    def _relation_candidates(
        self,
        relation_label: str,
        exact: ExactQueryIds,
        semantic_routing: SemanticRelationRouting | None,
    ) -> set[str]:
        candidates = set()
        exact_id = exact.relation_ids[relation_label]
        if any(exact_id in party.local_relations for party in self.parties):
            candidates.add(exact_id)
        if semantic_routing is not None:
            candidates.update(semantic_routing.relation_ids_by_label.get(relation_label, set()))
        return candidates or {exact_id}

    def _relation_score(
        self,
        relation_label: str,
        relation_id: str,
        exact: ExactQueryIds,
        semantic_routing: SemanticRelationRouting | None,
    ) -> float:
        if relation_id == exact.relation_ids[relation_label]:
            return 0.0
        if semantic_routing is None:
            return self.semantic_relation_penalty
        return semantic_routing.relation_penalties_by_label.get(relation_label, {}).get(
            relation_id,
            self.semantic_lsh_relation_penalty,
        )

    def _entity_score(
        self,
        entity_label: str,
        entity_id: str,
        exact: ExactQueryIds,
        semantic_entity_routing: SemanticEntityRouting | None,
    ) -> float:
        if entity_label not in exact.node_ids:
            return 0.0
        if entity_id == exact.node_ids[entity_label]:
            return 0.0
        if semantic_entity_routing is None:
            return self.semantic_entity_penalty
        return semantic_entity_routing.entity_penalties_by_label.get(entity_label, {}).get(
            entity_id,
            self.semantic_lsh_entity_penalty,
        )

    @staticmethod
    def _has_reused_node(edges: Sequence[tuple[str, str, str]]) -> bool:
        seen = set()
        for source, _, target in edges:
            for node in (source, target):
                if node in seen:
                    return True
                seen.add(node)
        return False
