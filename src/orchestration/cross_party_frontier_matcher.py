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
from src.common.types import ExactQueryIds, MatchResult, QueryEdge
from src.crypto.dpf import DpfBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.gateway.query_compiler import ExactQueryCompiler
from src.orchestration.opaque_path_pipeline import OpaquePathAggregator, OpaquePathRankingResult
from src.orchestration.private_frontier_handoff import PrivateFrontierHandoff
from src.party.frontier_index import FrontierIndex, frontier_token
from src.party.private_structural_matcher import OpaquePathShare, PartyEvidenceVault
from src.party.secure_index import SecurePartyIndex
from src.ranking.secure_topk import SecureTopK


@dataclass(frozen=True)
class FrontierPathState:
    request_id: str
    frontier_token: str
    edges: list[tuple[str, str, str]]


@dataclass
class CrossPartyFrontierMatcher:
    parties: Sequence[SecurePartyIndex]
    ids: HmacIdProvider
    backend: DpfBackend
    share_builder: MatchScoreShareBuilder
    evidence_vault: PartyEvidenceVault = field(default_factory=PartyEvidenceVault)

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
        handoff = PrivateFrontierHandoff(self.backend, party_ids)

        states = self._initial_states(edges[0], exact)
        if not states:
            return []
        if len(edges) == 1:
            return [self._share_final_path(state.edges) for state in states]

        for hop_index, edge in enumerate(edges[1:], start=1):
            is_final = hop_index == len(edges) - 1
            states, final_shares = self._continue_states(
                states,
                edge,
                exact,
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

    def _initial_states(self, edge: QueryEdge, exact: ExactQueryIds) -> list[FrontierPathState]:
        source_label, relation_label, target_label = edge
        source_id = exact.node_ids[source_label]
        relation_id = exact.relation_ids[relation_label]
        target_candidates = self._target_candidates(target_label, exact)
        states: list[FrontierPathState] = []
        for party in self.parties:
            for target_id in party.adjacency.get(source_id, {}).get(relation_id, []):
                if target_candidates is not None and target_id not in target_candidates:
                    continue
                target_display = party.display_entities.get(target_id, target_id)
                token = frontier_token(self.ids, target_display)
                request_id = self._request_id(source_id, relation_id, target_id, 0)
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
                    )
                )
        return states

    def _continue_states(
        self,
        states: Sequence[FrontierPathState],
        edge: QueryEdge,
        exact: ExactQueryIds,
        frontier_indexes: dict[str, FrontierIndex],
        frontier_universe: Sequence[str],
        handoff: PrivateFrontierHandoff,
        is_final: bool,
    ) -> tuple[list[FrontierPathState], list[OpaquePathShare]]:
        relation_id = exact.relation_ids[edge[1]]
        target_candidates = self._target_candidates(edge[2], exact)
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
                    for target_id in party.adjacency.get(source_id, {}).get(relation_id, []):
                        if target_candidates is not None and target_id not in target_candidates:
                            continue
                        edge_display = (
                            party.display_entities.get(source_id, source_id),
                            party.display_relations.get(relation_id, relation_id),
                            party.display_entities.get(target_id, target_id),
                        )
                        path_edges = previous.edges + [edge_display]
                        if is_final:
                            final_shares.append(self._share_final_path(path_edges))
                        else:
                            target_display = party.display_entities.get(target_id, target_id)
                            next_states.append(
                                FrontierPathState(
                                    request_id=self._request_id(source_id, relation_id, target_id, len(path_edges) - 1),
                                    frontier_token=frontier_token(self.ids, target_display),
                                    edges=path_edges,
                                )
                            )
        return next_states, final_shares

    def _target_candidates(self, target_label: str, exact: ExactQueryIds) -> set[str] | None:
        if target_label in exact.node_ids:
            return {exact.node_ids[target_label]}
        if target_label in exact.type_ids:
            type_id = exact.type_ids[target_label]
            return {entity_id for party in self.parties for entity_id in party.type_index.get(type_id, [])}
        return None

    def _share_final_path(self, edges: list[tuple[str, str, str]]) -> OpaquePathShare:
        result = MatchResult(score=0.0, edges=edges, reuse_nodes=self._has_reused_node(edges))
        self.evidence_vault.add(result)
        candidate = self.share_builder.share_match(result)
        return OpaquePathShare(
            candidate_id=candidate.candidate_id,
            score_shares=candidate.score_shares,
            support_shares=candidate.support_shares,
        )

    def _request_id(self, source_id: str, relation_id: str, target_id: str, hop_index: int) -> str:
        return self.ids.id_for("frontier_request", f"{hop_index}:{source_id}:{relation_id}:{target_id}")

    @staticmethod
    def _has_reused_node(edges: Sequence[tuple[str, str, str]]) -> bool:
        seen = set()
        for source, _, target in edges:
            for node in (source, target):
                if node in seen:
                    return True
                seen.add(node)
        return False
