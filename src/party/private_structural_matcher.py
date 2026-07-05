"""Party-local structural matching with opaque path-share output.

This module is the stronger secure direction for `expand`: each party checks its
own encoded KG locally and returns only opaque candidate shares to the aggregator.
The aggregator no longer needs party ownership metadata to perform structural DFS.

Current scope: exact, party-local paths. Cross-party frontier handoff is still a
separate protocol step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Sequence

from src.aggregation.score_aggregation import CandidateShare, MatchScoreShareBuilder, candidate_id_for_match
from src.common.types import ExactQueryIds, MatchResult, QueryEdge
from src.gateway.query_compiler import query_terms
from src.party.secure_index import SecurePartyIndex


@dataclass(frozen=True)
class OpaquePathShare:
    candidate_id: str
    score_shares: list[int]
    support_shares: list[int]

    def as_candidate_share(self) -> CandidateShare:
        return CandidateShare(self.candidate_id, list(self.score_shares), list(self.support_shares))


@dataclass(frozen=True)
class PartyLocalPathShares:
    path_shares: list[OpaquePathShare]


@dataclass
class PartyEvidenceVault:
    _evidence: Dict[str, MatchResult] = field(default_factory=dict)

    def add(self, match: MatchResult) -> str:
        candidate_id = candidate_id_for_match(match)
        self._evidence[candidate_id] = match
        return candidate_id

    def reveal(self, selected_ids: Iterable[str]) -> Dict[str, MatchResult]:
        selected = set(selected_ids)
        return {candidate_id: match for candidate_id, match in self._evidence.items() if candidate_id in selected}


@dataclass
class PartyLocalStructuralMatcher:
    index: SecurePartyIndex
    share_builder: MatchScoreShareBuilder
    evidence_vault: PartyEvidenceVault = field(default_factory=PartyEvidenceVault)

    def match_exact(self, query_graph: Sequence[QueryEdge], exact_ids: ExactQueryIds) -> PartyLocalPathShares:
        matches = self._local_matches(query_graph, exact_ids)
        shares: list[OpaquePathShare] = []
        for match in matches:
            self.evidence_vault.add(match)
            candidate = self.share_builder.share_match(match)
            shares.append(
                OpaquePathShare(
                    candidate_id=candidate.candidate_id,
                    score_shares=candidate.score_shares,
                    support_shares=candidate.support_shares,
                )
            )
        return PartyLocalPathShares(path_shares=shares)

    def reveal(self, selected_ids: Iterable[str]) -> Dict[str, MatchResult]:
        return self.evidence_vault.reveal(selected_ids)

    def _local_matches(self, query_graph: Sequence[QueryEdge], exact_ids: ExactQueryIds) -> list[MatchResult]:
        terms = query_terms(query_graph)
        node_candidates: Dict[str, list[str]] = {}
        for node in terms.query_nodes:
            encoded = exact_ids.node_ids[node]
            node_candidates[node] = [encoded] if encoded in self.index.display_entities else []
        for unknown in terms.unknown_nodes:
            type_id = exact_ids.type_ids.get(unknown)
            node_candidates[unknown] = list(self.index.type_index.get(type_id, [])) if type_id else list(self.index.display_entities)

        relation_candidates: Dict[str, list[str]] = {}
        for relation in terms.query_relations:
            encoded = exact_ids.relation_ids[relation]
            relation_candidates[relation] = [encoded] if encoded in self.index.local_relations else []

        root_options = [node for node, candidates in node_candidates.items() if candidates]
        if not root_options:
            return []
        root = min(root_options, key=lambda node: len(node_candidates[node]))
        sequence = self._dfs_edge_sequence(query_graph, root)
        matches: list[MatchResult] = []

        def visit(index: int, binding: Dict[str, str], edges: list[tuple[str, str, str]], score: float, reuse: bool):
            if index == len(sequence):
                matches.append(MatchResult(score=score, edges=edges, reuse_nodes=reuse))
                return

            source_label, relation_label, target_label = sequence[index]
            source_id = binding[source_label]
            allowed_relations = set(relation_candidates.get(relation_label, []))
            if not allowed_relations:
                return
            allowed_targets = set(node_candidates.get(target_label, []))
            if target_label in binding:
                allowed_targets = {binding[target_label]}
            if not allowed_targets:
                return

            for relation_id, targets in self.index.adjacency.get(source_id, {}).items():
                if relation_id not in allowed_relations:
                    continue
                for target_id in targets:
                    if target_id not in allowed_targets:
                        continue
                    next_binding = dict(binding)
                    next_reuse = reuse
                    if target_label in next_binding:
                        node_score = 0.0
                    else:
                        next_reuse = next_reuse or target_id in next_binding.values()
                        next_binding[target_label] = target_id
                        node_score = 0.0
                    edge = (
                        self.index.display_entities.get(source_id, source_id),
                        self.index.display_relations.get(relation_id, relation_id),
                        self.index.display_entities.get(target_id, target_id),
                    )
                    visit(index + 1, next_binding, edges + [edge], score + node_score, next_reuse)

        for root_id in sorted(node_candidates[root]):
            visit(0, {root: root_id}, [], 0.0, False)
        return matches

    @staticmethod
    def _dfs_edge_sequence(query_graph: Sequence[QueryEdge], root: str) -> list[QueryEdge]:
        adjacency = {}
        for index, (source, relation, target) in enumerate(query_graph):
            adjacency.setdefault(source, []).append((index, source, relation, target))
            adjacency.setdefault(target, []).append((index, target, relation, source))
        visited = set()
        sequence: list[QueryEdge] = []

        def walk(node: str) -> None:
            for edge_index, source, relation, target in sorted(adjacency.get(node, []), key=lambda edge: len(adjacency.get(edge[3], [])), reverse=True):
                if edge_index in visited:
                    continue
                visited.add(edge_index)
                sequence.append((source, relation, target))
                walk(target)

        walk(root)
        return sequence
