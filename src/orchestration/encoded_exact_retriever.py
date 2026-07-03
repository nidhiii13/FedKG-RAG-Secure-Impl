"""Encoded exact retriever for validating HMAC-index parity with existing data.

This preserves the structural retrieval behavior while operating over encoded
party indexes. It is not a substitute for FSS/DPF private lookup; it is the
real-data foundation used before wiring the FSS/DPF backend.
"""

import math
from dataclasses import dataclass
from itertools import product
from typing import Dict, List, Optional, Sequence, Set

from src.common.types import EntityRef, LocalExpansion, MatchResult, QueryEdge, RelationRef
from src.gateway.query_compiler import query_terms
from src.party.secure_index import SecurePartyIndex


class _TopK:
    def __init__(self, k: int):
        self.k = k
        self._items: List[MatchResult] = []

    def add(self, result: MatchResult) -> None:
        signature = (tuple(result.edges), result.reuse_nodes)
        for index, current in enumerate(self._items):
            if (tuple(current.edges), current.reuse_nodes) == signature:
                if result.score < current.score:
                    self._items[index] = result
                break
        else:
            self._items.append(result)
        self._items.sort(key=lambda item: (item.score, item.edges))
        del self._items[self.k :]

    def extend(self, results: Sequence[MatchResult]) -> None:
        for result in results:
            self.add(result)

    def max_score(self) -> float:
        if len(self._items) < self.k:
            return float("inf")
        return self._items[-1].score

    def get(self) -> List[MatchResult]:
        return list(self._items)


class EncodedExactRetriever:
    def __init__(self, parties: Sequence[SecurePartyIndex], final_topk: int = 3):
        if not parties:
            raise ValueError("At least one party is required")
        self.parties = {party.party_id: party for party in parties}
        self.final_topk = final_topk

    @staticmethod
    def _dfs_edge_sequence(query_graph: Sequence[QueryEdge], root: str) -> List[QueryEdge]:
        adjacency = {}
        for index, (source, relation, target) in enumerate(query_graph):
            adjacency.setdefault(source, []).append((index, source, relation, target))
            adjacency.setdefault(target, []).append((index, target, relation, source))
        visited = set()
        sequence = []

        def visit(node: str) -> None:
            incident = sorted(adjacency[node], key=lambda edge: len(adjacency[edge[3]]), reverse=True)
            for edge_index, source, relation, target in incident:
                if edge_index in visited:
                    continue
                visited.add(edge_index)
                sequence.append((source, relation, target))
                visit(target)

        visit(root)
        return sequence

    @staticmethod
    def _candidate_ids(candidates, party_id: str) -> Optional[Set[str]]:
        if candidates is None:
            return None
        return {candidate.entity_id for candidate in candidates if candidate.party_id == party_id}

    @staticmethod
    def _relation_ids(candidates, party_id: str) -> Optional[Set[str]]:
        if candidates is None:
            return None
        return {candidate.relation_id for candidate in candidates if candidate.party_id == party_id}

    @staticmethod
    def _distance(candidates, item) -> float:
        if candidates is None:
            return 0.0
        return candidates[item]

    def _alignment_key(self, entity: EntityRef) -> str:
        return self.parties[entity.party_id].alignment_key(entity)

    def _aliases(self, entity: EntityRef) -> List[EntityRef]:
        key = self._alignment_key(entity)
        aliases = []
        for party in self.parties.values():
            aliases.extend(party.resolve_alignment(key))
        return aliases or [entity]

    def _expand(self, current, query_relation, query_target, nodes, relations) -> List[LocalExpansion]:
        target_candidates = nodes.get(query_target)
        relation_candidates = relations.get(query_relation)
        expansions = []
        seen = set()
        for alias in self._aliases(current):
            party = self.parties[alias.party_id]
            allowed_relations = self._relation_ids(relation_candidates, alias.party_id)
            allowed_targets = self._candidate_ids(target_candidates, alias.party_id)
            for expansion in party.expand(alias, allowed_relations, allowed_targets):
                signature = (self._alignment_key(expansion.source), expansion.relation, self._alignment_key(expansion.target))
                if signature not in seen:
                    seen.add(signature)
                    expansions.append(expansion)
        return expansions

    def _format_edge(self, expansion: LocalExpansion):
        party = self.parties[expansion.source.party_id]
        target_party = self.parties[expansion.target.party_id]
        return (
            party.display_entity(expansion.source),
            party.display_relation(expansion.relation),
            target_party.display_entity(expansion.target),
        )

    def retrieve(self, query_graph: Sequence[QueryEdge], exact_ids, mode: str = "greedy"):
        if mode != "greedy":
            raise ValueError("EncodedExactRetriever currently supports greedy mode only")
        terms = query_terms(query_graph)
        party_candidates = {
            party_id: party.exact_candidates(
                terms.query_nodes,
                terms.unknown_nodes,
                terms.query_relations,
                exact_ids.node_ids,
                exact_ids.relation_ids,
                exact_ids.type_ids,
            )
            for party_id, party in self.parties.items()
        }
        nodes = {node: {} for node in terms.query_nodes}
        nodes.update({node: None for node in terms.unknown_nodes})
        relations = {relation: {} for relation in terms.query_relations}
        for candidates in party_candidates.values():
            for label, local in candidates.nodes.items():
                if local is None:
                    continue
                if nodes.get(label) is None:
                    nodes[label] = {}
                nodes[label].update(local)
            for label, local in candidates.relations.items():
                relations.setdefault(label, {}).update(local)

        root_options = [node for node, candidates in nodes.items() if candidates]
        if not root_options:
            raise ValueError("No root candidates found")
        root = min(root_options, key=lambda node: len(nodes[node]))
        sequence = self._dfs_edge_sequence(query_graph, root)
        results = _TopK(self.final_topk)

        def match(index, matching, alignment_matching, edges, score, reuse, parties):
            if index == len(sequence):
                results.add(MatchResult(score=score, edges=edges, reuse_nodes=reuse, parties=parties))
                return
            query_source, query_relation, query_target = sequence[index]
            current = matching[query_source]
            expansions = []
            for expansion in self._expand(current, query_relation, query_target, nodes, relations):
                target_key = self._alignment_key(expansion.target)
                if query_target in alignment_matching and alignment_matching[query_target] != target_key:
                    continue
                next_reuse = reuse
                if query_target in alignment_matching:
                    node_score = 0.0
                else:
                    next_reuse = next_reuse or target_key in alignment_matching.values()
                    node_score = self._distance(nodes.get(query_target), expansion.target)
                relation_score = self._distance(relations.get(query_relation), expansion.relation)
                expansions.append((score + node_score + relation_score, expansion, next_reuse))
            expansions.sort(key=lambda item: (item[0], item[1].relation.relation_id, item[1].target.entity_id))
            for next_score, expansion, next_reuse in expansions:
                next_matching = dict(matching)
                next_matching[query_target] = expansion.target
                next_alignment = dict(alignment_matching)
                next_alignment[query_target] = self._alignment_key(expansion.target)
                match(
                    index + 1,
                    next_matching,
                    next_alignment,
                    edges + [self._format_edge(expansion)],
                    next_score,
                    next_reuse,
                    parties + [expansion.source.party_id],
                )

        for root_entity, root_distance in sorted(nodes[root].items(), key=lambda item: (item[1], item[0])):
            match(0, {root: root_entity}, {root: self._alignment_key(root_entity)}, [], root_distance, False, [])
        return {"mode": mode, "root": root, "results": results.get()}
