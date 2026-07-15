"""Party-local HMAC encoded KG and type indexes."""

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set

from src.common.normalization import extract_unknown_type, normalize_text
from src.common.types import EntityRef, LocalExpansion, RelationRef, SecurePartyCandidates
from src.crypto.dpf_domain import assert_no_projection_collisions
from src.crypto.hmac_ids import HmacIdProvider


@dataclass
class SecurePartyIndex:
    party_id: str
    adjacency: Dict[str, Dict[str, List[str]]]
    type_index: Dict[str, List[str]]
    display_entities: Dict[str, str] = field(default_factory=dict)
    display_relations: Dict[str, str] = field(default_factory=dict)
    alignment_index: Dict[str, List[str]] = field(default_factory=dict)
    reverse_adjacency: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)

    @classmethod
    def from_plain_graph(
        cls,
        party_id: str,
        graph: Dict[str, Dict[str, Sequence[str]]],
        type_to_nodes: Optional[Dict[str, Sequence[str]]],
        ids: HmacIdProvider,
    ) -> "SecurePartyIndex":
        adjacency: Dict[str, Dict[str, List[str]]] = {}
        display_entities: Dict[str, str] = {}
        display_relations: Dict[str, str] = {}
        alignment_index: Dict[str, List[str]] = {}

        for source, rels in graph.items():
            source_id = ids.entity_id(source)
            display_entities.setdefault(source_id, str(source))
            alignment_index.setdefault(normalize_text(source), []).append(source_id)
            adjacency.setdefault(source_id, {})
            for relation, targets in rels.items():
                relation_id = ids.relation_id(relation)
                display_relations.setdefault(relation_id, str(relation))
                bucket = adjacency[source_id].setdefault(relation_id, [])
                for target in targets:
                    target_id = ids.entity_id(target)
                    display_entities.setdefault(target_id, str(target))
                    alignment_index.setdefault(normalize_text(target), []).append(target_id)
                    bucket.append(target_id)

        type_index: Dict[str, List[str]] = {}
        type_labels: Dict[str, str] = {}
        for type_name, nodes in (type_to_nodes or {}).items():
            type_id = ids.type_id(type_name)
            type_labels.setdefault(type_id, str(type_name))
            encoded_nodes = [ids.entity_id(node) for node in nodes if ids.entity_id(node) in display_entities]
            if encoded_nodes:
                type_index[type_id] = sorted(set(encoded_nodes))

        assert_no_projection_collisions(f"{party_id}:entities", display_entities)
        assert_no_projection_collisions(f"{party_id}:relations", display_relations)
        assert_no_projection_collisions(f"{party_id}:types", type_labels)

        encoded_adjacency = {
            source: {relation: sorted(set(targets)) for relation, targets in rels.items()}
            for source, rels in adjacency.items()
        }
        reverse_adjacency: Dict[str, Dict[str, List[str]]] = {}
        for source_id, rels in encoded_adjacency.items():
            for relation_id, target_ids in rels.items():
                for target_id in target_ids:
                    reverse_adjacency.setdefault(target_id, {}).setdefault(relation_id, []).append(source_id)

        return cls(
            party_id=str(party_id),
            adjacency=encoded_adjacency,
            type_index=type_index,
            display_entities=display_entities,
            display_relations=display_relations,
            alignment_index={key: sorted(set(values)) for key, values in alignment_index.items()},
            reverse_adjacency={
                target: {relation: sorted(set(sources)) for relation, sources in rels.items()}
                for target, rels in reverse_adjacency.items()
            },
        )

    @property
    def local_relations(self) -> Set[str]:
        return {relation for rels in self.adjacency.values() for relation in rels}

    def relation_targets(self, source_id: str, relation_id: str, reverse: bool = False) -> List[str]:
        """Return outgoing targets, or incoming sources for reverse traversal."""

        index = self.reverse_adjacency if reverse else self.adjacency
        return index.get(source_id, {}).get(relation_id, [])

    def exact_candidates(
        self,
        query_nodes: Sequence[str],
        unknown_nodes: Sequence[str],
        query_relations: Sequence[str],
        node_ids: Dict[str, str],
        relation_ids: Dict[str, str],
        type_ids: Dict[str, str],
    ) -> SecurePartyCandidates:
        nodes = {}
        for query_node in query_nodes:
            encoded = node_ids[query_node]
            nodes[query_node] = (
                {EntityRef(self.party_id, encoded): 0.0}
                if encoded in self.adjacency or encoded in self.display_entities
                else {}
            )
        for unknown_node in unknown_nodes:
            type_id = type_ids.get(unknown_node)
            nodes[unknown_node] = None if type_id is None else {
                EntityRef(self.party_id, entity_id): 0.0
                for entity_id in self.type_index.get(type_id, [])
            }
        relations = {}
        for query_relation in query_relations:
            encoded = relation_ids[query_relation]
            relations[query_relation] = (
                {RelationRef(self.party_id, encoded): 0.0}
                if encoded in self.local_relations
                else {}
            )
        return SecurePartyCandidates(nodes=nodes, relations=relations)

    def expand(
        self,
        source: EntityRef,
        allowed_relations: Optional[Set[str]],
        allowed_targets: Optional[Set[str]],
    ) -> List[LocalExpansion]:
        if source.party_id != self.party_id:
            return []
        expansions = []
        for relation_id, targets in self.adjacency.get(source.entity_id, {}).items():
            if allowed_relations is not None and relation_id not in allowed_relations:
                continue
            for target_id in targets:
                if allowed_targets is not None and target_id not in allowed_targets:
                    continue
                expansions.append(
                    LocalExpansion(
                        source=source,
                        relation=RelationRef(self.party_id, relation_id),
                        target=EntityRef(self.party_id, target_id),
                    )
                )
        return expansions

    def alignment_key(self, entity: EntityRef) -> str:
        return normalize_text(self.display_entity(entity))

    def resolve_alignment(self, alignment_key: str) -> List[EntityRef]:
        return [EntityRef(self.party_id, entity_id) for entity_id in self.alignment_index.get(alignment_key, [])]

    def display_entity(self, entity: EntityRef) -> str:
        return self.display_entities.get(entity.entity_id, entity.entity_id)

    def display_relation(self, relation: RelationRef) -> str:
        return self.display_relations.get(relation.relation_id, relation.relation_id)
