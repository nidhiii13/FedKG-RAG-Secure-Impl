"""Compile existing query graphs into HMAC exact IDs and DPF key-share requests."""

from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from src.common.normalization import extract_unknown_type, is_unknown
from src.common.types import ExactQueryIds, PrivateQueryShare, QueryEdge
from src.crypto.dpf import DpfBackend
from src.crypto.hmac_ids import HmacIdProvider


@dataclass(frozen=True)
class QueryTerms:
    query_nodes: List[str]
    unknown_nodes: List[str]
    query_relations: List[str]


def query_terms(query_graph: Sequence[QueryEdge]) -> QueryTerms:
    nodes = list(dict.fromkeys(node for edge in query_graph for node in (edge[0], edge[2])))
    return QueryTerms(
        query_nodes=[node for node in nodes if not is_unknown(node)],
        unknown_nodes=[node for node in nodes if is_unknown(node)],
        query_relations=list(dict.fromkeys(relation for _, relation, _ in query_graph if not is_unknown(relation))),
    )


class ExactQueryCompiler:
    def __init__(self, ids: HmacIdProvider):
        self.ids = ids

    def compile_ids(self, query_graph: Sequence[QueryEdge]) -> ExactQueryIds:
        terms = query_terms(query_graph)
        return ExactQueryIds(
            node_ids={node: self.ids.entity_id(node) for node in terms.query_nodes},
            relation_ids={relation: self.ids.relation_id(relation) for relation in terms.query_relations},
            type_ids={unknown: self.ids.type_id(extract_unknown_type(unknown)) for unknown in terms.unknown_nodes if extract_unknown_type(unknown)},
        )

    def compile_private_shares(
        self,
        query_graph: Sequence[QueryEdge],
        party_ids: Sequence[str],
        backend: DpfBackend,
    ) -> Dict[str, PrivateQueryShare]:
        exact = self.compile_ids(query_graph)
        shares = {
            party_id: PrivateQueryShare(
                party_id=party_id,
                query_shape=query_graph,
                node_key_shares={},
                relation_key_shares={},
                type_key_shares={},
            )
            for party_id in party_ids
        }
        for label, encoded in exact.node_ids.items():
            generated = backend.gen(encoded, beta=1, party_ids=party_ids)
            for party_id, key_share in generated.items():
                shares[party_id].node_key_shares[label] = key_share
        for label, encoded in exact.relation_ids.items():
            generated = backend.gen(encoded, beta=1, party_ids=party_ids)
            for party_id, key_share in generated.items():
                shares[party_id].relation_key_shares[label] = key_share
        for label, encoded in exact.type_ids.items():
            generated = backend.gen(encoded, beta=1, party_ids=party_ids)
            for party_id, key_share in generated.items():
                shares[party_id].type_key_shares[label] = key_share
        return shares
