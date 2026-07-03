"""Shared opaque evaluation universe for private exact lookup.

Every party must evaluate DPF shares on the same encoded points for a query
term. The points are HMAC IDs, not plaintext labels. This module builds that
shared universe from party-local encoded indexes for the current prototype.
"""

from __future__ import annotations

from typing import Sequence

from src.common.types import PrivateEvaluationUniverse, QueryEdge
from src.gateway.query_compiler import query_terms
from src.party.secure_index import SecurePartyIndex


def build_private_evaluation_universe(
    query_graph: Sequence[QueryEdge],
    parties: Sequence[SecurePartyIndex],
) -> PrivateEvaluationUniverse:
    terms = query_terms(query_graph)
    entity_points = sorted({entity_id for party in parties for entity_id in party.display_entities})
    relation_points = sorted({relation_id for party in parties for relation_id in party.local_relations})
    type_points = sorted({type_id for party in parties for type_id in party.type_index})

    return PrivateEvaluationUniverse(
        node_points={label: entity_points for label in terms.query_nodes},
        relation_points={label: relation_points for label in terms.query_relations},
        type_points={label: type_points for label in terms.unknown_nodes},
    )
